;;;; src/guard.lisp — entry-guard set with rotation (guard-spec, lite).
;;;;
;;;; Every circuit should enter the network through one of a small, stable set of
;;;; entry guards — reusing few guards is the basic defense against a malicious relay
;;;; becoming your first hop.  Tor's full guard-spec is elaborate; this keeps a small
;;;; persistent SET (default 3), ROTATES a guard out after a lifetime, drops one that
;;;; proves unreachable, and replenishes from the consensus.  Shared by the SOCKS
;;;; proxy AND the onion client/service (which previously picked a fresh random guard
;;;; per circuit — no persistence, maximal guard exposure).

(in-package #:cl-tor.guard)   ; package declared in packages.lisp (socks nicknames it)

(defparameter *num-guards* 3 "Size of the persistent entry-guard set.")
(defparameter *guard-lifetime* (* 60 86400)
  "Rotate a guard out this many seconds after it was first added (default ~60 days).")

(defstruct (gentry (:constructor mkg (rsa-hex added))) rsa-hex added)

(defvar *guards* nil "Lazily-loaded guard set (list of GENTRY).")
(defvar *loaded* nil)
(defvar *lock* (bt:make-lock "cl-tor-guards"))

(defun %file () (merge-pathnames ".cl-tor/guards" (user-homedir-pathname)))
(defun %now () (- (get-universal-time) 2208988800))    ; unix time

(defun %load ()
  (setf *guards*
        (or (ignore-errors
              (with-open-file (f (%file) :if-does-not-exist nil)
                (when f
                  (loop for line = (read-line f nil) while line
                        for sp = (position #\Space line)
                        when (and sp (plusp sp))
                          collect (mkg (subseq line 0 sp)
                                       (or (ignore-errors (parse-integer line :start (1+ sp)))
                                           (%now)))))))
            '())
        *loaded* t))

(defun %save ()
  (ignore-errors
    (ensure-directories-exist (%file))
    (with-open-file (f (%file) :direction :output :if-exists :supersede :if-does-not-exist :create)
      (dolist (g *guards*) (format f "~a ~d~%" (gentry-rsa-hex g) (gentry-added g))))))

(defun %relay-for (hex relays)
  "The consensus relay with rsa fingerprint HEX that is still a Running Guard, enriched;
   NIL if it's gone from the consensus or lost the flag."
  (let ((id (ignore-errors (u:hex->bytes hex))))
    (when id
      (loop for r in relays
            when (and (equalp (dir:relay-rsa-id r) id)
                      (dir:relay-has-flag r "Guard") (dir:relay-has-flag r "Running"))
              do (return (ignore-errors (dir:enrich-relay r)))))))

(defun pick-guard (relays)
  "Return a live, enriched entry guard from the persistent set: load it, RETIRE guards
   older than *GUARD-LIFETIME* (rotation), REPLENISH to *NUM-GUARDS* from RELAYS
   (bandwidth-weighted, deduped), persist changes, and return the first guard still
   usable in the current consensus — falling back to a fresh pick if none are."
  (bt:with-lock-held (*lock*)
    (unless *loaded* (%load))
    (let ((now (%now)) (changed nil))
      ;; rotate out expired guards
      (let ((live (remove-if (lambda (g) (> (- now (gentry-added g)) *guard-lifetime*)) *guards*)))
        (unless (= (length live) (length *guards*)) (setf changed t))
        (setf *guards* live))
      ;; replenish to the target set size (bounded so dup picks can't spin)
      (loop with tries = 0
            while (and (< (length *guards*) *num-guards*) (< tries (* 4 *num-guards*)))
            do (incf tries)
               (let* ((g (ignore-errors (dir:pick-relay :flag "Guard" :relays relays)))
                      (hex (and g (u:bytes->hex (dir:relay-rsa-id g)))))
                 (when (and hex (not (member hex *guards* :key #'gentry-rsa-hex :test #'string=)))
                   (setf *guards* (append *guards* (list (mkg hex (%now)))) changed t))))
      (when changed (%save))
      (or (loop for g in *guards*
                for r = (%relay-for (gentry-rsa-hex g) relays)
                when r do (return r))
          (ignore-errors (dir:enrich-relay (dir:pick-relay :flag "Guard" :relays relays)))))))

(defun guard-failed (guard)
  "Drop GUARD from the persistent set — it proved unreachable, so the next PICK-GUARD
   replenishes with a different one.  Call this only when the GUARD LINK itself failed
   (not for a middle/exit failure), so transient downstream churn doesn't churn guards."
  (when guard
    (bt:with-lock-held (*lock*)
      (unless *loaded* (%load))
      (let* ((hex (u:bytes->hex (dir:relay-rsa-id guard)))
             (kept (remove hex *guards* :key #'gentry-rsa-hex :test #'string=)))
        (unless (= (length kept) (length *guards*))
          (setf *guards* kept) (%save))))))

(defun reset-guards ()
  "Forget the in-memory set (re-loaded from disk on the next pick)."
  (bt:with-lock-held (*lock*) (setf *guards* nil *loaded* nil)))
