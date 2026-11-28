;;;; src/dirsvc.lisp -- the directory owner, and how other threads ask it.
;;;;
;;;; THE THREADS SHARE NOTHING.  The directory state -- the consensus, its relay list, the
;;;; microdescriptors ENRICH-RELAY fetches into those relays, the HSDir ring, the persistent
;;;; guard set -- belongs to ONE thread, the directory's OWNER.  Every other thread that builds
;;;; circuits (a SOCKS connection, an onion-service introduction or rendezvous, a descriptor
;;;; publish) ASKS the owner over a channel and gets plain data back (relays as
;;;; DIR:RELAY->PLAIN lists), a copy, which it turns into relay structs of its own.  The
;;;; circuits it then builds are its own too: a circuit is only ever touched by the thread
;;;; that built it.
;;;;
;;;; That is what modus needs -- a thread there may not store an object it made where another
;;;; thread can reach it, so a worker could not fill the shared relay cache or set the
;;;; directory globals; and a thread that is not main has a 16 MB heap, which the consensus does
;;;; not fit, so on modus the owner is the main thread -- and SBCL runs the same threads and
;;;; channels, so there is one code path.
;;;;
;;;; A DIRECTORY is the channels: one REQUESTS channel, one REPLY channel per slot, and a FREE
;;;; channel of slot numbers.  A thread holding a slot asks with DIR-ASK inside
;;;; WITH-DIRECTORY-CLIENT; whoever calls SERVE-DIRECTORY-REQUESTS on the directory answers
;;;; from its own state.  With no client bound, DIR-ASK answers from the calling thread's own
;;;; state -- the single-threaded use (a REPL, a script) needs no owner.
;;;;
;;;; The questions are DIRECTORY OPS (DEFINE-DIRECTORY-OP): a keyword naming a function of
;;;; plain arguments returning plain data.  hs-dir.lisp adds the onion-service ones.

(in-package #:cl-tor.dirsvc)

;;; ---- the owner's state -------------------------------------------------------

(defvar *relays* nil "The owner's consensus relay list (loaded on first use).")
(defvar *hsdirs* nil "The owner's HSDir relays, with their ed25519 ids (loaded on first use).")

(defun owner-relays ()
  "This thread's relay list, fetching and validating the consensus the first time."
  (or *relays* (setf *relays* (dir:consensus-relays))))

(defun owner-hsdirs ()
  "This thread's HSDir+Running relays with ed25519 ids (batch-enriched the first time)."
  (or *hsdirs*
      (setf *hsdirs*
            (let ((hs (remove-if-not (lambda (r) (and (dir:relay-has-flag r "HSDir")
                                                      (dir:relay-has-flag r "Running")))
                                     (owner-relays))))
              (dir:enrich-relays hs)
              (remove-if-not #'dir:relay-ed-id hs)))))

(defun load-directory ()
  "Fetch, validate and parse the consensus into this thread's directory state now, rather
than at the first question.  The number of relays."
  (setf *hsdirs* nil)
  (length (setf *relays* (dir:consensus-relays))))

(defmacro with-own-directory-state (&body body)
  "Run BODY with directory state of this thread's own: on modus a thread that is not main may
not set the globals (and need not -- it is then the only one that reads them)."
  `(let ((*relays* *relays*)
         (*hsdirs* *hsdirs*)
         (guard::*guards* guard::*guards*)
         (guard::*loaded* guard::*loaded*)
         (dir::*consensus-cache* dir::*consensus-cache*)
         (dir::*certs-cache* dir::*certs-cache*))
     ,@body))

;;; ---- directory ops ------------------------------------------------------------

(defvar *ops* (make-hash-table :test 'eq) "op keyword -> the symbol of its function")

(defmacro define-directory-op (op lambda-list &body body)
  "Define the directory question OP (a keyword): BODY runs on the owner, with plain arguments,
and returns plain data."
  (let ((fn (intern (format nil "DIROP-~a" (symbol-name op)))))
    `(progn (defun ,fn ,lambda-list ,@body)
            (setf (gethash ,op *ops*) ',fn)
            ',op)))

(defun %run-op (op args)
  (let ((fn (gethash op *ops*)))
    (unless fn (error "directory: no op ~s" op))
    (apply fn args)))

(defun %find-relay (plain)
  "The owner's relay with PLAIN's RSA identity, or NIL."
  (find (second plain) (owner-relays) :key #'dir:relay-rsa-id :test #'equalp))

(define-directory-op :path (port)
  "A (guard middle exit) path for an exit permitting PORT, through the persistent guard."
  (let* ((relays (owner-relays))
         (guard (guard:pick-guard relays)))
    (mapcar #'dir:relay->plain (dir:pick-path relays :port port :guard guard))))

(define-directory-op :guard-failed (plain)
  "A guard that would not connect: drop it from the set."
  (let ((r (%find-relay plain)))
    (when r (ignore-errors (guard:guard-failed r)))
    nil))

(define-directory-op :relay (flag)
  "One running relay carrying FLAG, enriched (ntor key, ed25519 id)."
  (let ((r (dir:pick-relay :flag flag :relays (owner-relays))))
    (unless r (error "directory: no relay with flag ~a" flag))
    (dir:relay->plain r)))

(define-directory-op :path-to (exit)
  "A (guard middle) prefix for a circuit whose last hop is EXIT (plain; already has its ntor
key): through the persistent guard, the middle distinct from both."
  (let* ((relays (owner-relays))
         (guard (guard:pick-guard relays))
         (middle (loop repeat 40
                       for m = (dir:pick-relay :relays relays)
                       when (and m
                                 (not (equalp (dir:relay-rsa-id m) (second exit)))
                                 (not (equalp (dir:relay-rsa-id m) (dir:relay-rsa-id guard)))
                                 (not (and (dir:relay-ed-id m) (ninth exit)
                                           (equalp (dir:relay-ed-id m) (ninth exit)))))
                         return m
                       finally (error "directory: no middle relay found"))))
    (list (dir:relay->plain guard) (dir:relay->plain middle))))

(define-directory-op :intro-relay (used)
  "A fresh Stable relay for an onion-service introduction point -- enriched, with an ntor key
and an ed25519 id not among USED (a list of ed25519 ids) -- or NIL."
  (loop repeat 40
        for r = (dir:pick-relay :flag "Stable" :relays (owner-relays))
        when (and r (dir:relay-ntor-key r) (dir:relay-ed-id r)
                  (not (member (dir:relay-ed-id r) used :test #'equalp)))
          return (dir:relay->plain r)))

;;; ---- the channels ---------------------------------------------------------------

(defstruct (tor-directory (:conc-name directory-) (:constructor %%make-directory (requests replies free)))
  requests replies free)

(defun %make-directory (requests replies &optional free)
  "A DIRECTORY over channels that already exist (REPLIES a vector or list of reply channels;
FREE the channel of free slot numbers, or NIL when slots are handed out by the caller) -- how a
thread that was handed a directory's channels as :ARGUMENTS rebuilds it."
  (%%make-directory requests (coerce replies 'simple-vector) free))

(defun make-directory (&key (slots 8))
  "The channels of a directory with SLOTS slots, all free.  Make it on the thread that will
hand it out (and, on modus, serve it: the main thread)."
  (let ((free (bob:make-channel :capacity 4096)))
    (dotimes (i slots) (bob:channel-send free i))
    (%%make-directory (bob:make-channel :capacity 65536)
                      (coerce (loop repeat slots collect (bob:make-channel :capacity 262144))
                              'simple-vector)
                      free)))

(defun directory-slots (dir) (length (directory-replies dir)))

(defun acquire-slot (dir)
  "A free slot number of DIR, or NIL when every slot is in use."
  (when (directory-free dir)
    (multiple-value-bind (slot ok) (bob:channel-try-receive (directory-free dir))
      (and ok slot))))

(defun release-slot (dir slot)
  (when (and slot (directory-free dir))
    (bob:channel-send (directory-free dir) slot :timeout 5)))

;;; ---- the owner side ---------------------------------------------------------------

(defun serve-directory-requests (dir)
  "Answer every queued question on DIR from this (the owner's) thread's directory state.
The number answered."
  (let ((n 0))
    (loop
      (multiple-value-bind (msg ok) (bob:channel-try-receive (directory-requests dir))
        (unless ok (return n))
        (incf n)
        (when (and (consp msg) (eq (first msg) :call))
          (destructuring-bind (slot op args) (rest msg)
            (bob:channel-send (svref (directory-replies dir) slot)
                              (handler-case (list :ok (%run-op op args))
                                (error (e) (list :error (princ-to-string e))))
                              :timeout 5)))))))

(defun serve-directory (dir &key stop-p)
  "Be DIR's owner: answer its questions until STOP-P (polled every 50 ms) returns true."
  (loop until (and stop-p (funcall stop-p))
        do (when (zerop (serve-directory-requests dir)) (sleep 0.05))))

;;; ---- the asking side ---------------------------------------------------------------

(defvar *client* nil
  "On a thread that asks an owner: (requests-channel reply-channel slot).  NIL: answer from this
thread's own directory state.")

(defmacro with-directory-client ((dir slot) &body body)
  "Run BODY with DIR-ASK asking DIR's owner, over SLOT's reply channel."
  `(let ((*client* (list (directory-requests ,dir) (svref (directory-replies ,dir) ,slot) ,slot)))
     ,@body))

(defun dir-ask (op &rest args)
  "Ask the directory OP with ARGS (plain data): the owner's answer, a copy -- or, with no
client bound (see WITH-DIRECTORY-CLIENT), the answer from this thread's own state."
  (if (null *client*)
      (%run-op op args)
      (destructuring-bind (requests reply slot) *client*
        (bob:channel-drain reply)                 ; a late answer to a question given up on
        (unless (bob:channel-send requests (list :call slot op args) :timeout 30)
          (error "directory: the owner is not taking questions"))
        ;; a first consensus fetch takes ~95 s on modus, and the owner answers in turn
        (multiple-value-bind (msg ok) (bob:channel-receive reply :timeout 600)
          (cond ((not ok) (error "directory: the owner did not answer ~s" op))
                ((eq (first msg) :ok) (second msg))
                (t (error "directory: ~a" (second msg))))))))

;;; ---- the shared directory: for code that is handed no slot ------------------------------
;;;
;;; A caller with no directory of its own (cl-transport's :TOR backend, DIAL-OVER-TOR, on any
;;; thread) reaches the owner through the SHARED directory: the owner registers one with
;;; SHARE-DIRECTORY, and WITH-SHARED-DIRECTORY takes a free slot of it for the extent of its
;;; body.  The global is set on the owner only; other threads only read it.

(defvar *shared-directory* nil
  "The directory threads with none of their own ask (SHARE-DIRECTORY), or NIL.")

(defvar *shared-owner* nil "The thread that shared *SHARED-DIRECTORY* (its owner).")

(defun share-directory (dir)
  "Make DIR (a MAKE-DIRECTORY this thread serves) the one threads without a directory of their
own ask.  NIL withdraws it.  Call it on the owner."
  (setf *shared-owner* (and dir sb-thread:*current-thread*)
        *shared-directory* dir))

(defun call-with-shared-directory (fn &key (timeout 600))
  "Call FN with DIR-ASK reaching the shared directory's owner, through a free slot held for
the call -- unless this thread already asks an owner, there is no shared directory, or this
thread is the owner (then FN runs as it is, on this thread's own state)."
  (let ((dir *shared-directory*))
    (if (or *client* (null dir) (null (directory-free dir))
            (eq sb-thread:*current-thread* *shared-owner*))
        (funcall fn)
        (let ((end (+ (get-universal-time) timeout)) (slot nil))
          (loop (setf slot (acquire-slot dir))
                (when slot (return))
                (when (> (get-universal-time) end)
                  (error "directory: no free slot in ~d s" timeout))
                (sleep 0.05))
          (unwind-protect (with-directory-client (dir slot) (funcall fn))
            (release-slot dir slot))))))

(defmacro with-shared-directory ((&key (timeout 600)) &body body)
  "Run BODY with DIR-ASK reaching the shared directory's owner (CALL-WITH-SHARED-DIRECTORY)."
  `(call-with-shared-directory (lambda () ,@body) :timeout ,timeout))

;;; ---- circuits, built on the asking thread ---------------------------------------------

(defparameter *circuit-build-timeout* 60
  "Seconds a circuit build may take when no deadline is set already (CIRC:WITH-DEADLINE).")

(defun build-path-circuit (path)
  "Build a circuit along PATH (guard middle exit relay structs) on this thread; a guard that
would not connect is reported to the directory.  Bounded by the deadline in force, or by
*CIRCUIT-BUILD-TIMEOUT*: a relay that takes a cell and never answers must not hold a thread
for ever.  (Live, on modus, .onion dials through the proxy once hung 4 x 600 s; a build
without a deadline waited for CREATED2 with no bound.)"
  (if circ:*deadline*
      (%build-path-circuit path)
      (circ:with-deadline (*circuit-build-timeout*) (%build-path-circuit path))))

(defun %build-path-circuit (path)
  (destructuring-bind (g m e) path
    (let ((lk (handler-case (link:connect-link g)
                (error (err)
                  (ignore-errors (dir-ask :guard-failed (dir:relay->plain g)))
                  (error err)))))
      (handler-case (circ:build-circuit lk m e)
        (error (err) (ignore-errors (link:close-link lk)) (error err))))))

(defun circuit-to (exit &key (tries 3))
  "A 3-hop circuit whose last hop is EXIT (a relay struct with its ntor key and ids), entering
through the persistent guard, retrying past relay churn."
  (let ((last-error nil))
    (loop repeat tries
          do (handler-case
                 (return-from circuit-to
                   (build-path-circuit
                    (append (mapcar #'dir:plain->relay (dir-ask :path-to (dir:relay->plain exit)))
                            (list exit))))
               (error (e) (setf last-error e))))
    (error "could not build a circuit to ~a after ~d tries: ~a"
           (dir:relay-nickname exit) tries last-error)))

(defun fresh-circuit (&key (port 443) (tries 6))
  "A 3-hop circuit through the persistent guard to an exit permitting PORT."
  (let ((last-error nil))
    (loop repeat tries
          do (handler-case
                 (return-from fresh-circuit
                   (build-path-circuit (mapcar #'dir:plain->relay (dir-ask :path port))))
               (error (e) (setf last-error e))))
    (error "could not build a circuit after ~d tries: ~a" tries last-error)))
