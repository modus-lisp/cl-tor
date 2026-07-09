;;;; src/hs-dir.lisp — v3 onion service HSDir hash ring (rend-spec-v3 [HASHRING]).
;;;;
;;;; Turns a .onion identity key into the set of directory relays that hold its
;;;; descriptor, for the current time period.  This file is the ring MATH + the
;;;; consensus timing inputs it needs (time period, shared-random value, params).
;;;; Building the full ring over every HSDir (which needs each relay's ed25519 id
;;;; from its microdescriptor) and the actual descriptor fetch come next.

(defpackage #:cl-tor.hsdir
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto)
                    (#:ed #:cl-tor.ed25519) (#:dir #:cl-tor.directory))
  (:export #:parse-consensus-header #:time-period-and-srv
           #:hsdir-index #:hs-index #:responsible-hsdirs
           #:*hsdir-n-replicas* #:*hsdir-spread-fetch*))

(in-package #:cl-tor.hsdir)

(defparameter *hsdir-n-replicas* 2)      ; consensus param defaults (rend-spec-v3)
(defparameter *hsdir-spread-fetch* 3)
(defparameter *default-period-length* 1440)   ; hsdir-interval, minutes (1 day)

(defun %int8be (n)
  "INT_8: 8-byte big-endian."
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b (- 7 i)) (logand (ash n (* -8 i)) #xff)))))

(defun %split-ws (line)
  (remove "" (uiop:split-string line :separator '(#\Space #\Tab)) :test #'string=))

;;; --- consensus timing inputs ------------------------------------------------

(defun %parse-utc (date time)
  "\"2026-07-08\" \"12:00:00\" -> universal-time (UTC)."
  (flet ((n (s a b) (parse-integer s :start a :end b)))
    (encode-universal-time (n time 6 8) (n time 3 5) (n time 0 2)
                           (n date 8 10) (n date 5 7) (n date 0 4) 0)))

(defun parse-consensus-header (text)
  "Parse the consensus preamble → (values valid-after-ut srv-current srv-previous
   params-alist).  SRVs are 32 raw bytes (or NIL); PARAMS maps name string → integer."
  (let (valid-after srv-cur srv-prev (params '()))
    (with-input-from-string (in text)
      (loop for line = (read-line in nil) while line do
        (cond
          ((and (>= (length line) 2) (string= (subseq line 0 2) "r ")) (return))  ; relays begin
          ((and (>= (length line) 12) (string= (subseq line 0 12) "valid-after "))
           (let ((tk (%split-ws line))) (setf valid-after (%parse-utc (second tk) (third tk)))))
          ((and (>= (length line) 26) (string= (subseq line 0 26) "shared-rand-current-value "))
           (setf srv-cur (u:base64-decode (third (%split-ws line)))))
          ((and (>= (length line) 27) (string= (subseq line 0 27) "shared-rand-previous-value "))
           (setf srv-prev (u:base64-decode (third (%split-ws line)))))
          ((and (>= (length line) 7) (string= (subseq line 0 7) "params "))
           (dolist (kv (rest (%split-ws line)))
             (let ((eq (position #\= kv)))
               (when eq (push (cons (subseq kv 0 eq)
                                    (or (ignore-errors (parse-integer kv :start (1+ eq))) 0))
                              params))))))))
    (values valid-after srv-cur srv-prev params)))

(defun %param (params name default)
  (let ((c (assoc name params :test #'string=))) (if c (cdr c) default)))

(defun time-period-and-srv (valid-after srv-current srv-previous params)
  "For the consensus VALID-AFTER (universal-time), return (values period-number
   period-length shared-random-value) to use for a CLIENT descriptor fetch.
   Period rotates 12h after the SRV: a consensus in [00:00,12:00) uses the previous
   SRV, in [12:00,24:00) the current one (rend-spec-v3 [CLIENTFETCH])."
  (let* ((period-length (%param params "hsdir-interval" *default-period-length*))
         (epoch (encode-universal-time 0 0 0 1 1 1970 0))
         (minutes (floor (- valid-after epoch) 60))
         (rotation-offset (* 12 60))                       ; 720 min
         (tp (floor (- minutes rotation-offset) period-length)))
    (multiple-value-bind (s mi hour) (decode-universal-time valid-after 0)
      (declare (ignore s mi))
      (values tp period-length (if (>= hour 12) srv-current srv-previous)))))

;;; --- the hash ring ----------------------------------------------------------

(defun hsdir-index (ed-id srv period-num period-length)
  "hs_relay_index(node) = SHA3-256(\"node-idx\" | ed25519-id | SRV | INT_8(period_num)
   | INT_8(period_length)).  ED-ID and SRV are 32 raw bytes."
  (c:sha3-256 (u:cat (u:ascii->bytes "node-idx") ed-id srv
                     (%int8be period-num) (%int8be period-length))))

(defun hs-index (blinded-key replica period-length period-num)
  "hs_service_index(replicanum) = SHA3-256(\"store-at-idx\" | blinded_pubkey |
   INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))."
  (c:sha3-256 (u:cat (u:ascii->bytes "store-at-idx") blinded-key
                     (%int8be replica) (%int8be period-length) (%int8be period-num))))

(defun %bytes< (a b)
  "Lexicographic (big-endian integer) compare of equal-length byte vectors."
  (dotimes (i (length a) nil)
    (cond ((< (aref a i) (aref b i)) (return t))
          ((> (aref a i) (aref b i)) (return nil)))))

(defun responsible-hsdirs (identity-pubkey relays period-num period-length srv
                           &key (replicas *hsdir-n-replicas*) (spread *hsdir-spread-fetch*))
  "Responsible HSDir relays for the .onion IDENTITY-PUBKEY (32 bytes) this period.
   RELAYS must be HSDir-flagged relays WITH ed25519 ids (relay-ed-id) populated.
   Builds the ring (relays sorted by hsdir-index), and for each replica takes the
   first SPREAD relays whose index follows hs-index.  Returns a de-duplicated list."
  (let* ((blinded (ed:blind-public-key identity-pubkey period-num period-length))
         (ring (sort (mapcar (lambda (r)
                               (cons (hsdir-index (dir:relay-ed-id r) srv period-num period-length) r))
                             relays)
                     #'%bytes< :key #'car))
         (chosen '()))
    (dotimes (rep replicas)
      (let* ((idx (hs-index blinded (1+ rep) period-length period-num))
             ;; first ring position whose hsdir-index > idx (else wrap to 0)
             (start (or (position-if (lambda (e) (%bytes< idx (car e))) ring) 0)))
        (dotimes (k spread)
          (let ((r (cdr (nth (mod (+ start k) (length ring)) ring))))
            (pushnew r chosen)))))
    (nreverse chosen)))
