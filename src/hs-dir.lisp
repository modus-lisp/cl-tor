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
                    (#:ed #:cl-tor.ed25519) (#:dir #:cl-tor.directory)
                    (#:circ #:cl-tor.circuit) (#:strm #:cl-tor.stream)
                    (#:rc #:cl-tor.relay-crypto) (#:link #:cl-tor.link)
                    (#:guard #:cl-tor.guard))
  (:export #:parse-consensus-header #:time-period-and-srv #:next-time-period-and-srv
           #:hsdir-index #:hs-index #:responsible-hsdirs
           #:onion->pubkey #:pubkey->onion #:fetch-descriptor
           #:build-circuit-to #:relay-pool #:hsdir-pool #:post-over-circuit
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

(defun next-time-period-and-srv (valid-after srv-current srv-previous params)
  "During the OVERLAP [00:00,12:00 UTC) a service should ALSO publish for the NEXT time
   period, so clients find its descriptor across the 12:00 rotation.  In that window the
   next period is current-tp+1 and its SRV is srv-current (both known); returns
   (values next-period-num period-length srv-current).  Outside the overlap the next
   period's SRV isn't known yet — returns NIL (no second descriptor)."
  (multiple-value-bind (tp plen srv) (time-period-and-srv valid-after srv-current srv-previous params)
    (declare (ignore srv))
    (multiple-value-bind (s mi hour) (decode-universal-time valid-after 0)
      (declare (ignore s mi))
      (when (< hour 12)
        (values (1+ tp) plen srv-current)))))

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

;;; --- .onion decode + base64 (rend-spec-v3 §6 address encoding) ---------------

(defparameter +b32+ "abcdefghijklmnopqrstuvwxyz234567")

(defun %base32-decode (string)
  (let ((bits 0) (nbits 0)
        (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for ch across (string-downcase string)
          for v = (position ch +b32+)
          do (unless v (error "base32: bad char ~s" ch))
             (setf bits (logior (ash bits 5) v) nbits (+ nbits 5))
             (when (>= nbits 8)
               (decf nbits 8)
               (vector-push-extend (logand (ash bits (- nbits)) #xff) out)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %base32-encode (bytes)
  (let ((out (make-string-output-stream)) (bits 0) (nbits 0))
    (loop for b across bytes do
      (setf bits (logior (ash bits 8) b) nbits (+ nbits 8))
      (loop while (>= nbits 5) do
        (decf nbits 5)
        (write-char (char +b32+ (logand (ash bits (- nbits)) 31)) out)))
    (when (plusp nbits)
      (write-char (char +b32+ (logand (ash bits (- 5 nbits)) 31)) out))
    (get-output-stream-string out)))

(defun pubkey->onion (pubkey)
  "The v3 .onion address for a 32-byte Ed25519 identity PUBKEY (base32 of
   PUBKEY | CHECKSUM(2) | VERSION(3), + \".onion\")."
  (let ((ck (subseq (c:sha3-256 (u:cat (u:ascii->bytes ".onion checksum") pubkey #(3))) 0 2)))
    (concatenate 'string (%base32-encode (u:cat pubkey ck #(3))) ".onion")))

(defun onion->pubkey (onion)
  "Decode a v3 .onion address to its 32-byte Ed25519 identity public key.  Verifies
   the version byte and checksum = SHA3-256(\".onion checksum\" | pubkey | v)[:2]."
  (let* ((label (string-downcase (subseq onion 0 (or (search ".onion" onion) (length onion)))))
         (raw (%base32-decode label)))
    (unless (and (= (length raw) 35) (= (aref raw 34) 3)) (error "onion: bad v3 address"))
    (let* ((pk (subseq raw 0 32))
           (ck (subseq raw 32 34))
           (want (subseq (c:sha3-256 (u:cat (u:ascii->bytes ".onion checksum") pk #(3))) 0 2)))
      (unless (equalp ck want) (error "onion: bad checksum"))
      pk)))

(defparameter +b64+ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun %base64-encode (bytes)
  (with-output-to-string (s)
    (loop for i from 0 below (length bytes) by 3
          for n = (- (length bytes) i)
          for b0 = (aref bytes i)
          for b1 = (if (> n 1) (aref bytes (+ i 1)) 0)
          for b2 = (if (> n 2) (aref bytes (+ i 2)) 0)
          do (write-char (char +b64+ (ash b0 -2)) s)
             (write-char (char +b64+ (logior (ash (logand b0 3) 4) (ash b1 -4))) s)
             (write-char (if (> n 1) (char +b64+ (logior (ash (logand b1 15) 2) (ash b2 -6))) #\=) s)
             (write-char (if (> n 2) (char +b64+ (logand b2 63)) #\=) s))))

;;; --- descriptor fetch over a circuit ----------------------------------------

(defvar *relays-cache* nil)
(defun %relays ()
  (or *relays-cache* (setf *relays-cache* (dir:consensus-relays))))

(defun %hsdirs (relays)
  "HSDir+Running relays with ed25519 ids (batch-enriched); the ring nodes."
  (let ((hs (remove-if-not (lambda (r) (and (dir:relay-has-flag r "HSDir")
                                            (dir:relay-has-flag r "Running")))
                           relays)))
    (dir:enrich-relays hs)
    (remove-if-not #'dir:relay-ed-id hs)))

(defun %build-circuit-to (exit relays)
  "Build a 3-hop circuit whose exit is EXIT (a chosen, enriched relay), entering
   through a persistent entry guard."
  (dir:enrich-relay exit)
  (let* ((guard (guard:pick-guard relays))
         (middle (loop for m = (dir:pick-relay :relays relays)
                       until (and (not (equalp (dir:relay-ed-id m) (dir:relay-ed-id exit)))
                                  (not (equalp (dir:relay-rsa-id m) (dir:relay-rsa-id guard))))
                       finally (return (dir:enrich-relay m))))
         (lk (handler-case (link:connect-link guard)
               (error (e) (guard:guard-failed guard) (error e)))))   ; guard down -> drop it
    (handler-case (circ:build-circuit lk middle exit)
      (error (e) (ignore-errors (link:close-link lk)) (error e)))))

(defconstant +r-begin-dir+ 13)

(defun %http-body (bytes)
  (let ((i (search #(13 10 13 10) bytes)))
    (if i (subseq bytes (+ i 4)) bytes)))

(defun %fetch-over-circuit (circ path &key (sid 1))
  "RELAY_BEGIN_DIR to the last hop, HTTP/1.0 GET PATH, return the response BODY bytes."
  (circ:send-relay circ +r-begin-dir+ sid #())
  (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
          (declare (ignore hop len data))
          (cond ((and (= rcmd rc:+r-connected+) (= rsid sid)) (return))
                ((and (= rcmd rc:+r-end+) (= rsid sid)) (error "dir stream refused")))))
  (strm:send-stream-data circ sid
    (u:ascii->bytes (format nil "GET ~a HTTP/1.0~c~c~c~c" path #\Return #\Newline #\Return #\Newline)))
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
            (declare (ignore hop rsid len))
            (cond ((= rcmd rc:+r-data+) (loop for b across data do (vector-push-extend b out)))
                  ((= rcmd rc:+r-end+) (return)))))
    (%http-body (coerce out '(simple-array (unsigned-byte 8) (*))))))

;;; --- public helpers reused by the SERVICE side (hs-host) --------------------

(defun build-circuit-to (exit relays) (%build-circuit-to exit relays))
(defun relay-pool () (%relays))
(defun hsdir-pool (relays) (%hsdirs relays))

(defun post-over-circuit (circ path body-bytes &key (sid 1))
  "RELAY_BEGIN_DIR to the last hop, then HTTP/1.0 POST PATH with BODY-BYTES.  Returns
   the response text (for status checking)."
  (circ:send-relay circ +r-begin-dir+ sid #())
  (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
          (declare (ignore hop len data))
          (cond ((and (= rcmd rc:+r-connected+) (= rsid sid)) (return))
                ((and (= rcmd rc:+r-end+) (= rsid sid)) (error "dir stream refused")))))
  (strm:send-stream-data circ sid
    (u:cat (u:ascii->bytes
            (format nil "POST ~a HTTP/1.0~c~cContent-Type: application/octet-stream~c~cContent-Length: ~d~c~c~c~c"
                    path #\Return #\Newline #\Return #\Newline (length body-bytes)
                    #\Return #\Newline #\Return #\Newline))
           body-bytes))
  (let ((out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
            (declare (ignore hop rsid len))
            (cond ((= rcmd rc:+r-data+) (loop for b across data do (vector-push-extend b out)))
                  ((= rcmd rc:+r-end+) (return)))))
    (map 'string #'code-char (coerce out '(simple-array (unsigned-byte 8) (*))))))

(defun fetch-descriptor (onion)
  "Fetch the raw v3 descriptor text for ONION from a responsible HSDir over a fresh
   Tor circuit.  Returns the descriptor string (starts with \"hs-descriptor 3\")."
  (let* ((pubkey (onion->pubkey onion))
         (relays (%relays))
         (text (dir:fetch-consensus)))
    (multiple-value-bind (va cur prev params) (parse-consensus-header text)
      (multiple-value-bind (tp plen srv) (time-period-and-srv va cur prev params)
        (let* ((hsdirs (%hsdirs relays))
               (blinded (ed:blind-public-key pubkey tp plen))
               (path (format nil "/tor/hs/3/~a" (%base64-encode blinded)))
               (responsible (responsible-hsdirs pubkey hsdirs tp plen srv)))
          (dolist (hd responsible (error "no responsible HSDir served ~a" onion))
            (let ((circ nil))
              (handler-case
                  (progn
                    (setf circ (%build-circuit-to hd relays))
                    (let ((body (map 'string #'code-char (%fetch-over-circuit circ path))))
                      (ignore-errors (circ:destroy-circuit circ))
                      (ignore-errors (link:close-link (circ:circuit-link circ)))
                      (when (search "hs-descriptor" body) (return body))))
                (serious-condition ()
                  (when circ (ignore-errors (circ:destroy-circuit circ))
                        (ignore-errors (link:close-link (circ:circuit-link circ)))))))))))))
