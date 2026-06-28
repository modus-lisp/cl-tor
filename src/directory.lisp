;;;; src/directory.lisp — minimal directory bootstrap.
;;;;
;;;; Enough of the directory protocol (dir-spec) to learn about live relays so the
;;;; link and circuit layers can be tested against the real network: fetch the
;;;; microdescriptor consensus from a hardcoded authority, parse the relay list
;;;; (identity, address, flags, bandwidth, microdesc digest), and fetch each
;;;; chosen relay's microdescriptor for its ntor onion key and Ed25519 identity.
;;;;
;;;; Bandwidth-weighted selection, exit-policy checks, and consensus-signature
;;;; validation are deferred to P4 — this is the "give me one running relay with
;;;; an ntor key" layer.  HTTP is plain over the authority DirPort (no TLS).

(in-package #:cl-tor.directory)

;; A handful of directory authorities (name host dir-port).  These identities and
;; addresses are long-lived and baked into every Tor client.
(defparameter *authorities*
  '(("moria1"     "128.31.0.39"     9131)
    ("dannenberg" "193.23.244.244"  80)
    ("maatuska"   "171.25.193.9"    443)   ; also serves DirPort on 443
    ("bastet"     "204.13.164.118"  80)
    ("longclaw"   "199.58.81.140"   80)))

;;; ---- tiny HTTP/1.0 client (plain TCP) -----------------------------------

(defun %read-all (stream)
  (let ((buf (make-array 65536 :element-type '(unsigned-byte 8)))
        (out (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for n = (read-sequence buf stream)
          while (plusp n)
          do (loop for i from 0 below n do (vector-push-extend (aref buf i) out)))
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defun %split-http (bytes)
  "Split an HTTP/1.0 response into (values status-code body-bytes)."
  (let ((sep (loop for i from 0 below (- (length bytes) 3)
                   when (and (= (aref bytes i) 13) (= (aref bytes (+ i 1)) 10)
                             (= (aref bytes (+ i 2)) 13) (= (aref bytes (+ i 3)) 10))
                     return i)))
    (unless sep (error "http: no header terminator"))
    (let* ((header (map 'string #'code-char (subseq bytes 0 sep)))
           (status (let ((sp (position #\Space header)))
                     (parse-integer header :start (1+ sp) :end (+ sp 4) :junk-allowed t))))
      (values status (u:subv bytes (+ sep 4))))))

(defun http-get (host port path &key (timeout 30))
  "HTTP/1.0 GET; returns body bytes.  Inflates a zlib body when PATH ends in .z."
  (let ((sock (usocket:socket-connect host port :element-type '(unsigned-byte 8)
                                                 :timeout timeout)))
    (unwind-protect
         (let ((stream (usocket:socket-stream sock)))
           (write-sequence (u:ascii->bytes
                            (format nil "GET ~a HTTP/1.0~c~cHost: ~a~c~cConnection: close~c~c~c~c"
                                    path #\Return #\Newline host #\Return #\Newline
                                    #\Return #\Newline #\Return #\Newline))
                           stream)
           (force-output stream)
           (multiple-value-bind (status body) (%split-http (%read-all stream))
             (unless (eql status 200) (error "http ~a for ~a~a" status host path))
             (if (and (>= (length path) 2) (string= (subseq path (- (length path) 2)) ".z"))
                 (chipz:decompress nil 'chipz:zlib body)
                 body)))
      (ignore-errors (usocket:socket-close sock)))))

;;; ---- consensus ----------------------------------------------------------

(defstruct relay
  nickname rsa-id ip or-port (flags '()) (bandwidth 0) md-digest ntor-key ed-id)

(defun relay-has-flag (relay flag) (member flag (relay-flags relay) :test #'string=))

(defvar *consensus-cache* nil)

(defun fetch-consensus (&key force)
  "Fetch + inflate the microdesc consensus from the first reachable authority.
Cached for the session unless :FORCE."
  (or (and (not force) *consensus-cache*)
      (setf *consensus-cache*
            (loop for (name host port) in *authorities*
                  for body = (ignore-errors
                              (http-get host port
                                        "/tor/status-vote/current/consensus-microdesc.z"))
                  when body return (map 'string #'code-char body)
                  finally (error "no authority reachable")))))

(defun %tokens (line) (let ((r '()) (i 0) (n (length line)))
                        (loop while (< i n) do
                          (loop while (and (< i n) (char= (char line i) #\Space)) do (incf i))
                          (let ((s i)) (loop while (and (< i n) (char/= (char line i) #\Space)) do (incf i))
                               (when (> i s) (push (subseq line s i) r))))
                        (nreverse r)))

(defun parse-consensus (text)
  "Parse the microdesc consensus TEXT into a list of RELAY structs (newest order)."
  (let ((relays '()) (cur nil))
    (with-input-from-string (in text)
      (loop for line = (read-line in nil) while line do
        (cond
          ((and (>= (length line) 2) (string= (subseq line 0 2) "r "))
           (when cur (push cur relays))
           (let ((tk (%tokens line)))
             ;; r nick id pub-date pub-time IP ORPort DirPort
             (setf cur (make-relay :nickname (second tk)
                                   :rsa-id (u:base64-decode (third tk))
                                   :ip (nth 5 tk)
                                   :or-port (parse-integer (nth 6 tk))))))
          ((and cur (>= (length line) 2) (string= (subseq line 0 2) "s "))
           (setf (relay-flags cur) (rest (%tokens line))))
          ((and cur (>= (length line) 2) (string= (subseq line 0 2) "m "))
           (setf (relay-md-digest cur) (second (%tokens line))))
          ((and cur (>= (length line) 11) (string= (subseq line 0 11) "w Bandwidth"))
           (let ((eq (position #\= line)))
             (setf (relay-bandwidth cur)
                   (or (parse-integer line :start (1+ eq) :junk-allowed t) 0)))))))
    (when cur (push cur relays))
    (nreverse relays)))

(defun consensus-relays (&key force)
  (parse-consensus (fetch-consensus :force force)))

;;; ---- microdescriptors ---------------------------------------------------

(defun fetch-microdesc (digest-b64 &key (authority (first *authorities*)))
  "Fetch + parse one microdescriptor; returns (values ntor-key-32 ed25519-id-32)."
  (destructuring-bind (name host port) authority
    (declare (ignore name))
    (let ((text (map 'string #'code-char
                     (http-get host port (format nil "/tor/micro/d/~a" digest-b64))))
          ntor ed)
      (with-input-from-string (in text)
        (loop for line = (read-line in nil) while line do
          (let ((tk (%tokens line)))
            (cond ((string= (first tk) "ntor-onion-key") (setf ntor (u:base64-decode (second tk))))
                  ((and (string= (first tk) "id") (string= (second tk) "ed25519"))
                   (setf ed (u:base64-decode (third tk))))))))
      (values ntor ed))))

(defun enrich-relay (relay &key (authority (first *authorities*)))
  "Fill RELAY's ntor-key and ed-id from its microdescriptor.  Returns RELAY."
  (when (relay-md-digest relay)
    (multiple-value-bind (ntor ed) (fetch-microdesc (relay-md-digest relay) :authority authority)
      (setf (relay-ntor-key relay) ntor (relay-ed-id relay) ed)))
  relay)

;;; ---- selection (bootstrap: flag filter + uniform random; weighting in P4) -

(defun %candidates (relays flag)
  (remove-if-not (lambda (r) (and (relay-has-flag r "Running") (relay-has-flag r "Valid")
                                  (relay-has-flag r "Fast")
                                  (relay-has-flag r flag) (relay-md-digest r)))
                 relays))

(defun pick-relay (&key (flag "Fast") relays)
  "Pick one running relay carrying FLAG and enrich it with its ntor key / ed id."
  (let* ((relays (or relays (consensus-relays)))
         (cands (%candidates relays flag)))
    (when cands (enrich-relay (nth (random (length cands)) cands)))))

(defun pick-path (&optional relays)
  "Pick an enriched (guard middle exit) 3-relay path (distinct relays)."
  (let* ((relays (or relays (consensus-relays)))
         (guard (enrich-relay (nth (random (length (%candidates relays "Guard")))
                                   (%candidates relays "Guard"))))
         (exit  (loop for e = (nth (random (length (%candidates relays "Exit")))
                                   (%candidates relays "Exit"))
                      unless (string= (relay-nickname e) (relay-nickname guard))
                        return (enrich-relay e)))
         (middle (loop for m = (nth (random (length (%candidates relays "Fast")))
                                    (%candidates relays "Fast"))
                       unless (or (string= (relay-nickname m) (relay-nickname guard))
                                  (string= (relay-nickname m) (relay-nickname exit)))
                         return (enrich-relay m))))
    (list guard middle exit)))
