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

;; The directory authorities (name host dir-port v3-identity-fingerprint), copied
;; from Tor's src/app/config/auth_dirs.inc — these v3idents are the trust anchors
;; for consensus validation, so they MUST come from the source, not the network.
(defparameter *authorities*
  '(("moria1"     "128.31.0.39"     9231 "F533C81CEF0BC0267857C99B2F471ADF249FA232")
    ("tor26"      "217.196.147.77"  80   "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C")
    ("dizum"      "45.66.35.11"     80   "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58")
    ("gabelmoo"   "131.188.40.189"  80   "ED03BB616EB2F60BEC80151114BB25CEF515B226")
    ("dannenberg" "193.23.244.244"  80   "0232AF901C31A04EE9848595AF9BB7620D4C5B2E")
    ("maatuska"   "171.25.193.9"    443  "49015F787433103580E3B66A1707A00E60F2D15B")
    ("longclaw"   "199.58.81.140"   80   "23D15D965BC35114467363C165C4F724B64B4F66")
    ("bastet"     "204.13.164.118"  80   "27102BC123E7AF1D4741AE047E160C91ADC76B21")
    ("faravahar"  "216.218.219.41"  80   "70849B868D606BAECFB6128C5E3D782029AA394F")))

(defun %trusted-v3idents ()
  (mapcar #'fourth *authorities*))

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
  nickname rsa-id ip or-port (flags '()) (bandwidth 0) md-digest ntor-key ed-id exit-ports)

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

(defun %ascii (string) (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

;;; ---- consensus validation (dir-spec §3.1, §3.4.1) -----------------------
;;;
;;; Trust chain: a hardcoded authority v3ident (SHA1 of its identity key) signs a
;;; key certificate that certifies a signing key; that signing key signs the
;;; consensus.  We require valid signatures from a majority of the authorities.

(defvar *verify-consensus* t "When true, consensus-relays validates signatures.")

(defun %line-value (text key &optional (start 0))
  "Value token(s) of a 'KEY value' line at/after START."
  (let* ((p (search (format nil "~a " key) text :start2 start))
         (nl (position #\Newline text :start p)))
    (subseq text (+ p (length key) 1) nl)))

(defun %pem-after (text label &optional (start 0))
  "DER bytes of the first PEM block after LABEL (from START)."
  (let* ((lp (search label text :start2 start))
         (b (search "-----BEGIN " text :start2 lp))
         (nl (position #\Newline text :start b))
         (e (search "-----END " text :start2 nl)))
    (u:base64-decode (remove #\Newline (subseq text (1+ nl) e)))))

(defstruct authcert fingerprint id-n id-e sign-n sign-e sign-digest)

(defun %parse-cert (block)
  "Parse one key certificate; validate its self-certification; return an AUTHCERT
or NIL if the identity key doesn't match the fingerprint / the cert doesn't verify."
  (handler-case
      (let* ((fp (string-upcase (%line-value block "fingerprint")))
             (id-der (%pem-after block "dir-identity-key"))
             (sign-der (%pem-after block "dir-signing-key"))
             (cert-end (+ (search "dir-key-certification" block)
                          (length "dir-key-certification") 1))
             (cert-sig (%pem-after block "dir-key-certification"))
             (signed (%ascii (subseq block 0 cert-end))))
        (unless (string= fp (string-upcase (u:bytes->hex (c:sha1 id-der))))
          (return-from %parse-cert nil))            ; identity key must hash to fingerprint
        (multiple-value-bind (id-n id-e) (c:der-rsa-public-key id-der)
          ;; dir-key-certification: identity key signs the cert (digest sha256 or sha1)
          (unless (or (c:rsa-verify id-n id-e cert-sig (c:sha256 signed))
                      (c:rsa-verify id-n id-e cert-sig (c:sha1 signed)))
            (return-from %parse-cert nil))
          (multiple-value-bind (sn se) (c:der-rsa-public-key sign-der)
            (make-authcert :fingerprint fp :id-n id-n :id-e id-e :sign-n sn :sign-e se
                           :sign-digest (string-upcase (u:bytes->hex (c:sha1 sign-der)))))))
    (error () nil)))

(defvar *certs-cache* nil)

(defun fetch-certs (&key force)
  "Fetch + validate authority key certificates -> hash fingerprint -> AUTHCERT,
keeping only certs whose fingerprint is a trusted v3ident."
  (or (and (not force) *certs-cache*)
      (let* ((text (loop for (name host port) in *authorities*
                         for body = (ignore-errors (http-get host port "/tor/keys/all"))
                         when body return (map 'string #'code-char body)
                         finally (error "no authority reachable for certs")))
             (trusted (%trusted-v3idents))
             (table (make-hash-table :test 'equal)))
        (loop with start = 0
              for p = (search "dir-key-certificate-version" text :start2 start)
              while p
              do (let* ((next (search "dir-key-certificate-version" text :start2 (1+ p)))
                        (cert (%parse-cert (subseq text p next))))
                   (when (and cert (member (authcert-fingerprint cert) trusted :test #'string=))
                     (setf (gethash (authcert-fingerprint cert) table) cert))
                   (setf start (or next (length text)))))
        (setf *certs-cache* table))))

(defun validate-consensus (text &optional (certs (fetch-certs)))
  "T iff TEXT carries valid signatures from a majority of trusted authorities."
  (let* ((region-end (+ (search "directory-signature " text) (length "directory-signature ")))
         (digest (c:sha256 (%ascii (subseq text 0 region-end))))
         (good (make-hash-table :test 'equal)))
    (loop with start = 0
          for p = (search "directory-signature " text :start2 start)
          while p
          do (let* ((nl (position #\Newline text :start p))
                    (toks (let ((s (subseq text (+ p (length "directory-signature ")) nl)))
                            (loop for tk in (uiop:split-string s :separator " ")
                                  unless (string= tk "") collect tk)))
                    ;; "[algo] id-fp signing-key-digest"
                    (algo (if (= (length toks) 3) (first toks) "sha1"))
                    (id-fp (string-upcase (if (= (length toks) 3) (second toks) (first toks))))
                    (skd (string-upcase (car (last toks))))
                    (sig (%pem-after text "directory-signature" p))
                    (cert (gethash id-fp certs)))
               (when (and cert (string= skd (authcert-sign-digest cert))
                          (string= algo "sha256")
                          (c:rsa-verify (authcert-sign-n cert) (authcert-sign-e cert) sig digest))
                 (setf (gethash id-fp good) t))
               (setf start (1+ p))))
    (>= (hash-table-count good)
        (1+ (floor (length *authorities*) 2)))))      ; majority quorum

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
  "Fetch the consensus (validating its signatures unless *verify-consensus* is
nil) and parse it into RELAY structs."
  (let ((text (fetch-consensus :force force)))
    (when (and *verify-consensus* (not (validate-consensus text)))
      (error "consensus signature validation failed (untrusted directory?)"))
    (parse-consensus text)))

;;; ---- microdescriptors ---------------------------------------------------

(defun %parse-port-policy (tokens)
  "p line tokens (\"accept\"/\"reject\" \"80,443,...\") -> (kind . ((lo . hi)...))."
  (cons (intern (string-upcase (first tokens)) :keyword)
        (loop for spec in (uiop:split-string (or (second tokens) "") :separator ",")
              for dash = (position #\- spec)
              unless (string= spec "")
                collect (if dash
                            (cons (parse-integer spec :end dash)
                                  (parse-integer spec :start (1+ dash)))
                            (let ((n (parse-integer spec))) (cons n n))))))

(defun fetch-microdesc (digest-b64 &key (authority (first *authorities*)))
  "Fetch + parse one microdescriptor; returns (values ntor-key ed25519-id port-policy)."
  (destructuring-bind (name host port &rest _) authority
    (declare (ignore name _))
    (let ((text (map 'string #'code-char
                     (http-get host port (format nil "/tor/micro/d/~a" digest-b64))))
          ntor ed policy)
      (with-input-from-string (in text)
        (loop for line = (read-line in nil) while line do
          (let ((tk (%tokens line)))
            (cond ((string= (first tk) "ntor-onion-key") (setf ntor (u:base64-decode (second tk))))
                  ((and (string= (first tk) "id") (string= (second tk) "ed25519"))
                   (setf ed (u:base64-decode (third tk))))
                  ((string= (first tk) "p") (setf policy (%parse-port-policy (rest tk))))))))
      (values ntor ed policy))))

(defun enrich-relay (relay &key (authority (first *authorities*)))
  "Fill RELAY's ntor-key, ed-id, and exit-ports from its microdescriptor."
  (when (relay-md-digest relay)
    (multiple-value-bind (ntor ed policy) (fetch-microdesc (relay-md-digest relay) :authority authority)
      (setf (relay-ntor-key relay) ntor (relay-ed-id relay) ed (relay-exit-ports relay) policy)))
  relay)

(defun exit-allows-port (relay port)
  "T iff RELAY's exit port policy permits PORT."
  (let ((policy (relay-exit-ports relay)))
    (if (null policy) nil
        (let ((listed (loop for (lo . hi) in (cdr policy) thereis (<= lo port hi))))
          (if (eq (car policy) :accept) listed (not listed))))))

;;; ---- selection (bandwidth-weighted, exit-policy aware) ------------------

(defun %candidates (relays flag)
  (remove-if-not (lambda (r) (and (relay-has-flag r "Running") (relay-has-flag r "Valid")
                                  (relay-has-flag r "Fast")
                                  (relay-has-flag r flag) (relay-md-digest r)))
                 relays))

(defun %weighted-choice (relays)
  "Pick one relay at random, weighted by its consensus bandwidth."
  (when relays
    (let* ((total (reduce #'+ relays :key (lambda (r) (max 1 (relay-bandwidth r)))))
           (pick (random (max 1 total))) (acc 0))
      (loop for r in relays do (incf acc (max 1 (relay-bandwidth r)))
            when (> acc pick) return r
            finally (return (car (last relays)))))))

(defun %distinct (relay &rest others)
  (notany (lambda (o) (and o (string= (relay-nickname relay) (relay-nickname o)))) others))

(defun pick-relay (&key (flag "Fast") relays)
  "Pick one running relay carrying FLAG (bandwidth-weighted) and enrich it."
  (let* ((relays (or relays (consensus-relays)))
         (cands (%candidates relays flag)))
    (when cands (enrich-relay (%weighted-choice cands)))))

(defun pick-path (&optional relays &key (port 443))
  "Pick an enriched (guard middle exit) path: bandwidth-weighted, distinct, with
an exit whose policy permits PORT."
  (let* ((relays (or relays (consensus-relays)))
         (guard (enrich-relay (%weighted-choice (%candidates relays "Guard"))))
         (exits (%candidates relays "Exit"))
         (exit (loop for tries from 1 to 15
                     for e = (%weighted-choice exits)
                     when (and e (%distinct e guard))
                       do (enrich-relay e)
                          (when (exit-allows-port e port) (return e))
                     finally (error "no exit permitting port ~d found" port)))
         (mids (%candidates relays "Fast"))
         (middle (loop for tries from 1 to 25
                       for m = (%weighted-choice mids)
                       when (and m (%distinct m guard exit)) return (enrich-relay m)
                       finally (error "no middle relay found"))))
    (list guard middle exit)))
