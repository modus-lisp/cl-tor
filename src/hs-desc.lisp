;;;; src/hs-desc.lisp — decrypt a v3 onion service descriptor (rend-spec-v3 §2.5).
;;;;
;;;; The fetched descriptor is doubly encrypted.  Both layers use the same scheme:
;;;;   blob = SALT(16) | CIPHERTEXT | MAC(32)
;;;;   keys = SHAKE256(SECRET_DATA | subcredential | INT_8(rev) | SALT | STRING_CONST, 80)
;;;;        -> SECRET_KEY(32, AES-256) | SECRET_IV(16) | MAC_KEY(32)
;;;;   MAC  = SHA3-256(INT_8(32) | MAC_KEY | INT_8(16) | SALT | CIPHERTEXT)
;;;;   plaintext = AES256-CTR(SECRET_KEY, SECRET_IV) XOR CIPHERTEXT
;;;; Layer 1 (superencrypted): SECRET_DATA = blinded-key, STRING = "hsdir-superencrypted-data".
;;;; Layer 2 (encrypted):      SECRET_DATA = blinded-key [| desc-cookie], STRING = "hsdir-encrypted-data".
;;;; Inner plaintext holds the introduction points.

(defpackage #:cl-tor.hsdesc
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:ed #:cl-tor.ed25519))
  (:export #:decrypt-descriptor #:intro-points
           #:intro-point #:intro-point-link-specs #:intro-point-onion-key
           #:intro-point-auth-key #:intro-point-enc-key #:intro-point-enc-cert))

(in-package #:cl-tor.hsdesc)

(defun %int8be (n)
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b (- 7 i)) (logand (ash n (* -8 i)) #xff)))))

(defun %message-blob (text &key (start 0))
  "Base64-decode the first -----BEGIN MESSAGE----- .. -----END MESSAGE----- after START."
  (let* ((b (search "-----BEGIN MESSAGE-----" text :start2 start))
         (e (and b (search "-----END MESSAGE-----" text :start2 b))))
    (unless (and b e) (error "hsdesc: no MESSAGE block"))
    (u:base64-decode
     (remove-if (lambda (ch) (member ch '(#\Newline #\Return #\Space #\Tab)))
                (subseq text (+ b (length "-----BEGIN MESSAGE-----")) e)))))

(defun %int-field (text name)
  "Integer value of the 'NAME <int>' line (NAME at a line start), or NIL."
  (let* ((needle (concatenate 'string (string #\Newline) name " "))
         (padded (concatenate 'string (string #\Newline) text))
         (i (search needle padded)))
    (when i (parse-integer padded :start (+ i (length needle)) :junk-allowed t))))

(defun %decrypt-layer (blob secret-data subcred revision string-constant)
  "Decrypt one descriptor layer; verify the MAC first.  Returns the plaintext string."
  (let* ((n (length blob))
         (salt (subseq blob 0 16))
         (mac (subseq blob (- n 32) n))
         (ct (subseq blob 16 (- n 32)))
         (secret-input (u:cat secret-data subcred (%int8be revision)))
         (keys (ed:shake256 (u:cat secret-input salt (u:ascii->bytes string-constant)) 80))
         (key (subseq keys 0 32)) (iv (subseq keys 32 48)) (mac-key (subseq keys 48 80))
         (want (c:sha3-256 (u:cat (%int8be 32) mac-key (%int8be 16) salt ct))))
    (unless (equalp want mac) (error "hsdesc: ~a MAC mismatch" string-constant))
    ;; 32-byte key -> AES-256-CTR; ctr-apply RETURNS the decrypted bytes
    (map 'string #'code-char (c:ctr-apply (c:aes128-ctr-cipher key iv) ct))))

(defun decrypt-descriptor (outer-text identity-pubkey period-num period-length &optional cookie)
  "Decrypt both layers of a v3 descriptor OUTER-TEXT for ONION identity-pubkey in the
   given time period.  Returns the inner plaintext (the introduction-point section)."
  (let* ((blinded (ed:blind-public-key identity-pubkey period-num period-length))
         (subcred (ed:subcredential identity-pubkey blinded))
         (revision (or (%int-field outer-text "revision-counter") 0))
         (layer1 (%decrypt-layer (%message-blob outer-text)
                                 blinded subcred revision "hsdir-superencrypted-data"))
         (layer2 (%decrypt-layer (%message-blob layer1)
                                 (if cookie (u:cat blinded cookie) blinded)
                                 subcred revision "hsdir-encrypted-data")))
    layer2))

;;; --- introduction points ----------------------------------------------------

(defstruct intro-point
  link-specs      ; raw link specifiers of the intro-point RELAY (NSPEC|{type,len,spec}...)
  onion-key       ; that relay's ntor key (to build a circuit to it)
  auth-key        ; intro AUTH_KEY (ed25519, from the auth-key cert's certified key)
  enc-key         ; the service's ntor enc key B for this intro (hs-ntor)
  enc-cert)       ; ed25519 certified key of the enc-key cross-cert (== curve25519->ed25519 enc-key)

(defun %cert-certified-key (cert-bytes)
  "The 32-byte CERTIFIED_KEY of a Tor ed25519 cert (cert-spec): version(1) type(1)
   expiration(4) key-type(1) then CERTIFIED_KEY(32)."
  (subseq cert-bytes 7 39))

(defun intro-points (inner-text)
  "Parse the decrypted inner plaintext into INTRO-POINTs: the relay link specifiers,
   its ntor onion-key, the intro AUTH_KEY (from its ed25519 cert), and the service's
   ntor enc-key B — everything the introduction handshake needs."
  (let ((points '()) (cur nil) (pending-cert-for nil) (cert-acc nil))
    (flet ((flush-cert ()
             (when (and pending-cert-for cert-acc cur)
               (let ((cert (u:base64-decode (apply #'concatenate 'string (nreverse cert-acc)))))
                 (case pending-cert-for
                   (:auth (setf (intro-point-auth-key cur) (%cert-certified-key cert)))
                   (:enc-cert (setf (intro-point-enc-cert cur) (%cert-certified-key cert)))))
               (setf pending-cert-for nil cert-acc nil))))
      (with-input-from-string (in inner-text)
        (loop for line = (read-line in nil) while line do
          (cond
            ((search "-----BEGIN ED25519 CERT-----" line))                 ; skip marker
            ((search "-----END ED25519 CERT-----" line) (flush-cert))
            (pending-cert-for (push line cert-acc))                         ; accumulate cert body
            (t (let ((tk (remove "" (uiop:split-string line :separator '(#\Space #\Tab)) :test #'string=)))
                 (cond
                   ((string= (first tk) "introduction-point")
                    (when cur (push cur points))
                    (setf cur (make-intro-point :link-specs (u:base64-decode (second tk)))))
                   ((and cur (string= (first tk) "onion-key") (string= (second tk) "ntor"))
                    (setf (intro-point-onion-key cur) (u:base64-decode (third tk))))
                   ((and cur (string= (first tk) "enc-key") (string= (second tk) "ntor"))
                    (setf (intro-point-enc-key cur) (u:base64-decode (third tk))))
                   ((and cur (string= (first tk) "auth-key")) (setf pending-cert-for :auth))
                   ((and cur (string= (first tk) "enc-key-cert")) (setf pending-cert-for :enc-cert))))))))
      (flush-cert)
      (when cur (push cur points))
      (nreverse points))))
