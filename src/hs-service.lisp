;;;; src/hs-service.lisp — v3 onion SERVICE: build/sign/encrypt a descriptor (S2).
;;;;
;;;; The mirror of the client's hs-desc: instead of fetching + decrypting, the service
;;;; ASSEMBLES its descriptor — a signing keypair, a blinded-key-signed cert over it,
;;;; the introduction-point section, two encrypted layers, and the outer signature —
;;;; ready to upload to the responsible HSDirs.  Encryption is symmetric with the
;;;; client's decrypt (AES-256-CTR + SHA3-256 MAC), so this round-trips through
;;;; cl-tor.hsdesc:decrypt-descriptor.

(defpackage #:cl-tor.hsservice
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:ed #:cl-tor.ed25519))
  (:export #:generate-identity #:identity-from-seed #:hs-identity-seed #:hs-identity-pubkey
           #:make-intro #:intro-link-specs #:intro-onion-key #:intro-auth-seed
           #:intro-enc-pub #:intro-enc-seed
           #:build-descriptor #:*descriptor-lifetime*))

(in-package #:cl-tor.hsservice)

(defparameter *descriptor-lifetime* 180 "Descriptor validity in minutes (Tor uses 180).")
(defconstant +unix-epoch-univ+ 2208988800 "Universal-time value of the Unix epoch.")

(defun %int8be (n)
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b (- 7 i)) (logand (ash n (* -8 i)) #xff)))))

(defun %now-hours (&optional (add 0))
  "Hours since the Unix epoch (+ ADD hours), for cert expiration."
  (+ (floor (- (get-universal-time) +unix-epoch-univ+) 3600) add))

;;; --- service identity -------------------------------------------------------

(defstruct (hs-identity (:constructor %make-identity)) seed pubkey)

(defun generate-identity ()
  "A fresh long-term service identity (Ed25519).  Persist the SEED to keep the address."
  (let ((seed (c:random-bytes 32)))
    (%make-identity :seed seed :pubkey (ed:secret-to-public seed))))

(defun identity-from-seed (seed)
  (%make-identity :seed seed :pubkey (ed:secret-to-public seed)))

;;; --- base64 / PEM helpers ---------------------------------------------------

(defun %wrap64 (s)
  "Insert a newline every 64 chars (PEM body wrapping)."
  (with-output-to-string (out)
    (loop for i from 0 below (length s) by 64
          do (write-string s out :start i :end (min (length s) (+ i 64)))
             (write-char #\Newline out))))

(defun %pem (label bytes)
  (format nil "-----BEGIN ~a-----~%~a-----END ~a-----" label (%wrap64 (u:base64-encode bytes)) label))

(defun %msg (bytes) (%pem "MESSAGE" bytes))
(defun %cert-pem (bytes) (%pem "ED25519 CERT" bytes))
(defun %b64 (bytes) (u:base64-encode bytes :pad nil))    ; inline keys are unpadded

;;; --- Tor ed25519 certificate (cert-spec / prop 220) -------------------------

(defun %cert (cert-type certified-key exp-hours sign-fn &key signing-ext-key)
  "Build + sign a Tor ed25519 cert.  SIGN-FN signs the cert body -> 64-byte sig.
   SIGNING-EXT-KEY (32 bytes) adds the signed-with-ed25519-key extension (type 4:
   ExtLength(2)|ExtType(1)|ExtFlags(1)|ExtData)."
  (let* ((ext (when signing-ext-key
                (u:cat (u:u16be 32) (vector 4) (vector 0) signing-ext-key)))
         (body (u:cat (vector 1)                    ; VERSION
                      (vector cert-type)            ; CERT_TYPE
                      (u:u32be exp-hours)           ; EXPIRATION (hours since epoch)
                      (vector 1)                    ; CERT_KEY_TYPE = ed25519
                      certified-key                 ; CERTIFIED_KEY (32)
                      (vector (if signing-ext-key 1 0))   ; N_EXTENSIONS
                      (or ext #()))))
    (u:cat body (funcall sign-fn body))))

;;; --- introduction points ----------------------------------------------------

(defstruct (intro (:constructor %make-intro))
  link-specs      ; NSPEC|{...} of the intro RELAY
  onion-key       ; that relay's ntor key (32)
  auth-seed       ; per-intro AUTH keypair seed (Ed25519)
  enc-seed        ; per-intro service enc keypair seed (x25519)
  enc-pub)        ; the x25519 enc pubkey (32)

(defun make-intro (link-specs onion-key)
  "An intro point for INTRO-RELAY (LINK-SPECS + its ntor ONION-KEY); fresh per-intro
   AUTH (Ed25519) and ENC (x25519) keys are generated."
  (let ((enc-seed (c:random-bytes 32)))
    (%make-intro :link-specs link-specs :onion-key onion-key
                 :auth-seed (c:random-bytes 32)
                 :enc-seed enc-seed :enc-pub (c:x25519-public enc-seed))))

(defun %intro-block (ip sign-fn signing-pub exp-hours)
  "The descriptor text for one introduction point (SIGN-FN signs its certs with the
   descriptor signing key)."
  (let* ((auth-pub (ed:secret-to-public (intro-auth-seed ip)))
         (auth-cert (%cert #x09 auth-pub exp-hours sign-fn :signing-ext-key signing-pub))
         ;; enc-key-cert (cross-cert, type 0B): certifies the Ed25519 equivalent of the
         ;; ntor enc key (prop228 App. A: y=(u-1)/(u+1), signbit 0), signed by the
         ;; descriptor signing key.  Stock-Tor clients validate this before using the
         ;; intro point — the conversion is byte-verified against real descriptors.
         (enc-cert (%cert #x0b (ed:curve25519->ed25519 (intro-enc-pub ip) 0)
                          exp-hours sign-fn :signing-ext-key signing-pub)))
    (format nil "introduction-point ~a~%onion-key ntor ~a~%auth-key~%~a~%enc-key ntor ~a~%enc-key-cert~%~a~%"
            (%b64 (intro-link-specs ip)) (%b64 (intro-onion-key ip))
            (%cert-pem auth-cert) (%b64 (intro-enc-pub ip)) (%cert-pem enc-cert))))

;;; --- layer encryption (mirror of hsdesc:%decrypt-layer) ---------------------

(defun %pad (bytes &optional (multiple 10000))
  "NUL-pad BYTES up to a multiple of MULTIPLE (hides the plaintext length)."
  (let ((n (* multiple (ceiling (max 1 (length bytes)) multiple))))
    (if (= n (length bytes)) bytes (u:cat bytes (u:octets (- n (length bytes)))))))

(defun %encrypt-layer (plaintext-bytes secret-data subcred revision string-constant)
  "Encrypt one descriptor layer -> SALT(16) | CIPHERTEXT | MAC(32)."
  (let* ((salt (c:random-bytes 16))
         (secret-input (u:cat secret-data subcred (%int8be revision)))
         (keys (ed:shake256 (u:cat secret-input salt (u:ascii->bytes string-constant)) 80))
         (key (subseq keys 0 32)) (iv (subseq keys 32 48)) (mac-key (subseq keys 48 80))
         (ct (c:ctr-apply (c:aes128-ctr-cipher key iv) plaintext-bytes))
         (mac (c:sha3-256 (u:cat (%int8be 32) mac-key (%int8be 16) salt ct))))
    (u:cat salt ct mac)))

;;; --- second (inner) layer ---------------------------------------------------

(defun %second-layer (intros sign-fn signing-pub exp-hours)
  (%pad (u:ascii->bytes
         (format nil "create2-formats 2~%~{~a~}"
                 (mapcar (lambda (ip) (%intro-block ip sign-fn signing-pub exp-hours)) intros)))))

;;; --- first (superencrypted) layer -------------------------------------------

(defun %auth-client-line ()
  (format nil "auth-client ~a ~a ~a"
          (%b64 (c:random-bytes 8)) (%b64 (c:random-bytes 16)) (%b64 (c:random-bytes 16))))

(defun %first-layer (inner-encrypted)
  "The superencrypted plaintext: no client auth (a fresh ephemeral key + fake
   auth-client lines for privacy), wrapping the already-encrypted inner layer."
  (let ((eph (c:x25519-public (c:random-bytes 32))))
    (%pad (u:ascii->bytes
           (format nil "desc-auth-type x25519~%desc-auth-ephemeral-key ~a~%~{~a~%~}encrypted~%~a~%"
                   (%b64 eph)
                   (loop repeat 16 collect (%auth-client-line))
                   (%msg inner-encrypted))))))

;;; --- outer descriptor -------------------------------------------------------

(defparameter +desc-sig-prefix+ "Tor onion service descriptor sig v3")

(defun build-descriptor (id period-num period-length revision intros)
  "Assemble a complete, signed, doubly-encrypted v3 descriptor for ID in the given
   time period, advertising INTROS.  Returns the descriptor text (ready to upload).
   ID is a struct from GENERATE-IDENTITY / IDENTITY-FROM-SEED."
  (let* ((id-pub (hs-identity-pubkey id))
         (blinded (ed:blind-public-key id-pub period-num period-length))
         (subcred (ed:subcredential id-pub blinded))
         (exp-hours (%now-hours 54))
         ;; descriptor signing key (short-term), certified by the blinded key
         (sign-seed (c:random-bytes 32))
         (sign-pub (ed:secret-to-public sign-seed))
         (blind-sign-fn (lambda (msg) (ed:blind-sign (hs-identity-seed id) id-pub
                                                     period-num period-length msg)))
         (desc-sign-fn (lambda (msg) (ed:sign sign-seed msg)))
         (signing-cert (%cert #x08 sign-pub exp-hours blind-sign-fn :signing-ext-key blinded))
         ;; two encrypted layers
         (inner (%encrypt-layer (%second-layer intros desc-sign-fn sign-pub exp-hours)
                                blinded subcred revision "hsdir-encrypted-data"))
         (super (%encrypt-layer (%first-layer inner)
                                blinded subcred revision "hsdir-superencrypted-data"))
         ;; outer document up to and including the superencrypted block
         (outer (format nil "hs-descriptor 3~%descriptor-lifetime ~d~%descriptor-signing-key-cert~%~a~%revision-counter ~d~%superencrypted~%~a~%"
                        *descriptor-lifetime* (%cert-pem signing-cert) revision (%msg super)))
         (sig (ed:sign sign-seed
                       (u:cat (u:ascii->bytes +desc-sig-prefix+) (u:ascii->bytes outer)))))
    (format nil "~asignature ~a~%" outer (%b64 sig))))
