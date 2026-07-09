;;;; src/ed25519.lisp — Ed25519 group arithmetic + v3 onion key blinding.
;;;;
;;;; cl-tor.crypto only VERIFIES Ed25519 signatures (via ironclad); v3 onion services
;;;; need the group itself — scalar-mult of an arbitrary point — to derive blinded
;;;; keys (rend-spec-v3 key blinding).  This is a from-scratch, spec-exact Edwards
;;;; implementation (RFC 8032 curve, extended coordinates), kept separate so the
;;;; modus port can re-point it like the rest of the crypto.  CL bignums do the field
;;;; arithmetic; correctness is cross-checked against ironclad's Ed25519 keygen.

(defpackage #:cl-tor.ed25519
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto))
  (:export #:+l+ #:point-decode #:point-encode #:scalarmult #:scalarmult-base
           #:point-add #:blind-public-key #:blind-secret-scalar
           #:credential #:subcredential #:shake256
           #:expand-seed #:secret-to-public #:sign #:sign-with-scalar #:blind-sign
           #:int->le #:le->int #:int->be))

(in-package #:cl-tor.ed25519)

;;; --- field GF(2^255-19) -----------------------------------------------------

(defconstant +p+ (- (expt 2 255) 19))
(defconstant +l+ (+ (expt 2 252) 27742317777372353535851937790883648493)  ; group order
  "Order of the Ed25519 prime-order subgroup.")

(declaim (inline fadd fsub fmul))
(defun fadd (a b) (mod (+ a b) +p+))
(defun fsub (a b) (mod (- a b) +p+))
(defun fmul (a b) (mod (* a b) +p+))
(defun fpow (a e) (let ((r 1) (a (mod a +p+))) (loop while (> e 0) do
                    (when (oddp e) (setf r (fmul r a))) (setf a (fmul a a) e (ash e -1))) r))
(defun finv (a) (fpow a (- +p+ 2)))                              ; Fermat inverse

;;; d and sqrt(-1) need finv; compute at load time (defparameter, not defconstant).
(defparameter *d* (fmul (mod -121665 +p+) (finv 121666)))
(defparameter *sqrtm1* (fpow 2 (/ (- +p+ 1) 4)))

;;; --- little-endian <-> integer ---------------------------------------------

(defun le->int (bytes) (loop for i below (length bytes) sum (ash (aref bytes i) (* 8 i))))
(defun int->le (n len)
  (let ((b (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len b) (setf (aref b i) (logand (ash n (* -8 i)) #xff)))))

;;; --- points in extended coordinates (X Y Z T),  x=X/Z  y=Y/Z  T=XY/Z --------

(defstruct (pt (:constructor mk (x y z tt))) x y z tt)

(defparameter *base*
  (mk 15112221349535400772501151409588531511454012693041857206046113283949847762202
      46316835694926478169428394003475163141307993866256225615783033603165251855960
      1
      (fmul 15112221349535400772501151409588531511454012693041857206046113283949847762202
            46316835694926478169428394003475163141307993866256225615783033603165251855960)))

(defparameter *identity* (mk 0 1 1 0))

(defun point-add (p q)
  "Unified twisted-Edwards (a=-1) addition (add-2008-hwcd-3); complete, also doubles."
  (let* ((a (fmul (fsub (pt-y p) (pt-x p)) (fsub (pt-y q) (pt-x q))))
         (b (fmul (fadd (pt-y p) (pt-x p)) (fadd (pt-y q) (pt-x q))))
         (cc (fmul (fmul (pt-tt p) (fmul 2 *d*)) (pt-tt q)))
         (dd (fmul (fmul (pt-z p) 2) (pt-z q)))
         (e (fsub b a)) (f (fsub dd cc)) (g (fadd dd cc)) (h (fadd b a)))
    (mk (fmul e f) (fmul g h) (fmul f g) (fmul e h))))

(defun scalarmult (n point)
  "Scalar N (integer) times POINT, double-and-add MSB-first over 253 bits."
  (let ((r *identity*) (q point))
    (loop for i from 0 below 256 do
      (when (logbitp i n) (setf r (point-add r q)))
      (setf q (point-add q q)))
    r))

(defun scalarmult-base (n) (scalarmult n *base*))

;;; --- encode / decode --------------------------------------------------------

(defun point-encode (p)
  "Compress POINT to 32 bytes: y little-endian with the sign bit of x in bit 255."
  (let* ((zi (finv (pt-z p))) (x (fmul (pt-x p) zi)) (y (fmul (pt-y p) zi))
         (b (int->le y 32)))
    (setf (aref b 31) (logior (aref b 31) (ash (logand x 1) 7)))
    b))

(defun point-decode (bytes32)
  "Decompress 32 bytes to a point, or NIL if not a valid encoding."
  (let* ((sign (ldb (byte 1 7) (aref bytes32 31)))
         (y (logand (le->int bytes32) (1- (expt 2 255)))))
    (when (>= y +p+) (return-from point-decode nil))
    (let* ((y2 (fmul y y)) (uu (fsub y2 1)) (vv (fadd (fmul *d* y2) 1))
           (x (fmul (fmul uu (fpow vv 3)) (fpow (fmul uu (fpow vv 7)) (/ (- +p+ 5) 8)))))
      (let ((vx2 (fmul vv (fmul x x))))
        (cond ((= vx2 uu))                          ; ok
              ((= vx2 (mod (- uu) +p+)) (setf x (fmul x *sqrtm1*)))
              (t (return-from point-decode nil))))
      (when (and (= x 0) (= sign 1)) (return-from point-decode nil))
      (unless (= (logand x 1) sign) (setf x (fsub 0 x)))
      (mk x y 1 (fmul x y)))))

;;; --- SHAKE256 (ironclad) ----------------------------------------------------

(defun shake256 (bytes nbytes)
  "SHAKE256 XOF of BYTES to NBYTES output."
  (let ((d (ironclad:make-digest :shake256 :output-length nbytes)))
    (ironclad:update-digest d (u:cat bytes))
    (ironclad:produce-digest d)))

;;; --- v3 onion key blinding (rend-spec-v3) -----------------------------------

(defparameter +blind-string+
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (u:ascii->bytes "Derive temporary signing key") #(0)))

(defparameter +basepoint-string+
  (u:ascii->bytes
   "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"))

(defun %blinding-factor (identity-pubkey period-number period-length &optional secret)
  "Clamped Ed25519 blinding scalar h for the given identity key + time period."
  (let* ((n (u:cat (u:ascii->bytes "key-blind")
                   (int->be period-number 8) (int->be period-length 8)))
         (h (c:sha3-256 (u:cat +blind-string+ identity-pubkey (or secret #())
                               +basepoint-string+ n))))
    (setf (aref h 0)  (logand (aref h 0) 248)
          (aref h 31) (logand (aref h 31) 63)
          (aref h 31) (logior (aref h 31) 64))
    (le->int h)))

(defun int->be (n len)
  (let ((b (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len b) (setf (aref b (- len 1 i)) (logand (ash n (* -8 i)) #xff)))))

(defun blind-public-key (identity-pubkey period-number period-length &optional secret)
  "The blinded public key A' = h*A for IDENTITY-PUBKEY (32 bytes) in the given
   time period.  Returns 32 bytes."
  (let ((a (point-decode identity-pubkey)))
    (unless a (error "ed25519: invalid identity public key"))
    (point-encode (scalarmult (%blinding-factor identity-pubkey period-number period-length secret) a))))

(defun blind-secret-scalar (identity-scalar identity-pubkey period-number period-length &optional secret)
  "The blinded secret scalar a' = h*a mod L (for self-consistency tests / signing)."
  (mod (* (%blinding-factor identity-pubkey period-number period-length secret)
          identity-scalar)
       +l+))

;;; --- HS credential / subcredential ------------------------------------------

(defun credential (identity-pubkey)
  (c:sha3-256 (u:cat (u:ascii->bytes "credential") identity-pubkey)))

(defun subcredential (identity-pubkey blinded-pubkey)
  (c:sha3-256 (u:cat (u:ascii->bytes "subcredential")
                     (credential identity-pubkey) blinded-pubkey)))

;;; --- Ed25519 signing (RFC 8032) + blinded-key signing -----------------------
;;;
;;; cl-tor.crypto only verifies; the onion SERVICE has to SIGN — the descriptor,
;;; its certs, and ESTABLISH_INTRO.  Standard signing follows RFC 8032; the
;;; descriptor cert is signed by the *blinded* key, whose scalar a' = h*a has no
;;; seed, so we sign from the explicit scalar.  A verifier only checks
;;; S*B = R + H(R|A|M)*A, so any secret unique nonce is fine — we derive it
;;; deterministically from the signer's own prefix so signing needs no entropy.

(defun %sha512 (bytes) (ironclad:digest-sequence :sha512 (u:cat bytes)))

(defun expand-seed (seed)
  "RFC 8032: SHA-512(SEED) -> (values scalar prefix), scalar clamped."
  (let* ((h (%sha512 seed)) (a (subseq h 0 32)) (prefix (subseq h 32 64)))
    (setf (aref a 0)  (logand (aref a 0) 248)
          (aref a 31) (logand (aref a 31) 127)
          (aref a 31) (logior (aref a 31) 64))
    (values (le->int a) prefix)))

(defun secret-to-public (seed)
  "The 32-byte Ed25519 public key for SEED."
  (point-encode (scalarmult-base (expand-seed seed))))

(defun sign-with-scalar (scalar prefix message pubkey)
  "Ed25519 signature R|S (64 bytes) over MESSAGE from an explicit SCALAR + nonce
   PREFIX under PUBKEY.  Handles both seed-derived and BLINDED keys."
  (let* ((r (mod (le->int (%sha512 (u:cat prefix message))) +l+))
         (rr (point-encode (scalarmult-base r)))
         (k (mod (le->int (%sha512 (u:cat rr pubkey message))) +l+))
         (s (mod (+ r (* k scalar)) +l+)))
    (u:cat rr (int->le s 32))))

(defun sign (seed message)
  "Standard RFC-8032 Ed25519 signature over MESSAGE with a 32-byte SEED."
  (multiple-value-bind (scalar prefix) (expand-seed seed)
    (sign-with-scalar scalar prefix message (point-encode (scalarmult-base scalar)))))

(defun blind-sign (identity-seed identity-pubkey period-number period-length message
                   &optional secret)
  "Sign MESSAGE with the blinded key for the time period (the descriptor signing
   cert is signed by the blinded key).  Nonce derived from the identity prefix +
   a domain tag, so it's deterministic + secret."
  (multiple-value-bind (scalar prefix) (expand-seed identity-seed)
    (let* ((a-prime (blind-secret-scalar scalar identity-pubkey period-number period-length secret))
           (a-prime-pub (blind-public-key identity-pubkey period-number period-length secret))
           (prefix2 (c:sha3-256 (u:cat (u:ascii->bytes "blind-prefix") prefix))))
      (sign-with-scalar a-prime prefix2 message a-prime-pub))))
