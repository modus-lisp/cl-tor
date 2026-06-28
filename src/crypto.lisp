;;;; src/crypto.lisp — the Tor cipher suite, wrapped over ironclad.
;;;;
;;;; Tor uses a small, fixed set of primitives: SHA-1 (relay-cell running digest)
;;;; and SHA-256 (ntor / directory), HMAC-SHA256 (ntor's H and HKDF), AES-128-CTR
;;;; (relay-cell onion crypto), Curve25519/X25519 (ntor key exchange), and Ed25519
;;;; (relay identity / cert validation).  These thin wrappers give them byte-vector
;;;; signatures so the protocol layers above never touch ironclad objects — which
;;;; also makes the eventual modus port a matter of re-pointing this one file.

(in-package #:cl-tor.crypto)

(defun random-bytes (n) (ironclad:random-data n))

(defun sha1   (bytes) (ironclad:digest-sequence :sha1   (u::cat bytes)))
(defun sha256 (bytes) (ironclad:digest-sequence :sha256 (u::cat bytes)))
(defun sha3-256 (bytes) (ironclad:digest-sequence :sha3/256 (u::cat bytes)))

(defun hmac-sha256 (key msg)
  "HMAC-SHA256(key, msg) -> 32 bytes."
  (let ((m (ironclad:make-hmac (u::cat key) :sha256)))
    (ironclad:update-hmac m (u::cat msg))
    (ironclad:hmac-digest m)))

(defun hkdf-expand (prk info length)
  "RFC-5869 HKDF-Expand with HMAC-SHA256: expand PRK to LENGTH bytes using INFO."
  (let ((out (u:octets 0)) (prev (u:octets 0)) (i 1))
    (loop while (< (length out) length)
          do (setf prev (hmac-sha256 prk (u:cat prev info (u:u8 i)))
                   out (u:cat out prev))
             (incf i))
    (u:subv out 0 length)))

;;; ---- X25519 -------------------------------------------------------------

(defun x25519 (scalar point)
  "RFC-7748 X25519: SCALAR (32 bytes) times POINT u-coordinate (32 bytes) -> 32 bytes."
  (ironclad:diffie-hellman
   (ironclad:make-private-key :curve25519 :x (u::cat scalar))
   (ironclad:make-public-key  :curve25519 :y (u::cat point))))

(defun x25519-basepoint ()
  (let ((b (u:octets 32))) (setf (aref b 0) 9) b))

(defun x25519-public (scalar)
  "The public key (u-coordinate) for a 32-byte X25519 SCALAR."
  (x25519 scalar (x25519-basepoint)))

(defun gen-x25519 ()
  "Generate an ephemeral X25519 keypair -> (values scalar public)."
  (let ((s (random-bytes 32))) (values s (x25519-public s))))

;;; ---- AES-128-CTR (relay-cell crypto) ------------------------------------

(defun aes128-ctr-cipher (key &optional (iv (u:octets 16)))
  "A stateful AES-128-CTR cipher object; advance it with CTR-APPLY."
  (ironclad:make-cipher :aes :key (u::cat key) :mode :ctr
                            :initialization-vector (u::cat iv)))

(defun ctr-apply (cipher bytes)
  "Apply CTR keystream to BYTES (encrypt == decrypt), advancing CIPHER's counter.
Returns a fresh byte vector."
  (let ((buf (u::cat bytes)))
    (ironclad:encrypt-in-place cipher buf)
    buf))

;;; ---- RSA (directory / consensus signatures) -----------------------------
;;; Implemented from scratch (modexp + DER parse + PKCS#1 v1.5 unpadding) so the
;;; modus port doesn't need an RSA library; Tor's signatures pad the raw digest
;;; with PKCS#1 v1.5 and no DigestInfo wrapper.

(defun mod-expt (base exp modulus)
  "Modular exponentiation BASE^EXP mod MODULUS (square-and-multiply)."
  (let ((result 1) (b (mod base modulus)))
    (loop while (plusp exp)
          do (when (oddp exp) (setf result (mod (* result b) modulus)))
             (setf exp (ash exp -1) b (mod (* b b) modulus)))
    result))

(defun %der-len (der pos)
  "Read a DER length at POS -> (values length next-pos)."
  (let ((b (aref der pos)))
    (if (< b #x80)
        (values b (1+ pos))
        (let ((nbytes (- b #x80)) (len 0))
          (dotimes (i nbytes) (setf len (logior (ash len 8) (aref der (+ pos 1 i)))))
          (values len (+ pos 1 nbytes))))))

(defun der-rsa-public-key (der)
  "Parse a PKCS#1 RSAPublicKey DER (SEQUENCE{INTEGER n, INTEGER e}) -> (values n e)."
  (assert (= (aref der 0) #x30))
  (multiple-value-bind (seqlen p) (%der-len der 1)
    (declare (ignore seqlen))
    (assert (= (aref der p) #x02))
    (multiple-value-bind (nlen p2) (%der-len der (1+ p))
      (let ((n (u:bytes->int (u:subv der p2 (+ p2 nlen))))
            (pe (+ p2 nlen)))
        (assert (= (aref der pe) #x02))
        (multiple-value-bind (elen p3) (%der-len der (1+ pe))
          (values n (u:bytes->int (u:subv der p3 (+ p3 elen)))))))))

(defun rsa-verify (n e signature expected-digest)
  "T iff SIGNATURE (bytes) is a valid Tor RSA signature over EXPECTED-DIGEST:
raw RSA (sig^e mod n), PKCS#1 v1.5 unpad (00 01 FF.. 00), tail == EXPECTED-DIGEST."
  (handler-case
      (let* ((klen (ceiling (integer-length n) 8))
             (m (mod-expt (u:bytes->int signature) e n))
             (mb (u:int->bytes m klen)))
        (and (= (aref mb 0) 0) (= (aref mb 1) 1)
             (let ((i 2))
               (loop while (and (< i (length mb)) (= (aref mb i) #xff)) do (incf i))
               (and (< i (length mb)) (= (aref mb i) 0)
                    (u:bytes= (u:subv mb (1+ i)) expected-digest)))))
    (error () nil)))

;;; ---- Ed25519 (cert validation) ------------------------------------------

(defun ed25519-verify (public-key32 message sig64)
  "T iff SIG64 is a valid Ed25519 signature of MESSAGE under PUBLIC-KEY32."
  (handler-case
      (ironclad:verify-signature
       (ironclad:make-public-key :ed25519 :y (u::cat public-key32))
       (u::cat message) (u::cat sig64))
    (error () nil)))
