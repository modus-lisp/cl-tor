;;;; inspect/offline-test.lisp — offline gate for the crypto + ntor foundation.
;;;;
;;;; Proves the cipher suite against published vectors (X25519 / RFC-7748, HKDF /
;;;; RFC-5869) and the ntor handshake by full client<->server agreement: both
;;;; sides must derive identical circuit keys and the client must accept the
;;;; server's AUTH (and reject a tampered one).  The unforgeable end-to-end check
;;;; — a real CREATE2 against a live relay — comes with the link/circuit layer.

(defpackage #:cl-tor.test
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:n #:cl-tor.ntor))
  (:export #:run))

(in-package #:cl-tor.test)

(defvar *pass* 0) (defvar *fail* 0)
(defun check (name got want &key (test #'equalp))
  (if (funcall test got want)
      (progn (incf *pass*) (format t "  ok   ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a~%        got:  ~a~%        want: ~a~%"
                                   name got want))))
(defun check-true (name got)
  (if got (progn (incf *pass*) (format t "  ok   ~a~%" name))
      (progn (incf *fail*) (format t "  FAIL ~a (expected true)~%" name))))

(defun test-x25519 ()
  (format t "~%X25519 (RFC-7748 vector):~%")
  (check "scalarmult"
         (u:bytes->hex (c:x25519 (u:hex->bytes "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                                 (u:hex->bytes "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")))
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" :test #'string=)
  ;; basepoint scalarmult: public(scalar) for the RFC-7748 "Alice" key
  (check "basepoint pubkey"
         (u:bytes->hex (c:x25519-public (u:hex->bytes "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")))
         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" :test #'string=))

(defun test-hkdf ()
  ;; RFC-5869 Test Case 1 (SHA-256): given PRK, expand INFO to 42 bytes.
  (format t "~%HKDF-Expand (RFC-5869 case 1):~%")
  (check "expand"
         (u:bytes->hex (c:hkdf-expand
                        (u:hex->bytes "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                        (u:hex->bytes "f0f1f2f3f4f5f6f7f8f9") 42))
         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
         :test #'string=))

(defun test-ntor ()
  (format t "~%ntor handshake (client<->server agreement):~%")
  ;; A relay's long-term ntor onion keypair + identity.
  (multiple-value-bind (b bigb) (c:gen-x25519)
    (let ((id (c:random-bytes 20)))
      (multiple-value-bind (onion-skin state) (n:client-create bigb id)
        (check "onion-skin length" (length onion-skin) n:+onionskin-len+ :test #'=)
        (multiple-value-bind (reply server-keys) (n:server-handshake onion-skin b bigb id)
          (check-true "server accepted onion-skin (addressed to it)" reply)
          (let ((client-keys (n:client-finish state reply)))
            (check-true "client accepted server AUTH" client-keys)
            (when (and client-keys server-keys)
              (check "Kf agrees" (n:circuit-keys-kf client-keys) (n:circuit-keys-kf server-keys))
              (check "Kb agrees" (n:circuit-keys-kb client-keys) (n:circuit-keys-kb server-keys))
              (check "Df agrees" (n:circuit-keys-df client-keys) (n:circuit-keys-df server-keys))
              (check "Db agrees" (n:circuit-keys-db client-keys) (n:circuit-keys-db server-keys)))
            ;; tamper: flip one AUTH byte -> client must reject
            (let ((bad (copy-seq reply)))
              (setf (aref bad 40) (logxor (aref bad 40) 1))
              (check-true "client rejects tampered AUTH" (null (n:client-finish state bad))))
            ;; wrong relay: skin addressed to a different identity -> server declines
            (multiple-value-bind (skin2 st2) (n:client-create bigb (c:random-bytes 20))
              (declare (ignore st2))
              (check-true "server declines skin for a different id"
                          (null (n:server-handshake skin2 b bigb id))))))))))

(defun test-aes-ctr ()
  (format t "~%AES-128-CTR (involution):~%")
  (let* ((key (c:random-bytes 16))
         (pt (c:random-bytes 100))
         (e (c:ctr-apply (c:aes128-ctr-cipher key) pt))
         (d (c:ctr-apply (c:aes128-ctr-cipher key) e)))
    (check-true "encrypt then decrypt round-trips" (equalp pt d))
    (check-true "ciphertext differs from plaintext" (not (equalp pt e)))))

(defun run ()
  (setf *pass* 0 *fail* 0)
  (format t "~&=== cl-tor offline gate (crypto + ntor) ===~%")
  (test-x25519)
  (test-hkdf)
  (test-ntor)
  (test-aes-ctr)
  (format t "~%=== ~d passed, ~d failed ===~%" *pass* *fail*)
  (when (plusp *fail*) (error "cl-tor offline gate: ~d failures" *fail*))
  t)
