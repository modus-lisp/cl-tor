;;;; src/ntor.lisp — the ntor-curve25519-sha256-1 circuit handshake.
;;;;
;;;; ntor is Tor's one-way-authenticated key exchange: the client knows a relay's
;;;; ntor onion key B and identity ID, runs an X25519 exchange against a fresh
;;;; ephemeral, and ends up with shared keys *and* proof it's really talking to
;;;; the relay that holds b (the private onion key) — without authenticating
;;;; itself.  This is the core of CREATE2/EXTEND2 circuit construction.
;;;;
;;;; Per tor-spec (create-created-cells):
;;;;   H(x, t)      = HMAC-SHA256(key=t, msg=x)
;;;;   PROTOID      = "ntor-curve25519-sha256-1"
;;;;   t_mac/t_key/t_verify/m_expand = PROTOID | ":mac" | ":key_extract" | ":verify" | ":key_expand"
;;;;   secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID     (server view)
;;;;                = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID     (client view)
;;;;   KEY_SEED     = H(secret_input, t_key)     verify = H(secret_input, t_verify)
;;;;   auth_input   = verify | ID | B | Y | X | PROTOID | "Server"
;;;;   AUTH         = H(auth_input, t_mac)
;;;; Circuit keys come from HKDF-Expand(KEY_SEED, m_expand): Df|Db|Kf|Kb (20|20|16|16).

(in-package #:cl-tor.ntor)

(defparameter +protoid+   (u:ascii->bytes "ntor-curve25519-sha256-1"))
(defparameter +t-mac+     (u:cat +protoid+ (u:ascii->bytes ":mac")))
(defparameter +t-key+     (u:cat +protoid+ (u:ascii->bytes ":key_extract")))
(defparameter +t-verify+  (u:cat +protoid+ (u:ascii->bytes ":verify")))
(defparameter +m-expand+  (u:cat +protoid+ (u:ascii->bytes ":key_expand")))
(defparameter +server+    (u:ascii->bytes "Server"))

(defconstant +id-len+ 20)
(defconstant +g-len+ 32)                ; curve25519 element
(defconstant +onionskin-len+ 84)        ; ID(20) | B(32) | X(32)
(defconstant +reply-len+ 64)            ; Y(32) | AUTH(32)
(defconstant +key-material-len+ 72)     ; Df(20)|Db(20)|Kf(16)|Kb(16)

(defun h (msg tweak) (c:hmac-sha256 tweak msg))   ; H(x,t) = HMAC-SHA256(key=t, msg=x)

(defstruct circuit-keys
  "The four relay-cell keys derived for one hop."
  (df nil) (db nil) (kf nil) (kb nil))

(defun keys-from-seed (key-seed)
  "Expand KEY_SEED into a CIRCUIT-KEYS (Df|Db|Kf|Kb)."
  (let ((k (c:hkdf-expand key-seed +m-expand+ +key-material-len+)))
    (make-circuit-keys :df (u:subv k 0 20) :db (u:subv k 20 40)
                       :kf (u:subv k 40 56) :kb (u:subv k 56 72))))

(defun %finish (secret-input id b x y)
  "Shared tail: derive KEY_SEED + AUTH from SECRET-INPUT and the transcript."
  (let* ((key-seed (h secret-input +t-key+))
         (verify (h secret-input +t-verify+))
         (auth-input (u:cat verify id b y x +protoid+ +server+))
         (auth (h auth-input +t-mac+)))
    (values key-seed auth)))

;;; ---- client side --------------------------------------------------------

(defstruct (client-state (:constructor %make-client-state))
  x bigx b id)

(defun client-create (onion-key-b node-id)
  "Begin an ntor handshake to a relay with ntor onion key ONION-KEY-B (32 bytes)
and identity NODE-ID (20 bytes).  Returns (values onion-skin state); ONION-SKIN
is the 84-byte CREATE2/EXTEND2 handshake payload."
  (let* ((b (u:subv onion-key-b 0 +g-len+))
         (id (u:subv node-id 0 +id-len+)))
    (multiple-value-bind (x bigx) (c:gen-x25519)
      (values (u:cat id b bigx)
              (%make-client-state :x x :bigx bigx :b b :id id)))))

(defun client-finish (state reply)
  "Complete the handshake given the relay's 64-byte CREATED2/EXTENDED2 REPLY.
Returns a CIRCUIT-KEYS on success, or NIL if the relay's AUTH fails."
  (let* ((y (u:subv reply 0 +g-len+))
         (their-auth (u:subv reply +g-len+ +reply-len+))
         (x (client-state-x state)) (bigx (client-state-bigx state))
         (b (client-state-b state)) (id (client-state-id state))
         (secret-input (u:cat (c:x25519 x y) (c:x25519 x b) id b bigx y +protoid+)))
    (multiple-value-bind (key-seed auth) (%finish secret-input id b bigx y)
      (when (u:bytes= auth their-auth)
        (keys-from-seed key-seed)))))

;;; ---- server side (for tests / running as a relay) -----------------------

(defun server-handshake (onion-skin onion-priv-b onion-pub-b node-id)
  "Process a client ONION-SKIN as the relay holding ONION-PRIV-B / ONION-PUB-B
and identity NODE-ID.  Returns (values reply circuit-keys), or NIL if the skin
isn't addressed to us.  REPLY is the 64-byte CREATED2 payload."
  (let ((id (u:subv onion-skin 0 +id-len+))
        (keyid (u:subv onion-skin +id-len+ (+ +id-len+ +g-len+)))
        (bigx (u:subv onion-skin (+ +id-len+ +g-len+) +onionskin-len+))
        (b (u:subv onion-pub-b 0 +g-len+)))
    (when (and (u:bytes= id (u:subv node-id 0 +id-len+)) (u:bytes= keyid b))
      (multiple-value-bind (y bigy) (c:gen-x25519)
        (let ((secret-input (u:cat (c:x25519 y bigx) (c:x25519 onion-priv-b bigx)
                                   id b bigx bigy +protoid+)))
          (multiple-value-bind (key-seed auth) (%finish secret-input id b bigx bigy)
            (values (u:cat bigy auth) (keys-from-seed key-seed))))))))
