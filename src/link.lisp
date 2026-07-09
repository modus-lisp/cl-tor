;;;; src/link.lisp — the client-side link handshake (tor-spec §2-4).
;;;;
;;;; Open a TLS connection to a relay's ORPort and run the in-protocol v3+ link
;;;; handshake.  As a client we never authenticate ourselves (only relays
;;;; authenticate to us), so the flow is:
;;;;
;;;;   TLS connect (certs are self-signed; no CA check) ->
;;;;   send VERSIONS [3,4,5]; read VERSIONS, pick max common ->
;;;;   read CERTS, AUTH_CHALLENGE (ignored), NETINFO ->
;;;;   validate the relay's Ed25519 cert chain + TLS-cert binding ->
;;;;   send our NETINFO.  Link is then ready for CREATE2.
;;;;
;;;; Cert validation here is the Ed25519 chain (cert 4: identity->signing;
;;;; cert 5: signing->SHA256(TLS cert)) matched to the expected consensus
;;;; identity.  RSA cross-cert (types 2/7) is deferred to P6 hardening; circuit
;;;; security ultimately rests on ntor + a validated consensus regardless.

(in-package #:cl-tor.link)

(defvar *debug-certs* nil "When true, print why cert validation failed.")

(defstruct (link (:constructor %make-link))
  relay sock stream conn version circid-len validated my-apparent-addr)

(defun send-cell (link cmd payload)
  (cell:write-cell (link-stream link) (link-circid-len link) 0 cmd payload))

(defun recv-cell (link)
  (cell:read-cell (link-stream link) (link-circid-len link)))

(defun close-link (link)
  (ignore-errors (close (link-stream link)))
  (ignore-errors (usocket:socket-close (link-sock link)))
  (when (link-conn link) (ignore-errors (seal:tls-close (link-conn link))))
  link)

;;; ---- VERSIONS -----------------------------------------------------------

(defparameter *our-versions* '(3 4 5))

(defun %versions-payload ()
  (apply #'u:cat (mapcar #'u:u16be *our-versions*)))

(defun %parse-versions (payload)
  (loop for i from 0 below (1- (length payload)) by 2
        collect (u:read-u16be payload i)))

;;; ---- Ed25519 cert parsing (cert-spec) -----------------------------------

(defun %parse-certs-cell (payload)
  "CERTS payload -> alist of (cert-type . cert-bytes)."
  (let ((n (aref payload 0)) (pos 1) (out '()))
    (dotimes (i n (nreverse out))
      (let* ((type (aref payload pos))
             (len (u:read-u16be payload (1+ pos)))
             (cert (u:subv payload (+ pos 3) (+ pos 3 len))))
        (push (cons type cert) out)
        (setf pos (+ pos 3 len))))))

(defun %parse-ed-cert (cert)
  "Parse an Ed25519 cert (cert-spec) -> (values certified-key signed-with body sig).
BODY is the signed region; SIGNED-WITH is the 32-byte key from the type-4
extension (the signer), or NIL."
  ;; VERSION(1) CERT_TYPE(1) EXPIRATION(4) CERT_KEY_TYPE(1) CERTIFIED_KEY(32)
  ;; N_EXTENSIONS(1) EXTENSIONS... SIGNATURE(64)
  (let* ((certified (u:subv cert 7 39))
         (n-ext (aref cert 39))
         (pos 40) (signed-with nil))
    (dotimes (i n-ext)
      (let* ((elen (u:read-u16be cert pos))
             (etype (aref cert (+ pos 2)))
             (edata (u:subv cert (+ pos 4) (+ pos 4 elen))))
        (when (= etype 4) (setf signed-with edata))
        (setf pos (+ pos 4 elen))))
    (values certified signed-with
            (u:subv cert 0 (- (length cert) 64))
            (u:subv cert (- (length cert) 64) (length cert)))))

(defparameter +rsa-ed-crosscert-prefix+
  (u:ascii->bytes "Tor TLS RSA/Ed25519 cross-certificate"))

(defun %validate-rsa-crosscert (certs identity expect-rsa-id)
  "Validate the RSA identity binding (cert-spec §2.3): cert 2 holds the RSA
identity key (fingerprint must match the consensus rsa-id, exponent 65537);
cert 7 is that RSA key signing the Ed25519 IDENTITY.  Signals on failure."
  (let ((c2 (cdr (assoc 2 certs))) (c7 (cdr (assoc 7 certs))))
    (unless (and c2 c7) (error "link: missing RSA certs (2/7)"))
    (let ((rsa-der (c:x509-rsa-key c2)))
      (when (and expect-rsa-id (not (u:bytes= (c:sha1 rsa-der) expect-rsa-id)))
        (error "link: RSA identity does not match consensus fingerprint"))
      (multiple-value-bind (n e) (c:der-rsa-public-key rsa-der)
        (unless (= e 65537) (error "link: RSA identity exponent is not 65537"))
        ;; cert 7: ED25519_KEY(32) EXPIRATION(4) SIGLEN(1) SIGNATURE
        (let* ((ed-key (u:subv c7 0 32))
               (expiration (u:subv c7 32 36))
               (siglen (aref c7 36))
               (sig (u:subv c7 37 (+ 37 siglen)))
               (digest (c:sha256 (u:cat +rsa-ed-crosscert-prefix+ ed-key expiration))))
          (unless (u:bytes= ed-key identity)
            (error "link: cross-cert certifies a different Ed25519 identity"))
          (unless (c:rsa-verify n e sig digest)
            (error "link: RSA->Ed25519 cross-cert signature invalid")))))))

(defun %validate-certs (certs tls-cert-sha256 expect-ed-id expect-rsa-id)
  "Validate the relay's certificate chain: the Ed25519 link chain (cert 4
identity->signing, cert 5 signing->TLS-cert) bound to the presented TLS cert and
matched to the consensus Ed25519 id, plus the RSA identity cross-cert (certs 2/7)
matched to the consensus RSA id.  Returns the Ed25519 identity, or signals."
  (let ((c4 (cdr (assoc 4 certs))) (c5 (cdr (assoc 5 certs))))
    (unless (and c4 c5) (error "link: missing Ed25519 certs (4/5)"))
    (multiple-value-bind (signing identity body4 sig4) (%parse-ed-cert c4)
      (unless identity (error "link: cert4 has no signing-key extension"))
      (unless (c:ed25519-verify identity body4 sig4)
        (error "link: cert4 signature invalid (identity->signing)"))
      (multiple-value-bind (certified-tls ignore body5 sig5) (%parse-ed-cert c5)
        (declare (ignore ignore))
        (unless (c:ed25519-verify signing body5 sig5)
          (error "link: cert5 signature invalid (signing->link)"))
        (unless (u:bytes= certified-tls tls-cert-sha256)
          (error "link: cert5 does not bind the presented TLS certificate"))
        (when (and expect-ed-id (not (u:bytes= identity expect-ed-id)))
          (error "link: relay Ed25519 identity does not match consensus"))
        (%validate-rsa-crosscert certs identity expect-rsa-id)
        identity))))

;;; ---- NETINFO ------------------------------------------------------------

(defun %ipv4-bytes (dotted)
  (let ((b (u:octets 4)) (i 0))
    (dolist (part (uiop:split-string dotted :separator ".") b)
      (setf (aref b i) (parse-integer part)) (incf i))))

(defun %build-netinfo (relay-ip)
  "Our NETINFO: timestamp 0, other-addr = the relay's IPv4, no addresses of ours."
  (u:cat (u:u32be 0)                       ; timestamp (0 is allowed for clients)
         (u:u8 4) (u:u8 4) (%ipv4-bytes relay-ip)  ; OTHERADDR: type 4, len 4, value
         (u:u8 0)))                        ; NMYADDR = 0

(defun %parse-netinfo-other (payload)
  "Pull our apparent address out of a relay NETINFO (the OTHERADDR field)."
  (when (and (>= (length payload) 10) (= (aref payload 4) 4))   ; ATYPE 4 = IPv4
    (format nil "~d.~d.~d.~d" (aref payload 6) (aref payload 7)
            (aref payload 8) (aref payload 9))))

;;; ---- connect ------------------------------------------------------------

(defun %seal-transport (sock)
  "A seal TLS transport over an already-connected usocket SOCK, so cl-tor keeps owning
   the socket — closing it still unblocks a reader parked in a cell read, exactly as
   before (the gray-stream / socks close paths are unchanged)."
  (let* ((bsd (usocket:socket sock))
         (fd (sb-bsd-sockets:socket-file-descriptor bsd)))
    (seal::%make-transport
     :sender (lambda (bytes)
               (let ((buf (coerce bytes '(simple-array (unsigned-byte 8) (*)))))
                 (sb-bsd-sockets:socket-send bsd buf (length buf)) t))
     :receiver (lambda ()
                 (when (sb-sys:wait-until-fd-usable fd :input 30)
                   (let ((buf (make-array 16384 :element-type '(unsigned-byte 8))))
                     (handler-case
                         (multiple-value-bind (data len) (sb-bsd-sockets:socket-receive bsd buf nil)
                           (declare (ignore data))
                           (when (and len (plusp len)) (subseq buf 0 len)))
                       (sb-bsd-sockets:socket-error () nil)))))
     :closer (lambda () (ignore-errors (usocket:socket-close sock))))))

(defun connect-link (relay &key (timeout 20))
  "Open and complete a link handshake to RELAY (a dir:relay).  Returns a LINK.  The TLS
   is pure Common Lisp via seal (no OpenSSL / FFI); relays' self-signed certs are not
   CA-checked (:verify nil) — Tor binds identity through the CERTS cell instead."
  (let* ((ip (dir:relay-ip relay)) (port (dir:relay-or-port relay))
         (sock (usocket:socket-connect ip port :element-type '(unsigned-byte 8)
                                               :timeout timeout))
         (conn (seal:connect ip port :verify nil :timeout timeout
                                     :transport (%seal-transport sock)))
         (tls (seal:make-tls-stream conn))
         (link (%make-link :relay relay :sock sock :stream tls :conn conn :circid-len 2)))
    (handler-case
        (progn
          ;; 1. VERSIONS exchange (2-byte circ ids on these cells).
          (cell:write-cell tls 2 0 cell:+versions+ (%versions-payload))
          (multiple-value-bind (cid cmd payload) (cell:read-cell tls 2)
            (declare (ignore cid))
            (unless (= cmd cell:+versions+) (error "link: expected VERSIONS, got ~d" cmd))
            (let ((common (intersection *our-versions* (%parse-versions payload))))
              (unless common (error "link: no common link version"))
              (setf (link-version link) (apply #'max common)
                    (link-circid-len link) (if (>= (link-version link) 4) 4 2))))
          ;; 2. Read CERTS / AUTH_CHALLENGE / NETINFO (now negotiated circ-id len).
          (let ((certs nil))
            (loop
              (multiple-value-bind (cid cmd payload) (recv-cell link)
                (declare (ignore cid))
                (cond
                  ((= cmd cell:+certs+) (setf certs (%parse-certs-cell payload)))
                  ((= cmd cell:+auth-challenge+))         ; ignore: we don't authenticate
                  ((= cmd cell:+netinfo+)
                   (setf (link-my-apparent-addr link) (%parse-netinfo-other payload))
                   (return))
                  ((= cmd cell:+vpadding+))               ; ignore padding
                  (t (error "link: unexpected cell ~d during handshake" cmd)))))
            ;; 3. Validate the relay's Ed25519 cert chain against the TLS cert.
            (let* ((leaf (first (seal:tls-connection-peer-certificates conn)))
                   (fp (and leaf (c:sha256 (seal:certificate-raw leaf)))))
              (setf (link-validated link)
                    (and certs fp
                         (handler-case
                             (progn
                               (%validate-certs certs
                                                (coerce fp '(simple-array (unsigned-byte 8) (*)))
                                                (dir:relay-ed-id relay)
                                                (dir:relay-rsa-id relay))
                               t)
                           (error (e)
                             (when *debug-certs* (format *error-output* "~&[cert] ~a~%" e))
                             nil))))))
          ;; 4. Our NETINFO -> link is ready.
          (send-cell link cell:+netinfo+ (%build-netinfo ip))
          link)
      (error (e) (close-link link) (error e)))))
