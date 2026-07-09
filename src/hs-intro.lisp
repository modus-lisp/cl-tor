;;;; src/hs-intro.lisp — v3 onion service introduction (rend-spec-v3 §3-4).
;;;;
;;;; The client establishes a rendezvous point, then sends INTRODUCE1 (through the
;;;; intro point) carrying — encrypted to the service — the rendezvous cookie and the
;;;; client's ephemeral key for the client<->service hs-ntor handshake.  This file:
;;;; hs-ntor (client side) + the ESTABLISH_RENDEZVOUS / INTRODUCE1 cells.  Getting
;;;; INTRODUCE_ACK(status=0) proves the cell format + AUTH_KEY reach the right intro
;;;; point; the hs-ntor secret is only exercised end-to-end at the rendezvous (H5).

(defpackage #:cl-tor.hs-intro
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util) (#:c #:cl-tor.crypto) (#:ed #:cl-tor.ed25519)
                    (#:dir #:cl-tor.directory) (#:circ #:cl-tor.circuit) (#:link #:cl-tor.link)
                    (#:desc #:cl-tor.hsdesc))
  (:export #:introduce #:*hs-ntor-protoid*))

(in-package #:cl-tor.hs-intro)

(defconstant +r-establish-rendezvous+ 33)
(defconstant +r-introduce1+ 34)
(defconstant +r-rendezvous-established+ 39)
(defconstant +r-introduce-ack+ 40)

(defparameter *hs-ntor-protoid* "tor-hs-ntor-curve25519-sha3-256-1")

(defun %int8be (n)
  (let ((b (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 b) (setf (aref b (- 7 i)) (logand (ash n (* -8 i)) #xff)))))

;;; --- link specifiers <-> relay ----------------------------------------------

(defun %parse-link-specs (bytes)
  "NSPEC|{LSTYPE LSLEN LSPEC}... -> (values ip or-port rsa-id ed-id)."
  (let ((n (aref bytes 0)) (i 1) ip port rsa ed)
    (dotimes (k n (values ip port rsa ed))
      (let* ((ty (aref bytes i)) (ln (aref bytes (1+ i))) (spec (subseq bytes (+ i 2) (+ i 2 ln))))
        (case ty
          (0 (setf ip (format nil "~d.~d.~d.~d" (aref spec 0) (aref spec 1) (aref spec 2) (aref spec 3))
                   port (logior (ash (aref spec 4) 8) (aref spec 5))))
          (2 (setf rsa spec))
          (3 (setf ed spec)))
        (setf i (+ i 2 ln))))))

(defun %relay-link-specs (relay)
  "Build NSPEC|{IPv4,RSAid,ed25519} link specifiers for RELAY (for a cell payload)."
  (let* ((ip (map '(vector (unsigned-byte 8)) #'parse-integer
                  (uiop:split-string (dir:relay-ip relay) :separator ".")))
         (port (dir:relay-or-port relay))
         (v4 (u:cat ip (vector (ldb (byte 8 8) port) (ldb (byte 8 0) port))))
         (specs (list (list 0 v4) (list 2 (dir:relay-rsa-id relay)))))
    (when (dir:relay-ed-id relay) (setf specs (append specs (list (list 3 (dir:relay-ed-id relay))))))
    (apply #'u:cat (vector (length specs))
           (mapcar (lambda (ls) (u:cat (vector (first ls) (length (second ls))) (second ls))) specs))))

(defun %intro-relay (ip)
  "A relay struct for the intro-point RELAY, from its link specs + descriptor ntor key."
  (multiple-value-bind (addr port rsa ed) (%parse-link-specs (desc:intro-point-link-specs ip))
    (dir::make-relay :ip addr :or-port port :rsa-id rsa :ed-id ed
                     :ntor-key (desc:intro-point-onion-key ip))))

;;; --- circuits ---------------------------------------------------------------

(defun %build-circ-to (exit relays)
  "3-hop circuit guard|middle|EXIT (a chosen, ntor-keyed relay)."
  (let* ((guard (dir:enrich-relay (dir:pick-relay :flag "Guard" :relays relays)))
         (middle (loop for m = (dir:pick-relay :relays relays)
                       until (and (not (equalp (dir:relay-rsa-id m) (dir:relay-rsa-id guard)))
                                  (not (equalp (dir:relay-rsa-id m) (dir:relay-rsa-id exit))))
                       finally (return (dir:enrich-relay m))))
         (lk (link:connect-link guard)))
    (handler-case (circ:build-circuit lk middle exit)
      (error (e) (ignore-errors (link:close-link lk)) (error e)))))

;;; --- hs-ntor (client) -------------------------------------------------------

(defun hs-ntor-client (enc-key-b auth-key subcred)
  "Client hs-ntor for INTRODUCE1 encryption.  ENC-KEY-B = service ntor enc key,
   AUTH-KEY = intro auth key, SUBCRED = subcredential.  Returns
   (values X ENC_KEY MAC_KEY x) where X is the client ephemeral pubkey."
  (multiple-value-bind (x xpub) (c:gen-x25519)
    (let* ((exp-bx (c:x25519 x enc-key-b))
           (protoid (u:ascii->bytes *hs-ntor-protoid*))
           (secret-input (u:cat exp-bx auth-key xpub enc-key-b protoid))
           (t-hsenc (u:ascii->bytes (concatenate 'string *hs-ntor-protoid* ":hs_key_extract")))
           (info (u:cat (u:ascii->bytes (concatenate 'string *hs-ntor-protoid* ":hs_key_expand"))
                        subcred))
           (keys (ed:shake256 (u:cat secret-input t-hsenc info) 64)))
      (values xpub (subseq keys 0 32) (subseq keys 32 64) x))))

;;; --- INTRODUCE1 -------------------------------------------------------------

(defun %build-introduce1 (auth-key rendezvous-cookie rp-ntor-key rp-link-specs enc-key-b subcred)
  "Assemble the INTRODUCE1 cell body.  Returns (values cell-bytes X x) so H5 can finish
   the client<->service handshake."
  (multiple-value-bind (xpub enc-key mac-key x) (hs-ntor-client enc-key-b auth-key subcred)
    (let* ((plaintext (u:cat rendezvous-cookie
                             (vector 0)                       ; N_EXTENSIONS
                             (vector 1) (u:u16be 32) rp-ntor-key   ; ONION_KEY: ntor, 32
                             rp-link-specs))                  ; NSPEC + rendezvous link specs
           (ct (c:ctr-apply (c:aes128-ctr-cipher enc-key (u:octets 16)) plaintext))  ; AES-256-CTR IV=0
           (head (u:cat (u:octets 20)                         ; LEGACY_KEY_ID = 20 zeros
                        (vector 2) (u:u16be 32) auth-key       ; AUTH_KEY ed25519
                        (vector 0)                             ; N_EXTENSIONS
                        xpub ct))                              ; ENCRYPTED = CLIENT_PK | DATA
           (mac (c:sha3-256 (u:cat (%int8be 32) mac-key head))))
      (values (u:cat head mac) xpub x))))

;;; --- driver -----------------------------------------------------------------

(defun introduce (intro-point subcred relays)
  "Establish a rendezvous point, then send INTRODUCE1 for INTRO-POINT.  Returns a plist
   with :status (INTRODUCE_ACK status, 0 = success), and — for H5 — :rend-circ,
   :cookie, :x, :xpub, :auth-key, :enc-key so the rendezvous handshake can complete."
  (let* ((rp (dir:enrich-relay (dir:pick-relay :flag "Fast" :relays relays)))
         (rp-link-specs (%relay-link-specs rp))
         (cookie (c:random-bytes 20))
         (rend-circ (%build-circ-to rp relays)))
    ;; ESTABLISH_RENDEZVOUS on the rendezvous circuit
    (circ:send-relay rend-circ +r-establish-rendezvous+ 0 cookie)
    (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay rend-circ)
            (declare (ignore hop rsid len data))
            (when (= rcmd +r-rendezvous-established+) (return))))
    ;; INTRODUCE1 via a separate circuit to the intro point
    (let ((intro-circ (%build-circ-to (%intro-relay intro-point) relays)))
      (multiple-value-bind (cell xpub x)
          (%build-introduce1 (desc:intro-point-auth-key intro-point) cookie
                             (dir:relay-ntor-key rp) rp-link-specs
                             (desc:intro-point-enc-key intro-point) subcred)
        (circ:send-relay intro-circ +r-introduce1+ 0 cell)
        (let ((status
                (loop (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay intro-circ)
                        (declare (ignore hop rsid len))
                        (when (= rcmd +r-introduce-ack+)
                          (return (logior (ash (aref data 0) 8) (aref data 1))))))))
          (ignore-errors (circ:destroy-circuit intro-circ))
          (ignore-errors (link:close-link (circ:circuit-link intro-circ)))
          (list :status status :rend-circ rend-circ :cookie cookie
                :x x :xpub xpub
                :auth-key (desc:intro-point-auth-key intro-point)
                :enc-key (desc:intro-point-enc-key intro-point)))))))
