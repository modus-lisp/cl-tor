;;;; src/socks-client.lisp — a minimal SOCKS5 CONNECT client.
;;;;
;;;; Dials HOST:PORT through an external SOCKS5 proxy and returns the proxy socket's
;;;; binary stream (already a fine binary stream — no gray wrapper needed).  This is
;;;; the "-proxy" model: point it at a system tor daemon (127.0.0.1:9050), any SOCKS5
;;;; proxy, or cl-tor's own run-proxy.  The hostname is sent to the proxy (atyp 3) so
;;;; DNS is resolved proxy-side — no local DNS leak.

(defpackage #:cl-transport.socks
  (:use #:cl)
  (:local-nicknames (#:u #:cl-tor.util))
  (:export #:socks5-connect))

(in-package #:cl-transport.socks)

(defun %read-n (s n)
  (let ((b (make-array n :element-type '(unsigned-byte 8))))
    (unless (= (read-sequence b s) n) (error "socks5: short read"))
    b))

(defun socks5-connect (host port &key (proxy-host "127.0.0.1") (proxy-port 9050)
                                      (timeout 20))
  "CONNECT to HOST:PORT via the SOCKS5 proxy at PROXY-HOST:PROXY-PORT.  Returns
   (values stream closer): a binary stream and a thunk that tears the connection down."
  (let* ((sock (usocket:socket-connect proxy-host proxy-port
                                       :element-type '(unsigned-byte 8) :timeout timeout))
         (s (usocket:socket-stream sock)))
    (handler-case
        (progn
          ;; greeting: version 5, one method, no-auth (0x00)
          (write-sequence (u:cat (u:u8 5) (u:u8 1) (u:u8 0)) s) (force-output s)
          (let ((reply (%read-n s 2)))
            (unless (and (= (aref reply 0) 5) (= (aref reply 1) 0))
              (error "socks5: proxy rejected no-auth (~a)" reply)))
          ;; CONNECT request, atyp 3 (domain name) so the proxy resolves it
          (let ((hb (u:ascii->bytes host)))
            (when (> (length hb) 255) (error "socks5: hostname too long"))
            (write-sequence (u:cat (u:u8 5) (u:u8 1) (u:u8 0) (u:u8 3)
                                   (u:u8 (length hb)) hb (u:u16be port)) s)
            (force-output s))
          ;; reply: ver, rep(0=ok), rsv, atyp, bnd.addr, bnd.port
          (let* ((hdr (%read-n s 4)) (rep (aref hdr 1)) (atyp (aref hdr 3)))
            (unless (= rep 0) (error "socks5: CONNECT failed (rep ~d)" rep))
            (%read-n s (ecase atyp (1 4) (4 16)
                         (3 (aref (%read-n s 1) 0))))   ; bound addr
            (%read-n s 2))                                ; bound port
          (values s (lambda () (ignore-errors (usocket:socket-close sock)))))
      (serious-condition (e)
        (ignore-errors (usocket:socket-close sock))
        (error e)))))
