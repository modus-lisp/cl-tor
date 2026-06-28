;;;; src/circuit.lisp — circuit construction (tor-spec §5) over a link.
;;;;
;;;; CREATE2 builds the first hop (the guard) with ntor; EXTEND2 (a RELAY_EARLY
;;;; cell carrying link specifiers + an ntor onion-skin, addressed to the current
;;;; last hop) telescopes the circuit outward one hop at a time.  Forward relay
;;;; cells are onion-encrypted with every hop's Kf (innermost = target); backward
;;;; cells are peeled hop by hop until one recognizes them.

(in-package #:cl-tor.circuit)

(defstruct (circuit (:constructor %make-circuit)) link id (hops '()))

(defun circuit-length (circ) (length (circuit-hops circ)))
(defun %stream (circ) (link:link-stream (circuit-link circ)))

;;; ---- CREATE2 (first hop) ------------------------------------------------

(defun %ntor-create2-payload (skin)
  (u:cat (u:u16be 2) (u:u16be (length skin)) skin))   ; HTYPE=2 (ntor), HLEN, HDATA

(defun create-circuit (link)
  "Open a circuit on LINK with a CREATE2 ntor handshake to the link's relay
(the guard).  Returns a CIRCUIT with one hop."
  (let* ((guard (link:link-relay link))
         (circ-id (logior #x80000000 (random #x7fffffff)))  ; v4 initiator: high bit set
         (circ (%make-circuit :link link :id circ-id)))
    (multiple-value-bind (skin state) (n:client-create (dir:relay-ntor-key guard)
                                                       (dir:relay-rsa-id guard))
      (cell:write-cell (%stream circ) 4 circ-id cell:+create2+ (%ntor-create2-payload skin))
      (multiple-value-bind (cid cmd payload) (cell:read-cell (%stream circ) 4)
        (declare (ignore cid))
        (unless (= cmd cell:+created2+)
          (error "create: expected CREATED2, got cmd ~d" cmd))
        (let* ((hlen (u:read-u16be payload 0))
               (hdata (u:subv payload 2 (+ 2 hlen)))
               (keys (n:client-finish state hdata)))
          (unless keys (error "create: ntor AUTH failed for guard"))
          (setf (circuit-hops circ) (list (rc:make-hop guard keys)))
          circ)))))

;;; ---- relay cell send / recv ---------------------------------------------

(defun send-relay (circ relay-cmd stream-id data &key early (target (1- (circuit-length circ))))
  "Onion-encrypt a relay cell to hop TARGET and send it (RELAY_EARLY if EARLY)."
  (let* ((hops (circuit-hops circ))
         (body (rc:build-relay-body (nth target hops) relay-cmd stream-id data)))
    (loop for i from target downto 0
          do (setf body (c:ctr-apply (rc:hop-kf (nth i hops)) body)))
    (cell:write-cell (%stream circ) 4 (circuit-id circ)
                     (if early cell:+relay-early+ cell:+relay+) body)))

(defun recv-relay (circ)
  "Read cells until one decrypts to a recognized relay cell.  Returns
(values hop-index relay-cmd stream-id length data).  Signals on DESTROY."
  (let ((hops (circuit-hops circ)))
    (loop
      (multiple-value-bind (cid cmd payload) (cell:read-cell (%stream circ) 4)
        (declare (ignore cid))
        (cond
          ((= cmd cell:+destroy+)
           (error "circuit destroyed by relay (reason ~d)" (aref payload 0)))
          ((or (= cmd cell:+relay+) (= cmd cell:+relay-early+))
           (let ((body payload))
             (loop for i from 0 below (length hops)
                   do (setf body (c:ctr-apply (rc:hop-kb (nth i hops)) body))
                      (when (rc:recognized-and-valid (nth i hops) body)
                        (multiple-value-bind (rcmd recognized sid len rdata)
                            (rc:parse-relay-body body)
                          (declare (ignore recognized))
                          (return-from recv-relay (values i rcmd sid len rdata)))))
             (error "relay cell not recognized by any hop")))
          (t nil))))))                          ; ignore PADDING etc.

;;; ---- EXTEND2 (subsequent hops) ------------------------------------------

(defun %link-specs (relay)
  "EXTEND2 link specifiers for RELAY: IPv4, legacy RSA id, Ed25519 id."
  (u:cat (u:u8 3)                                        ; NSPEC = 3
         (u:u8 0) (u:u8 6) (u:ipv4->bytes (dir:relay-ip relay)) (u:u16be (dir:relay-or-port relay))
         (u:u8 2) (u:u8 20) (dir:relay-rsa-id relay)
         (u:u8 3) (u:u8 32) (dir:relay-ed-id relay)))

(defun extend-circuit (circ relay)
  "Extend CIRC by one hop to RELAY via EXTEND2/EXTENDED2 ntor."
  (multiple-value-bind (skin state) (n:client-create (dir:relay-ntor-key relay)
                                                     (dir:relay-rsa-id relay))
    (let ((payload (u:cat (%link-specs relay) (u:u16be 2) (u:u16be (length skin)) skin)))
      (send-relay circ rc:+r-extend2+ 0 payload :early t))   ; addressed to current last hop
    (multiple-value-bind (hop rcmd sid len data) (recv-relay circ)
      (declare (ignore hop sid len))
      (unless (= rcmd rc:+r-extended2+)
        (error "extend: expected EXTENDED2, got relay cmd ~d" rcmd))
      (let* ((hlen (u:read-u16be data 0))
             (hdata (u:subv data 2 (+ 2 hlen)))
             (keys (n:client-finish state hdata)))
        (unless keys (error "extend: ntor AUTH failed for ~a" (dir:relay-nickname relay)))
        (setf (circuit-hops circ) (append (circuit-hops circ) (list (rc:make-hop relay keys))))
        circ))))

;;; ---- whole-path build ---------------------------------------------------

(defun build-circuit (link middle exit)
  "Build a 3-hop circuit: LINK's relay as guard, then MIDDLE, then EXIT."
  (let ((circ (create-circuit link)))
    (extend-circuit circ middle)
    (extend-circuit circ exit)
    circ))

(defun destroy-circuit (circ &optional (reason 0))
  (ignore-errors
   (cell:write-cell (%stream circ) 4 (circuit-id circ) cell:+destroy+ (u:u8 reason)))
  circ)
