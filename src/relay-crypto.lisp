;;;; src/relay-crypto.lisp — per-hop relay-cell onion crypto (tor-spec §6).
;;;;
;;;; Each hop holds four pieces of stateful crypto derived from its ntor keys:
;;;; forward / backward AES-128-CTR ciphers (Kf/Kb, zero IV) and forward /
;;;; backward SHA-1 running digests (seeded with Df/Db).  A relay cell's 509-byte
;;;; body is:
;;;;   RelayCmd(1) Recognized(2) StreamID(2) Digest(4) Length(2) Data(498) pad
;;;; The originator zeroes Recognized+Digest, runs the cell through the target
;;;; hop's running digest, and writes the first 4 bytes into Digest.  A hop "owns"
;;;; a received cell when, after its CTR layer is peeled, Recognized==0 and the
;;;; recomputed digest matches — both ciphers and digests advance one step per
;;;; cell, which keeps client and relay keystreams in lockstep.

(in-package #:cl-tor.relay-crypto)

(defconstant +r-begin+     1)
(defconstant +r-data+      2)
(defconstant +r-end+       3)
(defconstant +r-connected+ 4)
(defconstant +r-sendme+    5)
(defconstant +r-extend2+   14)
(defconstant +r-extended2+ 15)
(defconstant +r-drop+      10)
(defconstant +r-resolve+   11)
(defconstant +r-resolved+  12)

(defconstant +body-len+ 509)

(defstruct (hop (:constructor %make-hop)) relay kf kb df db)

(defun %seeded-sha1 (seed)
  (let ((d (ironclad:make-digest :sha1))) (ironclad:update-digest d seed) d))

(defun make-hop (relay keys)
  "Build a HOP's crypto state from its ntor CIRCUIT-KEYS."
  (%make-hop :relay relay
             :kf (c:aes128-ctr-cipher (n:circuit-keys-kf keys))
             :kb (c:aes128-ctr-cipher (n:circuit-keys-kb keys))
             :df (%seeded-sha1 (n:circuit-keys-df keys))
             :db (%seeded-sha1 (n:circuit-keys-db keys))))

(defun %seeded-sha3-256 (seed)
  (let ((d (ironclad:make-digest :sha3/256))) (ironclad:update-digest d seed) d))

(defun make-hs-hop (relay kf kb df db)
  "Build a v3 rendezvous (client<->service) hop: AES-256-CTR ciphers + SHA3-256
running digests, from the raw 32-byte hs-ntor keys.  The cell machinery
(build-relay-body / recognized-and-valid) is digest-agnostic, so it just works."
  (%make-hop :relay relay
             :kf (c:aes128-ctr-cipher kf)     ; 32-byte key -> AES-256-CTR
             :kb (c:aes128-ctr-cipher kb)
             :df (%seeded-sha3-256 df)
             :db (%seeded-sha3-256 db)))

(defun %digest4 (running)
  "First 4 bytes of RUNNING's current value (non-destructive)."
  (subseq (ironclad:produce-digest (ironclad:copy-digest running)) 0 4))

(defun build-relay-body (hop relay-cmd stream-id data)
  "Construct the 509-byte relay body destined for HOP, with the forward digest
filled in (advances HOP's forward running digest)."
  (let ((body (u:octets +body-len+)))
    (setf (aref body 0) relay-cmd)               ; recognized [1..2] stays 0
    (u:put-u16be body 3 stream-id)               ; digest [5..8] stays 0 for hashing
    (u:put-u16be body 9 (length data))
    (replace body data :start1 11)
    (ironclad:update-digest (hop-df hop) body)   ; digest over body with zero Digest field
    (replace body (%digest4 (hop-df hop)) :start1 5)
    body))

(defun parse-relay-body (body)
  "-> (values relay-cmd recognized stream-id length data)."
  (let ((len (u:read-u16be body 9)))
    (values (aref body 0) (u:read-u16be body 1) (u:read-u16be body 3)
            len (u:subv body 11 (+ 11 len)))))

(defun hop-recv-digest (hop)
  "The full 20-byte backward rolling digest of HOP after the last recognized cell
(used as the authenticator in circuit-level v1 SENDMEs)."
  (ironclad:produce-digest (ironclad:copy-digest (hop-db hop))))

(defun recognized-and-valid (hop body)
  "T iff BODY (already CTR-decrypted for HOP) is recognized at HOP: Recognized==0
and the backward running digest matches.  Commits HOP's backward digest on match."
  (when (zerop (u:read-u16be body 1))                ; Recognized field == 0
    (let ((claimed (u:subv body 5 9))
          (probe (ironclad:copy-digest (hop-db hop)))
          (b0 (copy-seq body)))
      (fill b0 0 :start 5 :end 9)                     ; zero Digest field for hashing
      (ironclad:update-digest probe b0)
      (when (u:bytes= (%digest4 probe) claimed)
        (setf (hop-db hop) probe)                     ; commit the advanced state
        t))))
