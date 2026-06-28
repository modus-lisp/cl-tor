;;;; src/cell.lisp — Tor cell framing (tor-spec §3).
;;;;
;;;; Two shapes on the wire:
;;;;   fixed    : CircID | Command(1) | Payload(509)
;;;;   variable : CircID | Command(1) | Length(2) | Payload(Length)
;;;; CircID is 2 bytes until link version is negotiated, then 4 bytes for v4+.
;;;; VERSIONS (cmd 7) and every command >= 128 are variable-length; the rest are
;;;; fixed.  Fixed payload is always 509 bytes (CELL_PAYLOAD_LEN), zero-padded.

(in-package #:cl-tor.cell)

(defconstant +padding+        0)
(defconstant +destroy+        4)
(defconstant +versions+       7)
(defconstant +netinfo+        8)
(defconstant +relay-early+    9)
(defconstant +create2+        10)
(defconstant +created2+       11)
(defconstant +relay+          3)
(defconstant +vpadding+       128)
(defconstant +certs+          129)
(defconstant +auth-challenge+ 130)

(defconstant +payload-len+ 509)

(defun variable-cell-p (cmd) (or (= cmd +versions+) (>= cmd 128)))

(defun read-bytes (stream n)
  "Read exactly N bytes from STREAM into a fresh vector, or error on EOF."
  (let ((buf (u:octets n)) (off 0))
    (loop while (< off n)
          for got = (read-sequence buf stream :start off)
          do (when (= got off) (error "cell: unexpected EOF (~d/~d)" off n))
             (setf off got))
    buf))

(defun read-cell (stream circid-len)
  "Read one cell.  Returns (values circ-id command payload)."
  (let* ((cidb (read-bytes stream circid-len))
         (circ-id (if (= circid-len 2) (u:read-u16be cidb 0) (u:read-u32be cidb 0)))
         (cmd (aref (read-bytes stream 1) 0)))
    (if (variable-cell-p cmd)
        (let ((len (u:read-u16be (read-bytes stream 2) 0)))
          (values circ-id cmd (read-bytes stream len)))
        (values circ-id cmd (read-bytes stream +payload-len+)))))

(defun write-cell (stream circid-len circ-id cmd payload)
  "Write one cell.  PAYLOAD is sent verbatim for variable cells, or zero-padded
to 509 bytes for fixed cells.  Flushes the stream."
  (let ((cid (if (= circid-len 2) (u:u16be circ-id) (u:u32be circ-id))))
    (write-sequence cid stream)
    (write-sequence (u:u8 cmd) stream)
    (if (variable-cell-p cmd)
        (progn (write-sequence (u:u16be (length payload)) stream)
               (write-sequence payload stream))
        (let ((body (u:octets +payload-len+)))
          (replace body payload :end1 (min +payload-len+ (length payload)))
          (write-sequence body stream))))
  (force-output stream))
