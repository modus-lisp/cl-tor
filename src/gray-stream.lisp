;;;; src/gray-stream.lisp — a binary Gray stream over a single Tor circuit stream.
;;;;
;;;; This is the bridge that makes a Tor exit stream look like an ordinary binary
;;;; socket stream to callers (read-sequence/read-byte/write-sequence/force-output/
;;;; close), so e.g. cl-consensus's peer read loop can run over Tor unchanged.  Part
;;;; of the cl-tor-transport provider (not the core Tor client).
;;;;
;;;; One circuit carries one stream (a fresh circuit per connection — the SOCKS
;;;; server's model).  There is NO READER THREAD: a read that finds nothing buffered
;;;; reads relay cells itself (RECV-RELAY), on the caller's thread, until data or
;;;; RELAY_END arrives -- like reading a socket.  So the circuit is advanced only by
;;;; the thread using the stream, which is what modus needs (a thread there may not
;;;; store its objects into another thread's, and a reader thread's cells would be
;;;; just that) and is no different on SBCL.  One thread may read while another
;;;; writes, as before: the TLS link tolerates one reader and one writer.  Uses
;;;; sb-gray; the method set is the portable Gray-streams contract.

(defpackage #:cl-tor.gray-stream
  (:use #:cl)
  (:local-nicknames (#:circ #:cl-tor.circuit) (#:strm #:cl-tor.stream)
                    (#:rc #:cl-tor.relay-crypto) (#:link #:cl-tor.link))
  (:export #:tor-stream #:make-tor-stream #:tor-stream-circuit))

(in-package #:cl-tor.gray-stream)

(defclass tor-stream (sb-gray:fundamental-binary-input-stream
                      sb-gray:fundamental-binary-output-stream)
  ((circuit :initarg :circuit :reader tor-stream-circuit)
   (sid     :initarg :sid     :reader tor-stream-sid)
   (chunks  :initform '())    ; FIFO of (unsigned-byte 8) vectors not yet consumed
   (head    :initform 0)      ; consumed offset into (first chunks)
   (eof     :initform nil)    ; far end sent RELAY_END (or the circuit failed)
   (closed  :initform nil)))

(defun %read-cell (s)
  "Read one relay cell from S's circuit (waiting for it) and file what it carries."
  (with-slots (circuit sid chunks eof) s
    (handler-case
        (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circuit)
          (declare (ignore hop len))
          (cond
            ((and (= rcmd rc:+r-data+) (or (null rsid) (= rsid sid)))
             (setf chunks (nconc chunks (list data))))
            ((and (= rcmd rc:+r-end+) (eql rsid sid))
             (setf eof t))))
      (serious-condition (e)
        (format *error-output* "~&[tor-stream: read failed: ~a]~%" e)
        (setf eof t)))))

(defun make-tor-stream (circuit sid)
  "Wrap an already-open circuit stream (SID on CIRCUIT, past RELAY_CONNECTED) as a
   TOR-STREAM.  Reads advance the circuit on the reading thread; there is no reader thread."
  (make-instance 'tor-stream :circuit circuit :sid sid))

;;; --- input ------------------------------------------------------------------

(defun %wait-readable (s)
  "Read cells until a chunk is available or EOF; T if there is data to read, NIL at EOF."
  (with-slots (chunks eof closed) s
    (loop while (and (null chunks) (not eof) (not closed))
          do (%read-cell s))
    (and chunks t)))

(defmethod sb-gray:stream-listen ((s tor-stream))
  (with-slots (circuit chunks eof closed) s
    (loop while (and (null chunks) (not eof) (not closed)
                     (let ((tls (link:link-stream (circ:circuit-link circuit))))
                       (and (typep tls 'seal:tls-stream) (seal:tls-stream-pending-p tls))))
          do (%read-cell s))
    (and chunks t)))

(defmethod sb-gray:stream-read-byte ((s tor-stream))
  (with-slots (chunks head) s
    (if (not (%wait-readable s))
        :eof
        (let* ((chunk (first chunks)) (b (aref chunk head)))
          (incf head)
          (when (>= head (length chunk)) (pop chunks) (setf head 0))
          b))))

(defmethod sb-gray:stream-read-sequence ((s tor-stream) seq &optional (start 0) end)
  "Socket-like: block until >=1 byte or EOF, then drain what's buffered up to END
   (no waiting for more once some is available).  Returns the next unfilled index."
  (let ((end (or end (length seq))))
    (with-slots (chunks head) s
      (unless (%wait-readable s) (return-from sb-gray:stream-read-sequence start))
      (let ((i start))
        (loop while (and (< i end) chunks) do
          (let* ((chunk (first chunks))
                 (take (min (- (length chunk) head) (- end i))))
            (replace seq chunk :start1 i :start2 head :end2 (+ head take))
            (incf i take) (incf head take)
            (when (>= head (length chunk)) (pop chunks) (setf head 0))))
        i))))

;;; --- output -----------------------------------------------------------------

(defmethod sb-gray:stream-write-byte ((s tor-stream) b)
  (strm:send-stream-data (tor-stream-circuit s) (tor-stream-sid s)
                         (make-array 1 :element-type '(unsigned-byte 8) :initial-element b))
  b)

(defmethod sb-gray:stream-write-sequence ((s tor-stream) seq &optional (start 0) end)
  (let* ((end (or end (length seq)))
         (bytes (if (and (typep seq '(simple-array (unsigned-byte 8) (*)))
                         (= start 0) (= end (length seq)))
                    seq
                    (subseq seq start end))))
    (strm:send-stream-data (tor-stream-circuit s) (tor-stream-sid s) bytes)
    seq))

(defmethod sb-gray:stream-force-output ((s tor-stream)) nil)   ; DATA cells sent eagerly
(defmethod sb-gray:stream-finish-output ((s tor-stream)) nil)
(defmethod stream-element-type ((s tor-stream)) '(unsigned-byte 8))

(defmethod close ((s tor-stream) &key abort)
  (declare (ignore abort))
  (with-slots (circuit sid closed) s
    (unless closed
      (setf closed t)
      (ignore-errors (strm:end-stream circuit sid))
      (ignore-errors (circ:destroy-circuit circuit))
      (ignore-errors (link:close-link (circ:circuit-link circuit))))
    t))
