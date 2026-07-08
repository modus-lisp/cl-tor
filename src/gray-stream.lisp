;;;; src/gray-stream.lisp — a binary Gray stream over a single Tor circuit stream.
;;;;
;;;; This is the bridge that makes a Tor exit stream look like an ordinary binary
;;;; socket stream to callers (read-sequence/read-byte/write-sequence/force-output/
;;;; close), so e.g. cl-consensus's peer read loop can run over Tor unchanged.  Part
;;;; of the cl-tor-transport provider (not the core Tor client).
;;;;
;;;; One circuit carries one stream (a fresh circuit per connection — the SOCKS
;;;; server's model), so a dedicated reader thread is the sole caller of RECV-RELAY
;;;; and demuxing is trivial.  Concurrency mirrors the proven SOCKS %splice: the
;;;; reader thread reads (RECV-RELAY) while the caller thread writes (SEND-STREAM-
;;;; DATA); the TLS link tolerates one-reader-one-writer.  Uses sb-gray today; the
;;;; method set is the portable Gray-streams contract for the modus port.

(defpackage #:cl-tor.gray-stream
  (:use #:cl)
  (:local-nicknames (#:circ #:cl-tor.circuit) (#:strm #:cl-tor.stream)
                    (#:rc #:cl-tor.relay-crypto) (#:link #:cl-tor.link)
                    (#:bt #:bordeaux-threads))
  (:export #:tor-stream #:make-tor-stream #:tor-stream-circuit))

(in-package #:cl-tor.gray-stream)

(defclass tor-stream (sb-gray:fundamental-binary-input-stream
                      sb-gray:fundamental-binary-output-stream)
  ((circuit :initarg :circuit :reader tor-stream-circuit)
   (sid     :initarg :sid     :reader tor-stream-sid)
   (lock    :initform (bt:make-lock "tor-stream"))
   (cv      :initform (bt:make-condition-variable))
   (chunks  :initform '())    ; FIFO of (unsigned-byte 8) vectors not yet consumed
   (head    :initform 0)      ; consumed offset into (first chunks)
   (eof     :initform nil)    ; far end sent RELAY_END
   (closed  :initform nil)
   (reader  :initform nil)))

(defun %reader-loop (s)
  "Pump inbound relay cells into the byte FIFO until RELAY_END / error / close."
  (with-slots (circuit sid lock cv chunks eof closed) s
    (handler-case
        (loop
          (when closed (return))
          (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circuit)
            (declare (ignore hop len))
            (cond
              ((and (= rcmd rc:+r-data+) (or (null rsid) (= rsid sid)))
               (bt:with-lock-held (lock)
                 (setf chunks (nconc chunks (list data)))
                 (bt:condition-notify cv)))
              ((and (= rcmd rc:+r-end+) (= rsid sid))
               (bt:with-lock-held (lock) (setf eof t) (bt:condition-notify cv))
               (return)))))
      (serious-condition ()
        (bt:with-lock-held (lock) (setf eof t) (bt:condition-notify cv))))))

(defun make-tor-stream (circuit sid)
  "Wrap an already-open circuit stream (SID on CIRCUIT, past RELAY_CONNECTED) as a
   TOR-STREAM and start its reader thread."
  (let ((s (make-instance 'tor-stream :circuit circuit :sid sid)))
    (setf (slot-value s 'reader)
          (bt:make-thread (lambda () (%reader-loop s)) :name "tor-stream reader"))
    s))

;;; --- input ------------------------------------------------------------------

(defun %wait-readable (s)
  "With S's lock held, block until a chunk is available or EOF; return T if there
   is data to read, NIL at EOF."
  (with-slots (lock cv chunks eof closed) s
    (loop while (and (null chunks) (not eof) (not closed))
          do (bt:condition-wait cv lock))
    (and chunks t)))

(defmethod sb-gray:stream-read-byte ((s tor-stream))
  (with-slots (lock chunks head) s
    (bt:with-lock-held (lock)
      (if (not (%wait-readable s))
          :eof
          (let* ((chunk (first chunks)) (b (aref chunk head)))
            (incf head)
            (when (>= head (length chunk)) (pop chunks) (setf head 0))
            b)))))

(defmethod sb-gray:stream-read-sequence ((s tor-stream) seq &optional (start 0) end)
  "Socket-like: block until >=1 byte or EOF, then drain what's buffered up to END
   (no waiting for more once some is available).  Returns the next unfilled index."
  (let ((end (or end (length seq))))
    (with-slots (lock chunks head) s
      (bt:with-lock-held (lock)
        (unless (%wait-readable s) (return-from sb-gray:stream-read-sequence start))
        (let ((i start))
          (loop while (and (< i end) chunks) do
            (let* ((chunk (first chunks))
                   (take (min (- (length chunk) head) (- end i))))
              (replace seq chunk :start1 i :start2 head :end2 (+ head take))
              (incf i take) (incf head take)
              (when (>= head (length chunk)) (pop chunks) (setf head 0))))
          i)))))

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
  (with-slots (circuit sid lock cv closed reader) s
    (bt:with-lock-held (lock) (setf closed t) (bt:condition-notify cv))
    (ignore-errors (strm:end-stream circuit sid))
    ;; unblock the reader (mid RECV-RELAY on the TLS link) by closing the link sock
    (ignore-errors (usocket:socket-close (link:link-sock (circ:circuit-link circuit))))
    (when reader (ignore-errors (bt:join-thread reader)))
    (ignore-errors (circ:destroy-circuit circuit))
    (ignore-errors (link:close-link (circ:circuit-link circuit)))
    t))
