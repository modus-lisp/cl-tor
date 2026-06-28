;;;; src/stream.lisp — Tor streams over a circuit (tor-spec §6.2).
;;;;
;;;; A stream is a TCP connection opened at the exit via RELAY_BEGIN; the exit
;;;; replies RELAY_CONNECTED (or RELAY_END on failure).  Data flows in RELAY_DATA
;;;; cells (<= 498 bytes each).  Flow control (SENDME) is not yet implemented, so
;;;; a single stream is bounded to ~1000 inbound cells (~500 KB) before it would
;;;; stall — fine for interactive/small fetches; see P6.

(in-package #:cl-tor.stream)

(defconstant +max-data+ 498)

(defun begin-stream (circ host port &key (sid 1))
  "Open a stream to HOST:PORT at the circuit's exit.  Returns the stream id, or
signals if the exit refuses.  HOST may be a name (resolved at the exit — no local
DNS leak) or an address string."
  (let ((payload (u:cat (u:ascii->bytes (format nil "~a:~d" host port))
                        (u:u8 0)            ; NUL terminator
                        (u:u32be 0))))      ; flags
    (circ:send-relay circ rc:+r-begin+ sid payload))
  (loop
    (multiple-value-bind (hop rcmd rsid len data) (circ:recv-relay circ)
      (declare (ignore hop len data))
      (cond
        ((and (= rcmd rc:+r-connected+) (= rsid sid)) (return sid))
        ((and (= rcmd rc:+r-end+) (= rsid sid)) (error "stream refused by exit (RELAY_END)"))
        (t nil)))))                          ; ignore unrelated cells (e.g. SENDME)

(defun send-stream-data (circ sid data)
  "Send DATA on stream SID, fragmented into RELAY_DATA cells."
  (loop for off from 0 below (max 1 (length data)) by +max-data+
        do (circ:send-relay circ rc:+r-data+ sid
                            (u:subv data off (min (length data) (+ off +max-data+))))))

(defun end-stream (circ sid &optional (reason 6))   ; 6 = REASON_DONE
  (ignore-errors (circ:send-relay circ rc:+r-end+ sid (u:u8 reason))))
