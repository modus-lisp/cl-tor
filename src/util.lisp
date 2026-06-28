;;;; src/util.lisp — bytes, hex, and big-endian framing helpers.

(in-package #:cl-tor.util)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun octets (n &key (initial-element 0))
  (make-array n :element-type '(unsigned-byte 8) :initial-element initial-element))

(defun cat (&rest seqs)
  "Concatenate byte sequences into one (unsigned-byte 8) vector."
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
         (mapcar (lambda (s) (coerce s '(simple-array (unsigned-byte 8) (*)))) seqs)))

(defun subv (v start &optional end)
  "Subseq as a fresh (unsigned-byte 8) vector."
  (coerce (subseq v start end) '(simple-array (unsigned-byte 8) (*))))

(defun bytes= (a b)
  "Constant-time-ish equality for byte vectors (length-leaking, value-safe)."
  (and (= (length a) (length b))
       (let ((d 0))
         (dotimes (i (length a) (zerop d))
           (setf d (logior d (logxor (aref a i) (aref b i))))))))

(defun bytes->hex (bytes)
  (let ((s (make-string (* 2 (length bytes)))))
    (loop for b across bytes for i from 0 by 2
          do (setf (char s i) (digit-char (ldb (byte 4 4) b) 16)
                   (char s (1+ i)) (digit-char (ldb (byte 4 0) b) 16)))
    (string-downcase s)))

(defun hex->bytes (hex)
  (let ((out (octets (floor (length hex) 2))))
    (loop for i from 0 below (* 2 (length out)) by 2 for j from 0
          do (setf (aref out j) (logior (ash (digit-char-p (char hex i) 16) 4)
                                        (digit-char-p (char hex (1+ i)) 16))))
    out))

(defun ascii->bytes (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

;;; ---- big-endian integer framing (Tor cells are big-endian) --------------

(defun u8  (n) (octets 1 :initial-element (logand n #xff)))
(defun u16be (n) (let ((b (octets 2))) (setf (aref b 0) (ldb (byte 8 8) n)
                                             (aref b 1) (ldb (byte 8 0) n)) b))
(defun u32be (n) (let ((b (octets 4)))
                   (dotimes (i 4 b) (setf (aref b i) (ldb (byte 8 (* 8 (- 3 i))) n)))))

(defun put-u8 (vec pos n) (setf (aref vec pos) (logand n #xff)) (1+ pos))
(defun put-u16be (vec pos n)
  (setf (aref vec pos) (ldb (byte 8 8) n) (aref vec (1+ pos)) (ldb (byte 8 0) n))
  (+ pos 2))
(defun put-u32be (vec pos n)
  (dotimes (i 4) (setf (aref vec (+ pos i)) (ldb (byte 8 (* 8 (- 3 i))) n)))
  (+ pos 4))

(defun read-u16be (vec pos) (logior (ash (aref vec pos) 8) (aref vec (1+ pos))))
(defun read-u32be (vec pos)
  (let ((n 0)) (dotimes (i 4 n) (setf n (logior (ash n 8) (aref vec (+ pos i)))))))
