;;;; bin/cl-tor.lisp — run the SOCKS5 proxy.
;;;;
;;;;   sbcl --load bin/cl-tor.lisp [port]
;;;;
;;;; Then point any program at it, e.g.:
;;;;   curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
;;;;
;;;; Each connection builds its own fresh 3-hop circuit from the live consensus.

(require :asdf)
(pushnew (uiop:pathname-parent-directory-pathname
          (uiop:pathname-directory-pathname (or *load-truename* *compile-file-truename*)))
         asdf:*central-registry* :test #'equal)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system "cl-tor"))

(in-package #:cl-tor.socks)

(let ((port (if (second sb-ext:*posix-argv*)
                (parse-integer (second sb-ext:*posix-argv*))
                9050)))
  (run-proxy :port port))
