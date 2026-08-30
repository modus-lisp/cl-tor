#!/usr/bin/env sh
# inspect/run-all.sh — the offline gate (no network): X25519/HKDF vectors and the
# ntor handshake (client<->server key agreement + AUTH).
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# This tree AND the one above it: cl-tor/test reaches seal (TLS) and cl-transport,
# which are sibling repos.  Without the second tree the suite only ever worked
# where quicklisp's local-projects happened to have them symlinked -- which is
# every developer machine here, and no runner.
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$here\") (:tree \"$here/..\") :inherit-configuration)"
exec sbcl --non-interactive \
  --eval '(require :asdf)' \
  --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system "cl-tor/test"))' \
  --eval '(uiop:quit (if (ignore-errors (cl-tor.test:run)) 0 1))'
