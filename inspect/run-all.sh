#!/usr/bin/env sh
# inspect/run-all.sh — the offline gate (no network): X25519/HKDF vectors and the
# ntor handshake (client<->server key agreement + AUTH).
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export CL_SOURCE_REGISTRY="(:source-registry (:tree \"$here\") :inherit-configuration)"
exec sbcl --non-interactive \
  --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system "cl-tor/test"))' \
  --eval '(uiop:quit (if (ignore-errors (cl-tor.test:run)) 0 1))'
