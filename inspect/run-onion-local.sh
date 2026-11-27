#!/usr/bin/env bash
# inspect/run-onion-local.sh [sbcl|modus] -- inspect/onion-local-test.lisp against a fake Tor
# network (inspect/fake-tor-net.lisp, always on SBCL) on 127.0.0.1.  MODUS names the modus
# binary (default: modus on PATH).  Nothing listens after it returns.
set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
who=${1:-sbcl}
work=$(mktemp -d "${TMPDIR:-/tmp}/cl-tor-onion.XXXXXX")
# This tree and the one above it (seal, cl-transport, bobbin ... are sibling repos), unless
# the caller set a registry.
export CL_SOURCE_REGISTRY=${CL_SOURCE_REGISTRY:-"(:source-registry (:tree \"$here\") (:tree \"$here/..\") :inherit-configuration)"}
export HOME="$work/home"; mkdir -p "$HOME"          # the guard set is per run
portfile="$work/ports"
sbcl --script "$here/inspect/fake-tor-net.lisp" "$portfile" 3600 > "$work/fake.log" 2>&1 &
fake=$!
for i in $(seq 1 600); do [ -s "$portfile" ] && break; sleep 0.2; done
if [ ! -s "$portfile" ]; then echo "the fake network did not start"; cat "$work/fake.log"; kill $fake; exit 2; fi
export FAKE_TOR="$(cat "$portfile")"
cd "$here"
if [ "$who" = modus ]; then
  "${MODUS:-modus}" --script inspect/onion-local-test.lisp; rc=$?
else
  sbcl --script inspect/onion-local-test.lisp; rc=$?
fi
rm -f "$portfile"; wait $fake
[ -n "${KEEP_FAKE_LOG:-}" ] && cat "$work/fake.log"
rm -rf "$work"
exit $rc
