#!/bin/sh
# Wrapper so the compiled C/libcurl sidecar plugs into the SidecarSpec model
# (command=sh, script=this file): it execs the `parse_cookies` binary built next to
# it (by CI / a local `cc` — see matrix.yml), forwarding argv and stdin. If the
# binary is absent (not compiled), the exec fails and the sidecar degrades to SKIP.
exec "$(dirname "$0")/parse_cookies" "$@"
