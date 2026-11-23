#!/usr/bin/env bash
# Compatibility entry point for commands from the original release.
exec bash "$(dirname -- "${BASH_SOURCE[0]}")/seori-replay.sh" "$@"
