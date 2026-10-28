#!/usr/bin/env bash
# verifier-consigne.sh — verify-exhibits.sh with its messages in French: the
# same checks, by the same script, so that the two cannot drift apart.
# Usage: bash verifier-consigne.sh [--seal=<SHA-256>] /media/usb/output
# Exit code: 0 if everything matches, 1 otherwise.
exec bash "$(dirname "$0")/verify-exhibits.sh" --language=fr "$@"
