#!/bin/sh
# Run the planted one-past-the-end read both ways. See the Makefile.
#
# Prints "caught N, missed M" and fails unless the exact-size build is
# caught and the padded build is not. Both halves matter: a target where
# the planted read is always caught says nothing about whether the
# buffers are the right size, because it would also pass if the bounds
# check were nowhere near the data.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
EXACT=$ROOT/target/overread/release/sshkeyv
SLACK=$ROOT/target/slack/release/sshkeyv

for b in "$EXACT" "$SLACK"; do
    [ -x "$b" ] || { echo "overread: $b was not built" >&2; exit 2; }
done

W=$(mktemp -d "${TMPDIR:-/tmp}/sshkeyv.overread.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM
ssh-keygen -q -t ed25519 -N '' -C overread -f "$W/k" || exit 2

caught=0
missed=0

"$EXACT" fields "$W/k.pub" >/dev/null 2>"$W/err.exact"
rc=$?
if [ "$rc" -eq 134 ]; then
    caught=$((caught+1))
    echo "exact-size buffers: the planted read aborts, exit 134"
    grep -m1 panicked "$W/err.exact" | sed 's/^/    /'
else
    echo "FAIL exact-size buffers: exit $rc, wanted 134 (SIGABRT)"
    cat "$W/err.exact" | sed 's/^/    /'
fi

"$SLACK" fields "$W/k.pub" >/dev/null 2>"$W/err.slack"
rc=$?
if [ "$rc" -eq 134 ]; then
    echo "FAIL padded buffers: the planted read was caught, so this build"
    echo "     is not demonstrating the blind spot it exists to show"
else
    missed=$((missed+1))
    echo "padded buffers: the same read is NOT caught, exit $rc"
    sed -n '1p' "$W/err.slack" | sed 's/^/    /'
fi

echo "caught $caught, missed $missed"
[ "$caught" -eq 1 ] && [ "$missed" -eq 1 ]
