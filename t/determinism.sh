#!/bin/sh
# Two properties that have no external oracle and still want checking.
#
# Repetition: every command run twice over the same inputs must print the
# same bytes. Rust's HashMap iterates in a different order each run by
# design, so a map anywhere in an output path turns this red; so does
# anything reading uninitialised memory or the clock. The clock-dependent
# command is counts, whose three validity-verdict lines are removed before
# comparing, because those legitimately change at a second boundary and a
# test that fails once an hour is worse than no test.
#
# Cross-container: the same key written three ways, as a key line, an
# RFC 4716 block and a PKCS8 SubjectPublicKeyInfo, must give identical
# fields apart from the comment, which only the key line carries. That is
# a stronger statement than repetition and it is the one that would catch
# a container reader that drops a byte.
#
# Argument: the corpus directory. Prints
# "N commands run twice, M differ; K keys in 3 containers, J differ".
set -u
C=${1:?usage: determinism.sh CORPUSDIR}
BIN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/target/release/sshkeyv
W=$(mktemp -d "${TMPDIR:-/tmp}/sshkeyv.det.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

n=0; differ=0
twice() {
    label=$1; shift
    n=$((n+1))
    "$@" >"$W/a" 2>&1
    "$@" >"$W/b" 2>&1
    if cmp -s "$W/a" "$W/b"; then :; else
        differ=$((differ+1))
        echo "  $label is not deterministic:"
        diff "$W/a" "$W/b" | head -5 | sed 's/^/      /'
    fi
}

set -- "$C"/*.pub
twice "fields"  "$BIN" fields "$@"
twice "fp"      "$BIN" fp "$@"
twice "blob"    "$BIN" blob "$@"
set -- "$C"/*-cert.pub
twice "show"    "$BIN" show "$@"
twice "verify"  "$BIN" verify "$@"
twice "unknown" "$BIN" unknown "$@"
twice "valid"   "$BIN" valid --at 1800000000 --principal alice "$@"
set -- "$C"/*
twice "check"   "$BIN" check "$@"

# counts without the three lines that depend on the wall clock.
n=$((n+1))
"$BIN" counts "$C"/* 2>/dev/null | grep -v '^cert\.valid\.\(now\|expired\|not-yet\)' > "$W/a"
"$BIN" counts "$C"/* 2>/dev/null | grep -v '^cert\.valid\.\(now\|expired\|not-yet\)' > "$W/b"
if cmp -s "$W/a" "$W/b"; then :; else
    differ=$((differ+1))
    echo "  counts is not deterministic"
fi

keys=0; kdiffer=0
for k in ed25519 ecdsa256 ecdsa384 ecdsa521 rsa2048 rsa4096; do
    [ -f "$C/$k.pub" ] || continue
    keys=$((keys+1))
    "$BIN" convert -m rfc4716 "$C/$k.pub" > "$W/k.rfc4716" || continue
    "$BIN" convert -m pkcs8   "$C/$k.pub" > "$W/k.pkcs8"   || continue
    for f in "$C/$k.pub" "$W/k.rfc4716" "$W/k.pkcs8"; do
        # The comment is only in the key line, so it is left out, and so
        # is the path each line starts with.
        "$BIN" fields "$f" | cut -f2,3 \
            | grep -v '^comment' > "$W/$(basename "$f").f"
    done
    a="$W/$(basename "$C/$k.pub").f"
    for f in "$W/k.rfc4716.f" "$W/k.pkcs8.f"; do
        if cmp -s "$a" "$f"; then :; else
            kdiffer=$((kdiffer+1))
            echo "  $k differs between containers ($(basename "$f")):"
            diff "$a" "$f" | head -6 | sed 's/^/      /'
        fi
    done
done
echo "$n commands run twice, $differ differ; $keys keys in 3 containers, $kdiffer differ"
[ "$differ" -eq 0 ] && [ "$kdiffer" -eq 0 ] && [ "$n" -ge 9 ] && [ "$keys" -ge 6 ]
