#!/bin/sh
# Build the tree twice, in two directories with different names and under
# a different clock, timezone, locale, umask and make parallelism, and
# require the binaries to be byte identical.
#
# Varying the PATH is the part that matters. Two builds in the same
# directory match even when a build is hopelessly unreproducible, so a
# check that does not move the tree proves nothing. The directory names
# here are deliberately different lengths, because a path that is baked
# in as a fixed-size field can match when the two paths are the same
# length and differ when they are not.
#
# Only the source is copied, not target/, so each build starts cold.
#
# Prints "built twice, identical" or names what differs.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
W=$(mktemp -d "${TMPDIR:-/tmp}/sshkeyv.repro.XXXXXX") || exit 2
trap 'rm -rf "$W"' EXIT INT TERM

a=$W/a
b=$W/b-a-rather-longer-directory-name-than-the-first-one
for d in "$a" "$b"; do
    mkdir -p "$d/src" "$d/t"
    cp "$ROOT"/Cargo.toml "$ROOT"/Cargo.lock "$ROOT"/Makefile "$d/"
    cp "$ROOT"/src/*.rs "$d/src/"
done

( cd "$a" && TZ=UTC LC_ALL=C umask 022 && make all -j1 >/dev/null 2>&1 )
ra=$?
( cd "$b" && TZ=Asia/Tokyo LC_ALL=en_US.utf8 umask 077 \
  && SOURCE_DATE_EPOCH=1234567890 make all -j4 >/dev/null 2>&1 )
rb=$?
if [ "$ra" -ne 0 ] || [ "$rb" -ne 0 ]; then
    echo "a build failed: $ra and $rb"
    exit 1
fi
A=$a/target/release/sshkeyv
B=$b/target/release/sshkeyv
if [ ! -x "$A" ] || [ ! -x "$B" ]; then
    echo "a binary is missing"
    exit 1
fi
if cmp -s "$A" "$B"; then
    echo "built twice, identical ($(wc -c < "$A") bytes)"
    exit 0
fi
echo "the two binaries differ:"
cmp -l "$A" "$B" | head -5 | sed 's/^/    /'
# Name the mechanism if it is the obvious one.
if strings "$B" | grep -q "a-rather-longer-directory-name"; then
    echo "    the build directory is embedded in the binary"
fi
exit 1
