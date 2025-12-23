#!/bin/sh
# `sshkeyv show` against `ssh-keygen -L -f`, whole output.
#
# This is the one comparison in the suite that is a plain diff rather than
# a field-by-field read, because `show` sets out to reproduce ssh-keygen's
# block exactly: eight and sixteen spaces of indent, the trailing space
# after "Principals:" when the list is not empty, and the UNKNOWN OPTION
# wording from show_options() in ssh-keygen.c.
#
# The oracle runs under TZ=UTC0. ssh-keygen prints validity times in local
# time and sshkeyv prints UTC, which is a deliberate difference recorded in
# the README; without TZ pinned this comparison would pass on a machine in
# UTC and fail everywhere else.
#
# Argument: the corpus directory. Prints
# "N certificates, M identical, K differ".
set -u
C=${1:?usage: showcmp.sh CORPUSDIR}
BIN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/target/release/sshkeyv

n=0; same=0; differ=0
for f in "$C"/*-cert.pub; do
    [ -f "$f" ] || continue
    n=$((n+1))
    a=$("$BIN" show "$f" 2>&1)
    b=$(TZ=UTC0 ssh-keygen -L -f "$f" 2>&1)
    if [ "$a" = "$b" ]; then
        same=$((same+1))
    else
        differ=$((differ+1))
        if [ "$differ" -le 3 ]; then
            echo "  $(basename "$f"):"
            printf '%s\n' "$a" > "$C/.a.$$"
            printf '%s\n' "$b" > "$C/.b.$$"
            diff "$C/.a.$$" "$C/.b.$$" | sed 's/^/    /'
            rm -f "$C/.a.$$" "$C/.b.$$"
        fi
    fi
done
echo "$n certificates, $same identical, $differ differ"
[ "$differ" -eq 0 ] && [ "$n" -gt 0 ]
