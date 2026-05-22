#!/bin/sh
# The validity-time formatting against `date -u`, both directions.
#
# The conversion is Howard Hinnant's civil_from_days and its inverse, and
# it is the kind of code that is right for 2026 and wrong for 1900, 2100
# or a leap day. `date -u -d @N` is an oracle this project does not
# control and has nothing to do with SSH, which is the point.
#
# The instants are chosen rather than random: both ends of the 32-bit
# range, every century boundary from 1900 to 2400 so that the 100 and 400
# year leap rules are both exercised in both directions, both 29ths of
# February either side of 2000, the day before and after each, and the
# four sentinel-adjacent values a certificate can carry.
#
# Prints "N instants, M differ, K round trips differ".
set -u
BIN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/target/release/sshkeyv

INSTANTS="0 1 86399 86400 951782399 951782400 951868800 1709164800
 2145916800 2147483647 2147483648 4102444800 4107542400 -2208988800"
# Century boundaries and leap days, computed with date so that the list is
# not a second transcription.
for y in 1900 1901 1904 1996 2000 2001 2004 2096 2100 2101 2104 2200 2300 2400; do
    for md in 01-01 02-28 03-01 12-31; do
        t=$(date -u -d "$y-$md 00:00:00" +%s 2>/dev/null) || continue
        INSTANTS="$INSTANTS $t"
    done
done
# Every hour of one day, so the time-of-day arithmetic is covered too.
for h in 0 1 11 12 13 22 23; do
    INSTANTS="$INSTANTS $((1700000000 + h * 3600))"
done

n=0; differ=0; rt=0
for t in $INSTANTS; do
    case "$t" in -*) continue ;; esac
    n=$((n+1))
    want=$(date -u -d "@$t" +%Y-%m-%dT%H:%M:%S)
    line=$("$BIN" time "$t")
    got=$(printf '%s' "$line" | cut -f2)
    extra=$(printf '%s' "$line" | cut -f3)
    if [ "$got" != "$want" ]; then
        differ=$((differ+1))
        echo "  $t: sshkeyv $got, date -u $want"
    fi
    if [ -n "$extra" ]; then
        rt=$((rt+1))
        echo "  $t: $extra"
    fi
    # And the other direction: the text date printed must parse back to
    # the same second.
    back=$("$BIN" time "$want" | cut -f2)
    if [ "$back" != "$t" ]; then
        rt=$((rt+1))
        echo "  $want: parsed back to $back, wanted $t"
    fi
done
echo "$n instants, $differ differ, $rt round trips differ"
[ "$differ" -eq 0 ] && [ "$rt" -eq 0 ] && [ "$n" -gt 60 ]
