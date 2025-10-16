#!/bin/sh
# sshkeyv test suite.
#
# Run it as `make test`, never directly: the Makefile's test target depends
# on `all`, and a harness that does not build the thing it tests reports
# passes for whatever binary was lying around. The staleness guard below is
# the second line of defence for when it is invoked directly anyway.
#
# The final line is exactly "N passed, M failed"; the collection's tooling
# parses it.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(dirname "$HERE")
BIN=$ROOT/target/release/sshkeyv

pass=0
fail=0
ok()   { pass=$((pass+1)); echo "ok   $*"; }
no()   { fail=$((fail+1)); echo "FAIL $*"; }
note() { echo "--- $*"; }

if [ ! -x "$BIN" ]; then
    echo "sshkeyv: $BIN does not exist; run make test, not t/run.sh" >&2
    exit 2
fi
for f in "$ROOT"/src/*.rs "$ROOT"/Cargo.toml; do
    if [ "$f" -nt "$BIN" ]; then
        echo "sshkeyv: $f is newer than $BIN; run make test, not t/run.sh" >&2
        exit 2
    fi
done

# Every fact this suite checks comes from one of these. A run without them
# would compare sshkeyv against itself and print a row of passes having
# checked nothing, so it is a refusal and not a skip.
for tool in ssh-keygen openssl python3; do
    command -v $tool >/dev/null 2>&1 || {
        echo "sshkeyv: $tool is not installed. It is an oracle for this" \
             "suite, and a reduced run would report passes having compared" \
             "sshkeyv with itself." >&2
        exit 2
    }
done

note "the tools themselves"
echo "    $(ssh -V 2>&1)"
echo "    $(openssl version)"

note "usage"
"$BIN" >/dev/null 2>&1
[ $? -eq 2 ] && ok "no arguments exits 2" || no "no arguments did not exit 2"
"$BIN" nonesuch >/dev/null 2>&1
[ $? -eq 2 ] && ok "an unknown command exits 2" \
             || no "an unknown command did not exit 2"

note "base64, against python's"
out=$(python3 "$HERE/b64cmp.py" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
# Both halves on purpose: the exit status alone would pass if the script
# died before comparing anything, and the summary line alone would pass if
# the script crashed after printing it.
if [ $rc -eq 0 ] && echo "$out" | tail -1 | grep -q '^154 compared, 0 differ, .* 0 under-refused$'; then
    ok "base64 agrees with python both ways"
else
    no "base64 disagrees with python"
fi

note "source invariants"
n=$(cat "$ROOT"/src/*.rs | grep -c 'unsafe')
if [ "$n" -eq 0 ]; then
    ok "no unsafe in src (0 occurrences)"
else
    no "src holds $n occurrences of unsafe"
fi
if grep -A1 '^\[dependencies\]' "$ROOT/Cargo.toml" | tail -1 | grep -q '^ *$'; then
    ok "Cargo.toml declares no dependencies"
else
    no "Cargo.toml has grown a dependency"
fi
w=$(cd "$ROOT" && touch src/main.rs && cargo build --release --offline 2>&1 \
      | grep -c '^warning')
if [ "$w" -eq 0 ]; then
    ok "the release build is warning-free"
else
    no "the release build emits $w warnings"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
