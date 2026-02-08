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

# The corpus holds private keys, so it is built OUTSIDE the repository and
# removed on the way out. A private key committed once stays in the object
# database after the file is deleted, and the collection's audit reads
# objects rather than the working tree, so this is the one failure in the
# list that cannot be undone afterwards.
C=$(mktemp -d "${TMPDIR:-/tmp}/sshkeyv.corpus.XXXXXX") || exit 2
case "$C" in
  "$ROOT"*) echo "sshkeyv: refusing to build the corpus inside the repository: $C" >&2
            exit 2 ;;
esac
trap 'rm -rf "$C"' EXIT INT TERM

note "the tools themselves"
echo "    $(ssh -V 2>&1)"
echo "    $(openssl version)"

note "corpus"
sh "$HERE/mkcorpus.sh" "$C" >/dev/null 2>"$C/.mkerr" || {
    echo "sshkeyv: the corpus generator failed:" >&2
    cat "$C/.mkerr" >&2
    exit 2
}
nf=$(ls "$C" | wc -l)
echo "    $nf files in $C"
# A corpus smaller than this means the generator fell over partway and
# every comparison after it would run over whatever did get made and
# report passes. The number is a floor, not the count.
if [ "$nf" -ge 120 ]; then
    ok "the corpus generator produced $nf files"
else
    no "the corpus generator produced only $nf files"
fi

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

note "the SSH wire format, against t/wire.py"
out=$(python3 "$HERE/wire.py" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 \
     | grep -q '^[0-9]* blobs, [0-9]* lines compared, 0 differ, 0 stop-offsets differ$'; then
    ok "the wire reader agrees with the python parser line for line"
else
    no "the wire reader disagrees with the python parser"
fi

note "SHA-256, SHA-512, MD5 and SHA-1, against coreutils and hashlib"
out=$(python3 "$HERE/hashcmp.py" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 | grep -q '^812 compared, 0 differ$'; then
    ok "all four digests agree with the coreutils tools and hashlib"
else
    no "a digest disagrees with the oracles"
fi

note "fingerprints in four forms, against ssh-keygen -l and -B"
out=$(python3 "$HERE/fpcmp.py" "$C" sha256 md5 sha1 bubblebabble 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 | grep -q '^[0-9]* compared, 0 differ, 0 refused$'; then
    ok "every fingerprint line equals ssh-keygen's"
else
    no "a fingerprint line differs from ssh-keygen's"
fi
# The comparison above is worth nothing over a corpus with no certificates
# in it, so the counts it prints are asserted on separately.
if echo "$out" | grep -q '^4[0-9] plain keys, 2[0-9] certificates$'; then
    ok "the fingerprint comparison saw both plain keys and certificates"
else
    no "the fingerprint comparison did not see both kinds"
fi

note "key fields, against ssh-keygen -l and a python parse"
out=$(python3 "$HERE/fieldcmp.py" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 \
     | grep -q '^[0-9]* files, [0-9]* compared, 0 differ, 0 refused, [0-9]* declined$'; then
    ok "every key field agrees with the oracles"
else
    no "a key field disagrees with an oracle"
fi

note "certificate fields, against ssh-keygen -L and a python parse"
out=$(python3 "$HERE/certcmp.py" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 \
     | grep -q '^[0-9]* certificates, [0-9]* compared, 0 differ, 0 refused$'; then
    ok "every certificate field agrees with the oracles"
else
    no "a certificate field disagrees with an oracle, or the corpus has a gap"
fi

note "sshkeyv show against ssh-keygen -L, whole output"
out=$(sh "$HERE/showcmp.sh" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 \
     | grep -q '^[0-9]* certificates, [0-9]* identical, 0 differ$'; then
    ok "every certificate block is byte for byte ssh-keygen's"
else
    no "a certificate block differs from ssh-keygen's"
fi

note "validity verdicts and principal authorisation"
out=$(python3 "$HERE/validcmp.py" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] \
   && echo "$out" | grep -q '^[0-9]* certificates, [0-9]* verdicts compared, 0 differ$' \
   && echo "$out" | grep -q '^[0-9]* authorisation questions, 0 differ$'; then
    ok "every verdict matches the window and the list ssh-keygen prints"
else
    no "a verdict disagrees with the window or the list ssh-keygen prints"
fi

note "the private key container, against ssh-keygen -y, -l and a python parse"
out=$(python3 "$HERE/privcmp.py" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 \
     | grep -q '^[0-9]* compared, 0 differ, 0 refused; [0-9]* malformed refused by both, 0 over-refused, 0 under-refused$'; then
    ok "the container header and private section agree with the oracles"
else
    no "the container header or private section disagrees with an oracle"
fi

note "malformed key lines, with ssh-keygen as the authority on malformed"
out=$(python3 "$HERE/refusecmp.py" "$C" 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
if [ $rc -eq 0 ] && echo "$out" | tail -1 \
     | grep -q '^[0-9]* cases, [0-9]* refused by both, 0 over-refused, 0 under-refused$'; then
    ok "sshkeyv and ssh-keygen refuse the same lines"
else
    no "sshkeyv and ssh-keygen disagree about which lines are malformed"
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
