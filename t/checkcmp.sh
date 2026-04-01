#!/bin/sh
# `sshkeyv check` over the whole corpus, with ssh-keygen as the authority
# on which files are keys.
#
# The point of this one is coverage rather than values: check reads every
# layer a file has, so it is the command that would notice an option whose
# data is not a single string, or a private container whose two copies of
# the public key disagree. Every file ssh-keygen can read must be ok here,
# and every file neither tool can read must be refused by both.
#
# Argument: the corpus directory. Prints
# "N files, M ok, K refused, J over-refused, I under-refused".
set -u
C=${1:?usage: checkcmp.sh CORPUSDIR}
BIN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/target/release/sshkeyv

n=0; ok=0; refused=0; over=0; under=0
for f in "$C"/*; do
    [ -f "$f" ] || continue
    n=$((n+1))
    if "$BIN" check "$f" >/dev/null 2>&1; then
        mine=0
    else
        mine=1
    fi
    # ssh-keygen -l reads a public key, a certificate and a private key
    # container, including an encrypted one. It does not read an SSHSIG
    # file, a PKCS8 SubjectPublicKeyInfo or an RFC4716 block, so those
    # three are asked of the flag that does: -Y check-novalidate for a
    # signature and -i for the two containers.
    case "$f" in
        *.sig)
                # check-novalidate verifies the signature over the message
                # on stdin, so it needs the right message and the right
                # namespace. Feeding it /dev/null and -n file reported 20
                # of the 25 signature files as refused by ssh-keygen, which
                # is the oracle answering a question about an empty message
                # rather than about the file. The corpus names both.
                ns=file
                case "$f" in *_git.sig) ns=git ;; esac
                m=$C/msg
                case "$f" in
                    *_big.sig)   m=$C/msg_big ;;
                    *_empty.sig) m=$C/msg_empty ;;
                esac
                ssh-keygen -Y check-novalidate -n "$ns" -s "$f" \
                    <"$m" >/dev/null 2>&1 ;;
        *.pkcs8) ssh-keygen -i -m pkcs8 -f "$f" >/dev/null 2>&1 ;;
        *.rfc4716) ssh-keygen -i -m rfc4716 -f "$f" >/dev/null 2>&1 ;;
        *) ssh-keygen -l -f "$f" >/dev/null 2>&1 ;;
    esac
    theirs=$?
    if [ "$mine" -eq 0 ] && [ "$theirs" -eq 0 ]; then
        ok=$((ok+1))
    elif [ "$mine" -ne 0 ] && [ "$theirs" -ne 0 ]; then
        refused=$((refused+1))
    elif [ "$mine" -ne 0 ]; then
        over=$((over+1))
        echo "  OVER-REFUSED $(basename "$f"): $("$BIN" check "$f" 2>&1 | tail -1)"
    else
        under=$((under+1))
        echo "  UNDER-REFUSED $(basename "$f"): ssh-keygen refuses it"
    fi
done
echo "$n files, $ok ok, $refused refused by both, $over over-refused, $under under-refused"
[ "$over" -eq 0 ] && [ "$under" -eq 0 ] && [ "$ok" -gt 0 ]
