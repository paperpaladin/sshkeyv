#!/bin/sh
# `sshkeyv verify --ca` against the CA key every certificate actually
# names, with ssh-keygen -L as the authority on which CA that is.
#
# The question --ca answers is the one a deployment has: was this issued by
# MY certificate authority. Without it, verify only proves the signature
# matches the key the certificate names, and a certificate names its own
# CA, so anybody can mint one that verifies. So every certificate is put to
# every CA key in the corpus: exactly one must be accepted and the rest
# must exit 4.
#
# Argument: the corpus directory. Prints
# "N pairs, M accepted, K rejected, J wrong".
set -u
C=${1:?usage: cacmp.sh CORPUSDIR}
BIN=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/target/release/sshkeyv

pairs=0; accepted=0; rejected=0; wrong=0
for cert in "$C"/*-cert.pub; do
    [ -f "$cert" ] || continue
    # ssh-keygen -L names the CA by its fingerprint; that is the oracle for
    # which CA key is the right one.
    want=$(ssh-keygen -L -f "$cert" 2>/dev/null \
           | sed -n 's/.*Signing CA: [A-Z0-9-]* \(SHA256:[^ ]*\).*/\1/p')
    if [ -z "$want" ]; then
        wrong=$((wrong+1))
        echo "  no Signing CA line for $(basename "$cert")"
        continue
    fi
    for ca in "$C"/ca_*.pub; do
        [ -f "$ca" ] || continue
        have=$(ssh-keygen -l -f "$ca" | awk '{print $2}')
        pairs=$((pairs+1))
        "$BIN" verify --ca "$ca" "$cert" >/dev/null 2>&1
        rc=$?
        if [ "$have" = "$want" ]; then
            if [ "$rc" -eq 0 ]; then
                accepted=$((accepted+1))
            else
                wrong=$((wrong+1))
                echo "  $(basename "$cert") with its own CA $(basename "$ca") exited $rc"
            fi
        else
            if [ "$rc" -eq 4 ]; then
                rejected=$((rejected+1))
            else
                wrong=$((wrong+1))
                echo "  $(basename "$cert") with the wrong CA $(basename "$ca") exited $rc, wanted 4"
            fi
        fi
    done
done
echo "$pairs pairs, $accepted accepted, $rejected rejected, $wrong wrong"
[ "$wrong" -eq 0 ] && [ "$accepted" -gt 0 ] && [ "$rejected" -gt 0 ]
