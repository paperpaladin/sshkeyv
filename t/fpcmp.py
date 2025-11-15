#!/usr/bin/env python3
"""`sshkeyv fp` against `ssh-keygen -l -f`, whole line.

This one comparison is a string equality rather than a field-by-field
read, because the line is entirely determined: bits, hash name, digest,
comment, kind in brackets. Reproducing it exactly is the point, so there
is nothing to interpret on either side.

A certificate is the case worth having. ssh-keygen -l on a certificate
prints the fingerprint of the key INSIDE it, not of the certificate, and
the first version of sshkeyv hashed the certificate blob and so disagreed
on every certificate in the corpus.

Usage: fpcmp.py CORPUSDIR [HASHNAME]
Prints "N compared, M differ, K refused".
"""
import os
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")


def main():
    d = sys.argv[1]
    hashes = sys.argv[2:] or ["sha256"]
    compared = differ = refused = 0
    bad = []
    certs = plains = 0
    for name in sorted(os.listdir(d)):
        if not name.endswith(".pub"):
            continue
        path = os.path.join(d, name)
        if name.endswith("-cert.pub"):
            certs += 1
        else:
            plains += 1
        for h in hashes:
            want = subprocess.run(
                ["ssh-keygen", "-l", "-E", h, "-f", path],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if want.returncode != 0:
                continue
            got = subprocess.run([BIN, "fp", "-E", h, path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            compared += 1
            w = want.stdout.decode().strip()
            if got.returncode != 0:
                refused += 1
                bad.append("%s %s: refused: %s"
                           % (name, h, got.stderr.decode().strip()))
            elif got.stdout.decode().strip() != w:
                differ += 1
                bad.append("%s %s:\n    got  %s\n    want %s"
                           % (name, h, got.stdout.decode().strip(), w))
    for b in bad[:20]:
        print("  " + b)
    # The construct counts are printed because a certificate comparison
    # over a corpus with no certificates in it passes having done nothing.
    print("%d plain keys, %d certificates" % (plains, certs))
    print("%d compared, %d differ, %d refused" % (compared, differ, refused))
    return 1 if (differ or refused) else 0


if __name__ == "__main__":
    sys.exit(main())
