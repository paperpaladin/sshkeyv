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
import base64
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
    privs = encs = 0
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if not os.path.isfile(path):
            continue
        is_priv = False
        if not name.endswith(".pub"):
            with open(path, "rb") as f:
                if f.read(35) != b"-----BEGIN OPENSSH " + "PRIVATE KEY-----":
                    continue
            is_priv = True
        if is_priv:
            # ssh-keygen -l on a private key prefers the .pub file beside
            # it and so can print a comment sshkeyv cannot see, because
            # sshkeyv reads only the file it was given and the comment
            # lives in the encrypted half. Encrypted containers are
            # therefore compared on the digest and the bits only.
            with open(path) as f:
                body = f.read()
            enc = "bcrypt" in base64.b64decode(
                "".join(l for l in body.splitlines()
                        if not l.startswith("-----")),
                validate=True).decode("latin-1")
            privs += 1
            if enc:
                encs += 1
        elif name.endswith("-cert.pub"):
            certs += 1
        else:
            plains += 1
        for h in hashes:
            # ssh-keygen prints the bubblebabble digest with -B, not with
            # -E, and with no hash name in front of it.
            cmd = (["ssh-keygen", "-B", "-f", path] if h == "bubblebabble"
                   else ["ssh-keygen", "-l", "-E", h, "-f", path])
            want = subprocess.run(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
            if want.returncode != 0:
                continue
            got = subprocess.run([BIN, "fp", "-E", h, path],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            compared += 1
            w = want.stdout.decode().strip()
            if is_priv:
                # The bits, the digest and the kind must match exactly.
                # The comment is compared only when ssh-keygen has a real
                # one: it prints the path of the .pub file it found when
                # the key it read carries none, and it reads that .pub
                # file in preference to the container, so its comment can
                # come from a different file altogether. sshkeyv reads
                # only the file it was given, and for an encrypted
                # container the comment is behind the passphrase.
                gw = got.stdout.decode().strip().split()
                ww = w.split()
                if got.returncode != 0:
                    refused += 1
                    bad.append("%s %s: refused: %s"
                               % (name, h, got.stderr.decode().strip()))
                    continue
                if gw[:2] != ww[:2] or gw[-1] != ww[-1]:
                    differ += 1
                    bad.append("%s %s:\n    got  %s\n    want %s"
                               % (name, h, " ".join(gw), w))
                    continue
                their_comment = w.rsplit(" (", 1)[0].split(" ", 2)[2]
                if (not enc and their_comment != "no comment"
                        and not os.path.exists(their_comment)):
                    mine = got.stdout.decode().strip().rsplit(
                        " (", 1)[0].split(" ", 2)[2]
                    compared += 1
                    if mine != their_comment:
                        differ += 1
                        bad.append("%s %s: comment %r, ssh-keygen %r"
                                   % (name, h, mine, their_comment))
                continue
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
    print("%d plain keys, %d certificates, %d private containers of which "
          "%d encrypted" % (plains, certs, privs, encs))
    print("%d compared, %d differ, %d refused" % (compared, differ, refused))
    return 1 if (differ or refused) else 0


if __name__ == "__main__":
    sys.exit(main())
