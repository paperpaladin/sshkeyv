#!/usr/bin/env python3
"""The RFC 4716 and PKCS8 encodings, both directions.

The PKCS8 comparison is the strongest in this project. ssh-keygen -e -m
pkcs8 produces the DER SubjectPublicKeyInfo for a key, there is exactly
one right answer, and the comparison is byte for byte against it. No
interpretation on either side.

Ed25519 is the exception and it goes the other way: ssh-keygen refuses to
convert it at all, with "unsupported key type ED25519". It is an ordinary
SubjectPublicKeyInfo under RFC 8410, so sshkeyv writes one and openssl is
the oracle instead, by reading it back and printing the key bytes.

RFC 4716 cannot be compared as text, because the Comment header ssh-keygen
writes names the local user and host. So three things are compared
instead: ssh-keygen -i reads sshkeyv's block and gives back the original
blob, sshkeyv reads ssh-keygen's block and gives back the original blob,
and the headers sshkeyv writes obey the 72-character continuation rule.

The DER refusals at the end are the BER-but-not-DER length encodings:
indefinite length, long form where short form would do, and a long form
with a leading zero octet. openssl is asked about each. It reads four of
the five, because its reader is a BER reader, and those over-refusals are
printed by name rather than hidden and do not fail the suite: each is a
second byte string with the same meaning, which is the malleability DER
exists to remove. An under-refusal, sshkeyv reading something openssl
will not, does fail.

Usage: convertcmp.py CORPUSDIR
"""
import base64
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")


def run(*args, **kw):
    return subprocess.run(list(args), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kw)


def blob_of_line(line):
    return base64.b64decode(line.split()[1], validate=True)


def main():
    d = sys.argv[1]
    work = os.path.join(d, "cvwork")
    os.makedirs(work, exist_ok=True)
    compared = differ = refused = 0
    bad = []
    kinds = set()
    for name in sorted(os.listdir(d)):
        if not name.endswith(".pub") or name.endswith("-cert.pub"):
            continue
        path = os.path.join(d, name)
        with open(path) as f:
            line = f.readline().strip()
        algo = line.split()[0]
        if algo.endswith("-cert-v01@openssh.com"):
            continue
        kinds.add(algo)
        blob = blob_of_line(line)

        # PKCS8, byte for byte, where ssh-keygen will produce it.
        want = run("ssh-keygen", "-e", "-m", "pkcs8", "-f", path)
        got = run(BIN, "convert", "-m", "pkcs8", path)
        compared += 1
        if want.returncode == 0:
            if got.returncode != 0:
                refused += 1
                bad.append("%s: pkcs8 refused: %s"
                           % (name, got.stderr.decode().strip()))
            elif got.stdout != want.stdout:
                differ += 1
                bad.append("%s: pkcs8 differs from ssh-keygen's" % name)
        else:
            # ssh-keygen will not convert it; openssl must still read it.
            if got.returncode != 0:
                refused += 1
                bad.append("%s: pkcs8 refused and ssh-keygen also refused "
                           "(%s)" % (name, got.stderr.decode().strip()))
            else:
                o = run("openssl", "pkey", "-pubin", "-text", "-noout",
                        input=got.stdout)
                if o.returncode != 0:
                    differ += 1
                    bad.append("%s: openssl will not read sshkeyv's pkcs8"
                               % name)
                else:
                    # The key bytes openssl prints must be the key bytes in
                    # the blob.
                    hexed = "".join(
                        c for ln in o.stdout.decode().splitlines()
                        if ln.startswith("    ") for c in ln.strip()
                    ).replace(":", "")
                    if hexed and hexed not in blob.hex():
                        differ += 1
                        bad.append("%s: openssl read different key bytes"
                                   % name)

        # PKCS8 back again, from ssh-keygen's own bytes where it has them.
        if want.returncode == 0:
            p8 = os.path.join(work, "k.pkcs8")
            with open(p8, "wb") as f:
                f.write(want.stdout)
            back = run(BIN, "convert", "-m", "openssh", p8)
            compared += 1
            if back.returncode != 0:
                refused += 1
                bad.append("%s: cannot read ssh-keygen's pkcs8: %s"
                           % (name, back.stderr.decode().strip()))
            elif blob_of_line(back.stdout.decode()) != blob:
                differ += 1
                bad.append("%s: reading ssh-keygen's pkcs8 gave a different "
                           "blob" % name)
            # And ssh-keygen must read sshkeyv's pkcs8.
            mine = os.path.join(work, "mine.pkcs8")
            with open(mine, "wb") as f:
                f.write(got.stdout)
            ki = run("ssh-keygen", "-i", "-m", "pkcs8", "-f", mine)
            compared += 1
            if ki.returncode != 0:
                differ += 1
                bad.append("%s: ssh-keygen will not read sshkeyv's pkcs8"
                           % name)
            elif blob_of_line(ki.stdout.decode()) != blob:
                differ += 1
                bad.append("%s: ssh-keygen read a different blob from "
                           "sshkeyv's pkcs8" % name)

        # RFC 4716, both directions.
        mine = os.path.join(work, "mine.rfc4716")
        got = run(BIN, "convert", "-m", "rfc4716", path)
        compared += 1
        if got.returncode != 0:
            refused += 1
            bad.append("%s: rfc4716 refused: %s"
                       % (name, got.stderr.decode().strip()))
        else:
            with open(mine, "wb") as f:
                f.write(got.stdout)
            for ln in got.stdout.decode().splitlines():
                if len(ln) > 72:
                    differ += 1
                    bad.append("%s: an rfc4716 line is %d characters"
                               % (name, len(ln)))
            ki = run("ssh-keygen", "-i", "-m", "rfc4716", "-f", mine)
            compared += 1
            if ki.returncode != 0:
                differ += 1
                bad.append("%s: ssh-keygen will not read sshkeyv's rfc4716: "
                           "%s" % (name, ki.stderr.decode().strip()))
            elif blob_of_line(ki.stdout.decode()) != blob:
                differ += 1
                bad.append("%s: ssh-keygen read a different blob from "
                           "sshkeyv's rfc4716" % name)
        theirs = run("ssh-keygen", "-e", "-m", "rfc4716", "-f", path)
        if theirs.returncode == 0:
            tp = os.path.join(work, "theirs.rfc4716")
            with open(tp, "wb") as f:
                f.write(theirs.stdout)
            back = run(BIN, "convert", "-m", "openssh", tp)
            compared += 1
            if back.returncode != 0:
                refused += 1
                bad.append("%s: cannot read ssh-keygen's rfc4716: %s"
                           % (name, back.stderr.decode().strip()))
            elif blob_of_line(back.stdout.decode()) != blob:
                differ += 1
                bad.append("%s: reading ssh-keygen's rfc4716 gave a "
                           "different blob" % name)

    # DER length encodings that are BER and not DER.
    base = run("ssh-keygen", "-e", "-m", "pkcs8", "-f",
               os.path.join(d, "ecdsa256.pub")).stdout
    der = base64.b64decode(
        "".join(l for l in base.decode().splitlines()
                if not l.startswith("-----")), validate=True)
    variants = [
        ("indefinite length", bytes([der[0], 0x80]) + der[2:] + b"\x00\x00"),
        ("long form for a short length",
         bytes([der[0], 0x81, der[1]]) + der[2:]),
        ("long form with a leading zero octet",
         bytes([der[0], 0x82, 0x00, der[1]]) + der[2:]),
        ("truncated by one byte", der[:-1]),
        ("one trailing byte", der + b"\x00"),
    ]
    both = over = under = 0
    for label, d2 in variants:
        p = os.path.join(work, "odd.pkcs8")
        b64 = base64.b64encode(d2).decode()
        with open(p, "w") as f:
            f.write("-----BEGIN PUBLIC KEY-----\n")
            for i in range(0, len(b64), 64):
                f.write(b64[i:i + 64] + "\n")
            f.write("-----END PUBLIC KEY-----\n")
        a = run(BIN, "convert", "-m", "openssh", p)
        o = run("openssl", "pkey", "-pubin", "-in", p, "-noout")
        if a.returncode != 0 and o.returncode != 0:
            both += 1
            print("    refused by both: %s -- %s"
                  % (label, a.stderr.decode().strip()))
        elif a.returncode != 0:
            over += 1
            print("  OVER-REFUSED openssl reads it: %s -- %s"
                  % (label, a.stderr.decode().strip()))
        elif o.returncode != 0:
            under += 1
            print("  UNDER-REFUSED openssl refuses it: %s" % label)
        else:
            print("    read by both: %s" % label)

    for b in bad[:20]:
        print("  " + b)
    print("  key types converted: %s" % " ".join(sorted(kinds)))
    gap = len(kinds) < 3
    if gap:
        print("  CORPUS GAP: fewer than three key types")
    print("%d compared, %d differ, %d refused; %d DER oddities refused by "
          "both, %d over-refused, %d under-refused"
          % (compared, differ, refused, both, over, under))
    # An over-refusal is printed by name and does not fail. openssl's DER
    # reader accepts BER lengths, and the four it reads here are all the
    # same shape: a second byte string with the same meaning, which is the
    # malleability DER exists to remove. Refusing them is a decision, and
    # it is in the README with this reasoning rather than left implicit.
    # An under-refusal does fail: it means sshkeyv read something openssl
    # will not.
    return 1 if (differ or refused or under or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
