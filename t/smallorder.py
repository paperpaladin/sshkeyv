#!/usr/bin/env python3
"""Ed25519 public keys of small order, where a good signature means nothing.

Ed25519 as RFC 8032 specifies it uses the cofactorless equation
[S]B = R + [k]A, and neither OpenSSH nor OpenSSL rejects a public key of
small order. If A is the identity point then R = identity with S = 0
satisfies that equation for ANY message, so every signature verifies.

This is measured rather than argued. openssl is handed the identity
encoding and each of the eight torsion points with that trivial signature,
and it calls three of them good. sshkeyv must agree about the arithmetic,
because disagreeing with both oracles about whether an equation holds
would be a defect, and must say so: it exits 4 with the word MEANINGLESS
rather than reporting a plain good signature, because a tool whose job is
to answer "does the CA signature verify" is useless if it says yes for a
key under which everything verifies.

Where openssl refuses a point, so must sshkeyv, and for the same reason:
those encodings are not on the curve or are not canonical.

Usage: smallorder.py CORPUSDIR
Prints "N keys, M meaningless, K refused, J differ".
"""
import base64
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")
ED_SPKI = bytes.fromhex("302a300506032b6570032100")

# The identity, and the eight points of order dividing 8. These are the
# standard encodings; the script does not trust them, it asks openssl and
# sshkeyv about each and requires the two to agree.
POINTS = {
    "identity": (1).to_bytes(32, "little"),
    "zero": bytes(32),
    "torsion-a": bytes.fromhex(
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    "torsion-b": bytes.fromhex(
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    "torsion-c": bytes.fromhex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    "torsion-d": bytes.fromhex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
}


def put(b):
    return struct.pack(">I", len(b)) + b


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


def cert(capk, sig_raw, subject_pk, keyid):
    body = (put(b"ssh-ed25519-cert-v01@openssh.com")
            + put(b"\x22" * 32)
            + put(subject_pk)
            + struct.pack(">Q", 1)
            + struct.pack(">I", 1)
            + put(keyid.encode())
            + put(put(b"alice"))
            + struct.pack(">Q", 0)
            + struct.pack(">Q", 2 ** 64 - 1)
            + put(b"") + put(b"") + put(b"")
            + put(put(b"ssh-ed25519") + put(capk)))
    return body, body + put(put(b"ssh-ed25519") + put(sig_raw))


def main():
    d = sys.argv[1]
    work = os.path.join(d, "sowork")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(d, "ed25519.pub")) as f:
        sub = base64.b64decode(f.readline().split()[1], validate=True)
    _, o = sshstr(sub, 0)
    subject_pk, _ = sshstr(sub, o)

    ident = (1).to_bytes(32, "little")
    trivial = ident + bytes(32)      # R = identity, S = 0

    keys = meaningless = refused = differ = 0
    for name, pk in POINTS.items():
        body, blob = cert(pk, trivial, subject_pk, "smallorder-" + name)
        path = os.path.join(work, "c-cert.pub")
        with open(path, "w") as f:
            f.write("ssh-ed25519-cert-v01@openssh.com %s so\n"
                    % base64.b64encode(blob).decode())
        p = subprocess.run([BIN, "verify", path], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        out = (p.stdout.decode() + p.stderr.decode()).strip()

        der = os.path.join(work, "k.der")
        pem = os.path.join(work, "k.pem")
        with open(der, "wb") as f:
            f.write(ED_SPKI + pk)
        lo = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                             "-in", der, "-out", pem],
                            stderr=subprocess.DEVNULL)
        ow = None
        if lo.returncode == 0:
            mf = os.path.join(work, "m.bin")
            sf = os.path.join(work, "s.bin")
            with open(mf, "wb") as f:
                f.write(body)
            with open(sf, "wb") as f:
                f.write(trivial)
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                                "-inkey", pem, "-rawin", "-sigfile", sf,
                                "-in", mf],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            ow = r.returncode == 0

        keys += 1
        mine_equation_holds = p.returncode in (0, 4)
        if ow is not None and ow != mine_equation_holds:
            differ += 1
            print("  DIFFER %s: openssl %s, sshkeyv rc=%d -- %s"
                  % (name, "good" if ow else "refused", p.returncode,
                     out.splitlines()[-1] if out else ""))
            continue
        if p.returncode == 4 and "MEANINGLESS" in out:
            meaningless += 1
            print("    %s: equation holds, reported meaningless (openssl %s)"
                  % (name, {None: "not asked", True: "good",
                            False: "refused"}[ow]))
        elif p.returncode == 0:
            differ += 1
            print("  NOT FLAGGED %s: sshkeyv called a small-order key's "
                  "signature plainly good" % name)
        else:
            refused += 1
            print("    %s: refused -- %s"
                  % (name, out.split(": ", 2)[-1].splitlines()[0]
                     if out else ""))
    print("%d keys, %d meaningless, %d refused, %d differ"
          % (keys, meaningless, refused, differ))
    if meaningless == 0 or refused == 0:
        print("  PROBE GAP: both outcomes must occur")
        return 1
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
