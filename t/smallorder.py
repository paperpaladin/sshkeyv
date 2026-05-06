#!/usr/bin/env python3
"""Ed25519 public keys of small order, where a good signature means nothing.

Ed25519 as RFC 8032 specifies it uses the cofactorless equation
[S]B = R + [k]A, and neither OpenSSH nor OpenSSL rejects a public key of
small order. With A the identity, R = identity and S = 0 satisfy that
equation for ANY message, so every signature verifies and a verified
signature proves nothing.

With A of order 2, 4 or 8 the same trivial signature verifies exactly when
the order of A divides k, and k is a hash of the message. So the answer
depends on the message, about half the time for an order-2 point. The
first version of this script took whatever message the corpus happened to
produce and was therefore a coin toss: it passed when it was written,
passed the commit gate, and then failed five runs out of eight in a loop.
Both outcomes are now reached on purpose, by searching for a key id that
makes the equation hold and another that makes it fail, with python's own
point arithmetic deciding which is which before sshkeyv is asked.

Chasing that flake found a real three-way disagreement, which is recorded
rather than smoothed over. See the README.

Usage: smallorder.py CORPUSDIR
Prints "N cases, M as expected, K differ, J known oracle disagreements".
"""
import base64
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")
ED_SPKI = bytes.fromhex("302a300506032b6570032100")

P = 2 ** 255 - 19
D = (-121665 * pow(121666, -1, P)) % P
L = 2 ** 252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (P - 1) // 4, P)


def decode_point(b):
    """Returns (point, rfc_ok, why).

    The point is what an implementation that ignores RFC 8032 5.1.3's
    x = 0 with x_0 = 1 rule arrives at, which is what both oracles do.
    rfc_ok says whether the RFC accepts the encoding, which is what
    sshkeyv does. Keeping them apart is what makes the torsion-d case
    deterministic: sshkeyv refuses it always, while the oracles accept it
    only when the equation holds, and the equation holds for about half of
    all messages. Treating it as undecodable gave one coin toss per run.
    """
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= P:
        return None, False, "y is not less than p"
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    if v == 0:
        return None, False, "v is zero"
    xx = u * pow(v, -1, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        return None, False, "no square root"
    rfc_ok = not (x == 0 and sign)
    why = None if rfc_ok else "x is zero with the sign bit set"
    if x % 2 != sign:
        x = (P - x) % P
    return (x, y), rfc_ok, why


def padd(p, q):
    x1, y1 = p
    x2, y2 = q
    d = D * x1 * x2 % P * y1 % P * y2 % P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + d, -1, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - d, -1, P) % P
    return (x3, y3)


def pmul(k, p):
    r = (0, 1)
    while k:
        if k & 1:
            r = padd(r, p)
        p = padd(p, p)
        k >>= 1
    return r


def put(b):
    return struct.pack(">I", len(b)) + b


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


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

# torsion-d is y = p - 1 with the sign bit set, so x = 0 and x_0 = 1. RFC
# 8032 section 5.1.3 says decoding fails. Measured here: OpenSSH's
# ssh-keygen -L accepts it and so does openssl. sshkeyv follows the RFC
# and is alone, which is recorded as a known disagreement and explained in
# the README rather than averaged away.
KNOWN_DISAGREEMENT = {"torsion-d"}


def build(subject_pk, pk, keyid, ident):
    cakey = put(b"ssh-ed25519") + put(pk)
    body = (put(b"ssh-ed25519-cert-v01@openssh.com")
            + put(b"\x22" * 32)
            + put(subject_pk)
            + struct.pack(">Q", 1)
            + struct.pack(">I", 1)
            + put(keyid)
            + put(put(b"alice"))
            + struct.pack(">Q", 0)
            + struct.pack(">Q", 2 ** 64 - 1)
            + put(b"") + put(b"") + put(b"")
            + put(cakey))
    sig = put(b"ssh-ed25519") + put(ident + bytes(32))
    return body, body + put(sig)


def main():
    d = sys.argv[1]
    work = os.path.join(d, "sowork")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(d, "ed25519.pub")) as f:
        sub = base64.b64decode(f.readline().split()[1], validate=True)
    _, o = sshstr(sub, 0)
    subject_pk, _ = sshstr(sub, o)
    ident = (1).to_bytes(32, "little")

    cases = expected = differ = known = 0
    for name, pk in POINTS.items():
        pt, rfc_ok, why = decode_point(pk)
        # For each point, find a key id that makes the equation hold and
        # one that makes it fail, deciding with python's arithmetic.
        wanted = {}
        for i in range(400):
            keyid = b"so-%03d" % i
            body, blob = build(subject_pk, pk, keyid, ident)
            k = int.from_bytes(
                hashlib.sha512(ident + pk + body).digest(), "little") % L
            holds = None if pt is None else pmul(k, pt) == (0, 1)
            if holds not in wanted:
                wanted[holds] = (keyid, body, blob)
            if pt is None or len(wanted) == 2:
                break
        for holds, (keyid, body, blob) in sorted(
                wanted.items(), key=lambda kv: str(kv[0])):
            path = os.path.join(work, "c-cert.pub")
            with open(path, "w") as f:
                f.write("ssh-ed25519-cert-v01@openssh.com %s so\n"
                        % base64.b64encode(blob).decode())
            p = subprocess.run([BIN, "verify", path],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
            out = (p.stdout.decode() + p.stderr.decode()).strip()
            cases += 1
            if not rfc_ok:
                # sshkeyv refuses the encoding whatever the equation does.
                want_rc, want_word = 3, None
                label = "%s (%s, equation %s)" % (
                    name, why, "holds" if holds else "does not hold")
            elif pt is None:
                want_rc, want_word = 3, None
                label = "%s (%s)" % (name, why)
            elif holds:
                want_rc, want_word = 4, "MEANINGLESS"
                label = "%s, equation holds" % name
            else:
                want_rc, want_word = 3, None
                label = "%s, equation does not hold" % name
            ok = p.returncode == want_rc and (
                want_word is None or want_word in out)
            if ok:
                expected += 1
            else:
                differ += 1
                print("  WRONG %s: rc=%d, wanted %d -- %s"
                      % (label, p.returncode, want_rc,
                         out.splitlines()[-1] if out else ""))

            # The two oracles over the same bytes.
            der = os.path.join(work, "k.der")
            pem = os.path.join(work, "k.pem")
            with open(der, "wb") as f:
                f.write(ED_SPKI + pk)
            ow = None
            if subprocess.run(["openssl", "pkey", "-pubin", "-inform",
                               "DER", "-in", der, "-out", pem],
                              stderr=subprocess.DEVNULL).returncode == 0:
                mf = os.path.join(work, "m.bin")
                sf = os.path.join(work, "s.bin")
                with open(mf, "wb") as f:
                    f.write(body)
                with open(sf, "wb") as f:
                    f.write(ident + bytes(32))
                ow = subprocess.run(
                    ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                     pem, "-rawin", "-sigfile", sf, "-in", mf],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL).returncode == 0
            kg = subprocess.run(["ssh-keygen", "-L", "-f", path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL).returncode == 0
            mine_holds = p.returncode in (0, 4)
            oracles_hold = bool(holds) if holds is not None else None
            if ow == mine_holds and kg == mine_holds:
                print("    %s: all three agree (%s)"
                      % (label, "holds" if mine_holds else "refused"))
            elif name in KNOWN_DISAGREEMENT and oracles_hold:
                known += 1
                print("    KNOWN DISAGREEMENT %s: sshkeyv %s, openssl %s, "
                      "ssh-keygen %s"
                      % (label, mine_holds, ow, kg))
            else:
                differ += 1
                print("  ORACLES DIFFER %s: sshkeyv %s, openssl %s, "
                      "ssh-keygen %s" % (label, mine_holds, ow, kg))
    print("%d cases, %d as expected, %d differ, %d known oracle "
          "disagreements" % (cases, expected, differ, known))
    if known == 0:
        print("  the known disagreement no longer occurs; the README is "
              "stale")
        return 1
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
