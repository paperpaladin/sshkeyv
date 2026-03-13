#!/usr/bin/env python3
"""The curve constants sshkeyv holds, against the formulas they come from.

A mistyped curve constant is the worst kind of defect to find from the
outside: it does not crash and it does not give a wrong answer. It gives a
refusal with a plausible message. Writing the P-521 group order with 131
hex digits instead of 132 divided it by sixteen, and every P-521 signature
was then reported as having an r or s at or above the group order, which
reads exactly like a verifier being careful.

So the primes are recomputed here from the expressions in FIPS 186-4
rather than copied: P-256 is 2^256 - 2^224 + 2^192 + 2^96 - 1, P-384 is
2^384 - 2^128 - 2^96 + 2^32 - 1, P-521 is 2^521 - 1. The group orders and
the b and G values cannot be computed from a short expression, so they are
written out here as a second transcription, and the check that makes that
worth anything is the last one: G must satisfy the curve equation modulo
p, and n G must be the identity, both computed in python from sshkeyv's
own numbers.

Usage: curvecmp.py
Prints "N compared, M differ".
"""
import os
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")

EXPECT = {
    "nistp256": dict(
        p=2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
        bytes=32),
    "nistp384": dict(
        p=2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
        n=int("ffffffffffffffffffffffffffffffffffffffffffffffff"
              "c7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
        b=int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe814112"
              "0314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
        gx=int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
              "59f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
        gy=int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
              "e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
        bytes=48),
    "nistp521": dict(
        p=2 ** 521 - 1,
        n=int("01ffffffffffffffffffffffffffffffffffffffffffffff"
              "fffffffffffffffffffa51868783bf2f966b7fcc0148f709"
              "a5d03bb5c9b8899c47aebb6fb71e91386409", 16),
        b=int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b3"
              "15f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1"
              "bf073573df883d2c34f1ef451fd46b503f00", 16),
        gx=int("00c6858e06b70404e9cd9e3ecb662395b4429c648139053f"
              "b521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ff"
              "a8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
        gy=int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b"
              "446817afbd17273e662c97ee72995ef42640c550b9013fad"
              "0761353c7086a272c24088be94769fd16650", 16),
        bytes=66),
}


def point_add(a, b, p):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % p == 0:
            return None
        lam = (3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, p) % p
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
    x = (lam * lam - a[0] - b[0]) % p
    return (x, (lam * (a[0] - x) - a[1]) % p)


def point_mul(k, pt, p):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt, p)
        pt = point_add(pt, pt, p)
        k >>= 1
    return r


def main():
    compared = differ = 0
    bad = []
    for name, want in EXPECT.items():
        p = subprocess.run([BIN, "curve", name], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        got = {}
        for line in p.stdout.decode().splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                got[parts[1]] = parts[2]
        if p.returncode != 0 or not got:
            print("  %s: sshkeyv curve failed: %s"
                  % (name, p.stderr.decode().strip()))
            return 1
        for k in ("p", "n", "b", "gx", "gy"):
            compared += 1
            g = int(got[k], 16)
            if g != want[k]:
                differ += 1
                bad.append("%s %s: sshkeyv %x, expected %x"
                           % (name, k, g, want[k]))
        compared += 1
        if int(got["bytes"]) != want["bytes"]:
            differ += 1
            bad.append("%s bytes: %s, expected %d"
                       % (name, got["bytes"], want["bytes"]))
        # The checks that make the transcription worth anything, both over
        # sshkeyv's own numbers rather than over the expected ones.
        sp, sn = int(got["p"], 16), int(got["n"], 16)
        sb = int(got["b"], 16)
        gx, gy = int(got["gx"], 16), int(got["gy"], 16)
        compared += 1
        if (gy * gy - (gx * gx * gx - 3 * gx + sb)) % sp != 0:
            differ += 1
            bad.append("%s: G is not on the curve y^2 = x^3 - 3x + b" % name)
        compared += 1
        if point_mul(sn, (gx, gy), sp) is not None:
            differ += 1
            bad.append("%s: n G is not the identity, so n is not the order"
                       % name)
        compared += 1
        if int(got["field-bits"]) != sp.bit_length():
            differ += 1
            bad.append("%s: field-bits is %s, p has %d bits"
                       % (name, got["field-bits"], sp.bit_length()))
        compared += 1
        if int(got["order-bits"]) != sn.bit_length():
            differ += 1
            bad.append("%s: order-bits is %s, n has %d bits"
                       % (name, got["order-bits"], sn.bit_length()))
    for b in bad[:20]:
        print("  " + b)
    print("%d compared, %d differ" % (compared, differ))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
