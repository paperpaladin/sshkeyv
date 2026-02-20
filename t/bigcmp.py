#!/usr/bin/env python3
"""The bignum against python's own integers.

RSA verification is one modular exponentiation and the curve arithmetic is
a few thousand modular multiplications, so a defect in here shows up at
the top as "every signature is invalid", which is indistinguishable from
a verifier being strict. That is the reason this exists as a separate
comparison instead of being tested only through the signatures.

The operands are chosen for the carry and borrow paths rather than at
random: zero, one, a single limb, values straddling 2^32 and 2^64, values
that are all 0xff limbs, values whose difference needs a borrow through
several limbs, and the real RSA moduli out of the corpus if a directory is
given. Knuth's algorithm D has two correction steps that almost never
run, so the divisor set includes values whose top limb is 0x80000000 and
0xffffffff, which is where the qhat estimate is worst.

A seeded random sweep of 3000 divisions follows the fixed cases, with the
seed written down so the set is the same every run: it exists because the
qhat correction loop in Knuth D survived every hand-picked case and the
three pairs that kill it were found by searching for them.

Usage: bigcmp.py [CORPUSDIR]
Prints "N compared, M differ".
"""
import base64
import os
import struct
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")


def run(op, *args):
    p = subprocess.run([BIN, "big", op] + ["%x" % a for a in args],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        return None
    t = p.stdout.decode().strip()
    if not t:
        return 0
    # bits prints a decimal count; everything else prints hex.
    return int(t, 10 if op == "bits" else 16)


VALUES = [
    0, 1, 2, 3, 255, 256, 0xffff, 0x10000,
    0xffffffff, 0x100000000, 0x100000001,
    0xffffffffffffffff, 0x10000000000000000,
    0xffffffff00000000, 0x80000000, 0x8000000000000000,
    (1 << 128) - 1, 1 << 127, (1 << 127) + 1,
    0xdeadbeefcafebabe123456789abcdef0,
    (1 << 256) - 1, (1 << 255) + 1,
    # All-0xff limbs, which is where a carry runs the whole length.
    int("ff" * 32, 16), int("ff" * 33, 16),
    # A value whose low limbs are zero, so a borrow runs the whole length.
    1 << 200,
    (1 << 200) + 1,
    # Knuth D's qhat estimate is worst when the divisor's top limb is
    # small relative to the base; these two bracket that.
    0x8000000000000001,
    0xffffffff00000001,
]


def corpus_moduli(d):
    out = []
    for name in sorted(os.listdir(d)):
        if not name.endswith(".pub"):
            continue
        with open(os.path.join(d, name)) as f:
            line = f.readline().split()
        if len(line) < 2 or not line[0].startswith("ssh-rsa"):
            continue
        blob = base64.b64decode(line[1], validate=True)
        o = 0

        def s(b, o):
            (n,) = struct.unpack(">I", b[o:o + 4])
            return b[o + 4:o + 4 + n], o + 4 + n
        _, o = s(blob, o)
        _, o = s(blob, o)
        n, o = s(blob, o)
        out.append(int.from_bytes(n, "big"))
    return out


def main():
    compared = differ = 0
    bad = []
    vals = list(VALUES)
    if len(sys.argv) > 1:
        vals += corpus_moduli(sys.argv[1])
    for a in vals:
        compared += 1
        got = run("bits", a, 0)
        if got != a.bit_length():
            differ += 1
            bad.append("bits %x: %r want %d" % (a, got, a.bit_length()))
        for b in vals:
            for op, want in (("add", a + b), ("mul", a * b)):
                compared += 1
                got = run(op, a, b)
                if got != want:
                    differ += 1
                    bad.append("%s %x %x: got %r want %x"
                               % (op, a, b, got, want))
            compared += 1
            got = run("sub", a, b)
            if a >= b:
                if got != a - b:
                    differ += 1
                    bad.append("sub %x %x: got %r want %x" % (a, b, got, a - b))
            elif got is not None:
                differ += 1
                bad.append("sub %x %x: should have refused, got %r"
                           % (a, b, got))
            if b != 0:
                for op, want in (("div", a // b), ("rem", a % b)):
                    compared += 1
                    got = run(op, a, b)
                    if got != want:
                        differ += 1
                        bad.append("%s %x %x: got %r want %x"
                                   % (op, a, b, got, want))
    # Exponentiation, over a smaller cross product because each one is a
    # full square-and-multiply.
    mods = [3, 0xffffffff, 0x100000001, (1 << 128) - 159,
            (1 << 256) - 189, 0xdeadbeefcafebabe123456789abcdef1]
    exps = [0, 1, 2, 3, 65537, (1 << 64) - 1, (1 << 128) + 7]
    if len(sys.argv) > 1:
        for n in corpus_moduli(sys.argv[1]):
            mods.append(n)
    for m in mods:
        for a in [0, 1, 2, 7, m - 1, m // 2, (1 << 200) + 3]:
            for e in exps:
                compared += 1
                got = run("modexp", a, e, m)
                want = pow(a, e, m)
                if got != want:
                    differ += 1
                    bad.append("modexp %x %x %x: got %r want %x"
                               % (a, e, m, got, want))
    # Inversion modulo a prime, by Fermat. The primes are known Mersenne
    # and pseudo-Mersenne primes and the NIST curve primes.
    primes = [
        (1 << 61) - 1,
        (1 << 127) - 1,
        (1 << 255) - 19,
        (1 << 256) - (1 << 224) + (1 << 192) + (1 << 96) - 1,       # P-256
        (1 << 384) - (1 << 128) - (1 << 96) + (1 << 32) - 1,        # P-384
        (1 << 521) - 1,                                             # P-521
    ]
    for p in primes:
        for a in [1, 2, 3, 7, p - 1, p // 3, (1 << 100) + 1]:
            compared += 1
            got = run("invmod", a, 0, p)
            want = pow(a, -1, p)
            if got != want:
                differ += 1
                bad.append("invmod %x mod %x: got %r want %x"
                           % (a, p, got, want))
            compared += 1
            if got is not None and (got * a) % p != 1:
                differ += 1
                bad.append("invmod %x mod %x: product is not 1" % (a, p))
    # Knuth D's two correction steps. Removing the add-back after a
    # negative remainder is caught by the ordinary cases above, 53 of
    # them. Removing the qhat decrement loop was NOT: it survived the
    # whole set, because the estimate is one too big only about twice in
    # 2^32 steps. These three pairs were found by a random search run
    # against that mutant, and the seeded sweep after them keeps the path
    # covered as the value list changes.
    for u, v in (
        (0x78e4b98d4787f93bca44eb86, 0x8726e25cfd56a926),
        (0xb86bb4d6c713289150505652, 0xbbc55c33ec1072ee),
        (0xeb4acb49d653e980071cfbc9e7920c6d, 0x8d869707e71aeba50f2cc346),
    ):
        for op, want in (("div", u // v), ("rem", u % v)):
            compared += 1
            got = run(op, u, v)
            if got != want:
                differ += 1
                bad.append("%s %x %x: got %r want %x" % (op, u, v, got, want))

    import random
    rng = random.Random(20261021)
    for _ in range(3000):
        nl = rng.choice([2, 3, 4])
        v = rng.getrandbits(32 * nl) | (1 << (32 * nl - 1))
        u = rng.getrandbits(32 * (nl + 1))
        compared += 1
        got = run("div", u, v)
        if got != u // v:
            differ += 1
            bad.append("div %x %x: got %r want %x" % (u, v, got, u // v))

    for b in bad[:20]:
        print("  " + b)
    print("%d compared, %d differ" % (compared, differ))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
