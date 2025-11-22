#!/usr/bin/env python3
"""SHA-256, SHA-512 and MD5 against the coreutils tools and hashlib.

Lengths 0 to 200 inclusive, plus 1000 and 100000. The interesting ones are
the padding boundaries: 55, 56 and 57 for SHA-256 and 111, 112 and 113 for
SHA-512, where the length counter does or does not fit in the last block
and an extra block appears. A digest tested only on key-sized inputs
cannot see a defect that needs one of those lengths. MD5 writes its
length little-endian where the other two write it big-endian, so the same
boundaries test a different line of code there.

Prints "N compared, M differ" and exits non-zero on a disagreement.
"""
import hashlib
import os
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")

LENGTHS = list(range(0, 201)) + [1000, 100000]


def main():
    compared = differ = 0
    bad = []
    for alg, sumtool in (("sha256", "sha256sum"), ("sha512", "sha512sum"),
                         ("md5", "md5sum")):
        for n in LENGTHS:
            data = bytes((i * 101 + n * 7) % 256 for i in range(n))
            got = subprocess.run([BIN, "hash", alg], input=data,
                                 stdout=subprocess.PIPE).stdout.decode().strip()
            want = subprocess.run([sumtool], input=data,
                                  stdout=subprocess.PIPE
                                  ).stdout.decode().split()[0]
            lib = hashlib.new(alg, data).hexdigest()
            compared += 1
            if want != lib:
                bad.append("%s %d: %s and hashlib disagree" % (alg, n, sumtool))
                differ += 1
            elif got != want:
                differ += 1
                bad.append("%s %d: got %s want %s" % (alg, n, got, want))
    for b in bad[:20]:
        print("  " + b)
    print("%d compared, %d differ" % (compared, differ))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
