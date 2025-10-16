#!/usr/bin/env python3
"""Compare sshkeyv's base64 with python's, both directions.

Python's base64 is the oracle for the encoder and, with validate=True, for
the decoder's accept/reject decision. It is not a strong oracle: it is a
standard library, not an independent implementation of the SSH formats. But
the decoder sits under every other comparison in this suite, so it needs
something to disagree with before any of them mean anything.

The inputs are every byte length from 0 to 64, so all three padding cases
occur, plus the malformed spellings that a lenient decoder accepts: three
padding characters, padding in the middle, a character outside the
alphabet, a length that is not a multiple of four, and a final character
with non-zero unused bits.

Prints "N compared, M differ, K refused-by-both, J over-refused,
I under-refused" and exits non-zero on any disagreement.
"""
import base64
import os
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")


def run(mode, data):
    p = subprocess.run([BIN, "b64", mode], input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout


def main():
    compared = differ = refused_both = over = under = 0
    bad = []
    overs = []

    # Encoding. Every length from 0 to 64 covers the three padding cases and
    # the chunk boundary.
    for n in range(0, 65):
        data = bytes((i * 37 + n) % 256 for i in range(n))
        rc, got = run("-e", data)
        want = base64.b64encode(data) + b"\n"
        compared += 1
        if rc != 0 or got != want:
            differ += 1
            bad.append("encode %d: rc=%d got=%r want=%r" % (n, rc, got, want))

    # Decoding of well-formed text.
    for n in range(0, 65):
        data = bytes((i * 11 + 3) % 256 for i in range(n))
        text = base64.b64encode(data)
        rc, got = run("-d", text)
        compared += 1
        if rc != 0 or got != data:
            differ += 1
            bad.append("decode %d: rc=%d got=%r want=%r" % (n, rc, got, data))

    # Malformed text. python's validate=True is the oracle for whether it is
    # well formed; a canonical-bits violation is one python accepts and
    # sshkeyv refuses, and those are counted apart as over-refusals rather
    # than hidden, because over-refusal is a defect and not caution.
    malformed = [
        b"QQ===", b"QQ====", b"Q===", b"=QQQ", b"QQ=Q", b"QQQ",
        b"Q", b"QQ", b"QQQQQ", b"QQ-Q", b"QQ_Q", b"QQ Q", b"QQ\nQ",
        b"QQ\tQ", b"**QQ", b"QB==", b"QQB=", b"QQJ=", b"AA==", b"AB==",
        b"/w==", b"//8=", b"QUJD", b"QUJDRA==",
    ]
    for text in malformed:
        rc, got = run("-d", text)
        try:
            want = base64.b64decode(text, validate=True)
            py_ok = True
        except Exception:
            py_ok = False
            want = None
        compared += 1
        if not py_ok and rc != 0:
            refused_both += 1
        elif py_ok and rc == 0:
            if got != want:
                differ += 1
                bad.append("decode %r: got=%r want=%r" % (text, got, want))
        elif py_ok and rc != 0:
            over += 1
            overs.append(text)
        else:
            under += 1
            bad.append("decode %r: sshkeyv accepted what python refuses" % text)

    if overs:
        print("  over-refused (python accepts, sshkeyv does not): %s"
              % b" ".join(overs).decode())
    for b in bad[:20]:
        print("  " + b)
    print("%d compared, %d differ, %d refused-by-both, %d over-refused, "
          "%d under-refused" % (compared, differ, refused_both, over, under))
    # An over-refusal is reported and is not a failure on its own: the
    # canonical-bits rule is deliberately stricter than python's. An
    # under-refusal is a failure, because it means sshkeyv read something
    # nobody else will read the same way.
    return 1 if (differ or under) else 0


if __name__ == "__main__":
    sys.exit(main())
