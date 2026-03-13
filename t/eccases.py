#!/usr/bin/env python3
"""The ECDSA signatures and keys that must NOT verify.

Same class of case as t/edcases.py, different arithmetic. Each one is
built from a real certificate signed by an ECDSA CA, so the control at the
top of the list must verify or none of the refusals mean anything.

  r = 0 and s = 0. Both are outside [1, n-1] and both give an equation
  that a verifier can satisfy by accident: with s = 0 the inverse does not
  exist, and a verifier that computes it anyway is computing with
  rubbish.

  r = n and s = n. Reducing instead of refusing gives r = 0 again.

  r + n and s + n, where those fit in the same mpint. Unlike Ed25519's
  S + L this does NOT leave the equation true, because r is compared
  directly rather than used as a scalar; the case is here because a
  verifier that reduces r modulo n before comparing would accept it.

  A public point whose coordinates are not on the curve, and one whose x
  is at or above the field prime.

openssl is asked about each one over the same bytes. Where openssl cannot
be driven, because the DER signature cannot be formed from the bytes, that
is counted apart from openssl giving a verdict.

Each case also carries the reason sshkeyv must give. That is not
decoration: three of these four checks are not needed for the VERDICT,
because the verification equation refuses the signature anyway, and
asserting only the exit status left three mutants alive.

Usage: eccases.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")

ORDERS = {
    "nistp256": 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    "nistp384": int("ffffffffffffffffffffffffffffffffffffffffffffffff"
                    "c7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
    "nistp521": int("01fffffffffffffffffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffa51868783bf2f966b7fcc0148f709a5"
                    "d03bb5c9b8899c47aebb6fb71e91386409", 16),
}
PRIMES = {
    "nistp256": 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1,
    "nistp384": 2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1,
    "nistp521": 2 ** 521 - 1,
}


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


def put(b):
    return struct.pack(">I", len(b)) + b


def mpint(v):
    if v == 0:
        return put(b"")
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return put(b)


def find(d):
    """A certificate signed by an ECDSA CA, with its pieces."""
    for name in sorted(os.listdir(d)):
        if not name.endswith("-cert.pub"):
            continue
        with open(os.path.join(d, name)) as f:
            parts = f.readline().split()
        blob = base64.b64decode(parts[1], validate=True)
        n, o = sshstr(blob, 0)
        plain = n.decode()[:-len("-cert-v01@openssh.com")]
        _, o = sshstr(blob, o)
        for _ in range({"ssh-ed25519": 1, "ssh-rsa": 2}.get(plain, 2)):
            _, o = sshstr(blob, o)
        o += 12
        for _ in range(2):
            _, o = sshstr(blob, o)
        o += 16
        for _ in range(3):
            _, o = sshstr(blob, o)
        cakey, o = sshstr(blob, o)
        tbs = blob[:o]
        sig, _ = sshstr(blob, o)
        caname, co = sshstr(cakey, 0)
        caname = caname.decode()
        if not caname.startswith("ecdsa-sha2-"):
            continue
        curve_name, co2 = sshstr(cakey, co)
        capoint, _ = sshstr(cakey, co2)
        signame, so = sshstr(sig, 0)
        raw, _ = sshstr(sig, so)
        r, ro = sshstr(raw, 0)
        s, _ = sshstr(raw, ro)
        yield (parts[0], blob, tbs, cakey, caname,
               curve_name.decode(), capoint,
               int.from_bytes(r, "big"), int.from_bytes(s, "big"))


def rebuild_sig(tbs, caname, r, s):
    return tbs + put(put(caname.encode()) + put(mpint(r) + mpint(s)))


def swap_cakey(tbs, old, new):
    assert tbs.endswith(put(old))
    return tbs[:len(tbs) - len(put(old))] + put(new)


def sshkeyv(path):
    p = subprocess.run([BIN, "verify", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    return p.returncode, (p.stdout.decode() + p.stderr.decode()).strip()


def main():
    d = sys.argv[1]
    work = os.path.join(d, "ecwork")
    os.makedirs(work, exist_ok=True)
    seen = list(find(d))
    if not seen:
        print("  CORPUS GAP: no certificate signed by an ECDSA CA")
        print("0 cases, 0 refused, 0 wrong")
        return 1
    curves = sorted({x[5] for x in seen})
    print("  ECDSA CA curves in the corpus: %s" % " ".join(curves))
    cases = 0
    refused = 0
    wrong = 0
    for (algo, blob, tbs, cakey, caname, curve, capoint, r,
         s) in seen:
        n = ORDERS[curve]
        p = PRIMES[curve]
        w = (p.bit_length() + 7) // 8
        # The expected REASON is part of each case, not just the exit
        # status, and that is what makes the checks load-bearing. Three of
        # the four range and curve checks survived mutation when only the
        # status was asserted: a signature with s = 0, a point off the
        # curve and an x equal to the field prime are all refused anyway,
        # by the verification equation or by the identity test, so
        # deleting the specific check changed nothing a status could see.
        # What it changed was the message, and a verifier whose message
        # says the equation failed when the key is malformed sends the
        # reader after the wrong thing.
        variants = [
            ("control", blob, True, None),
            ("r = 0", rebuild_sig(tbs, caname, 0, s), False,
             "equal to zero"),
            ("s = 0", rebuild_sig(tbs, caname, r, 0), False,
             "equal to zero"),
            ("r = n", rebuild_sig(tbs, caname, n, s), False,
             "at or above the group order"),
            ("s = n", rebuild_sig(tbs, caname, r, n), False,
             "at or above the group order"),
            ("r + n", rebuild_sig(tbs, caname, r + n, s), False,
             "at or above the group order"),
            ("s + n", rebuild_sig(tbs, caname, r, s + n), False,
             "at or above the group order"),
        ]
        # A point not on the curve: flip the low bit of y.
        bad_y = bytearray(capoint)
        bad_y[-1] ^= 1
        ck = put(caname.encode()) + put(curve.encode()) + put(bytes(bad_y))
        variants.append(("CA point not on the curve",
                         rebuild_sig(swap_cakey(tbs, cakey, ck), caname, r, s),
                         False, "not on the curve"))
        # A point whose x is p, which is not a field element.
        bad_x = bytes([4]) + p.to_bytes(w, "big") + capoint[1 + w:]
        ck2 = put(caname.encode()) + put(curve.encode()) + put(bad_x)
        variants.append(("CA point x equals the field prime",
                         rebuild_sig(swap_cakey(tbs, cakey, ck2), caname, r, s),
                         False, "not less than the field prime"))
        for label, b, want_good, reason in variants:
            path = os.path.join(work, "case.pub")
            with open(path, "w") as f:
                f.write("%s %s eccase\n"
                        % (algo, base64.b64encode(b).decode()))
            rc, out = sshkeyv(path)
            ok = rc == 0
            cases += 1
            if ok == want_good and not want_good and reason not in out:
                wrong += 1
                print("  WRONG REASON %s/%s: %s"
                      % (curve, label, out.split(": ", 2)[-1]))
            elif ok == want_good:
                if not want_good:
                    refused += 1
            else:
                wrong += 1
                print("  %s %s/%s: sshkeyv says %s -- %s"
                      % ("CONTROL FAILED" if want_good else "ACCEPTED",
                         curve, label, "good" if ok else "refused",
                         out.split(": ", 2)[-1]))
    gap = len(curves) < 3
    if gap:
        print("  CORPUS GAP: fewer than three ECDSA CA curves")
    print("%d cases, %d refused, %d wrong" % (cases, refused, wrong))
    return 1 if (wrong or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
