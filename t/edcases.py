#!/usr/bin/env python3
"""The Ed25519 signatures that must NOT verify.

A verifier written from the verification equation alone passes every test
in the rest of this suite and still accepts all three of these. Each one
is a real signature, in the sense that the curve equation holds for it;
what is wrong is the encoding, and the rules that make an encoding unique
are in RFC 8032 section 8.4 rather than in the equation.

  S + L. Adding the group order to S leaves [S]B unchanged, because L
  times the base point is the identity. So the equation still holds and a
  verifier with no range check on S accepts it. The consequence is that
  every signature has a second spelling, which breaks anything using a
  signature as an identifier, and gives two certificates with the same
  meaning and different fingerprints.

  A non-canonical y. A public key whose y coordinate is y + p encodes the
  same curve point. A verifier that reduces instead of refusing gives one
  key two encodings and two fingerprints.

  A y with no square root. Then there is no point with that y at all, and
  a decoder that returns something anyway is verifying against a value
  that is not on the curve.

openssl is asked about each one too, over the same bytes, so that
"refused" is not just sshkeyv being broken in a convenient direction.
Where openssl and sshkeyv differ the difference is printed and counted,
not averaged away.

Usage: edcases.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
ED_SPKI = bytes.fromhex("302a300506032b6570032100")


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


def put(b):
    return struct.pack(">I", len(b)) + b


def find_cert(d):
    for name in sorted(os.listdir(d)):
        if not name.endswith("-cert.pub"):
            continue
        with open(os.path.join(d, name)) as f:
            parts = f.readline().split()
        blob = base64.b64decode(parts[1], validate=True)
        # The CA key type is what matters, so walk to signature_key.
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
        sig, o = sshstr(blob, o)
        caname, co = sshstr(cakey, 0)
        if caname != b"ssh-ed25519":
            continue
        capk, _ = sshstr(cakey, co)
        signame, so = sshstr(sig, 0)
        raw, _ = sshstr(sig, so)
        return parts[0], blob, tbs, cakey, capk, raw
    return None


def rebuild(algo, tbs, cakey, raw):
    blob = tbs[:len(tbs)]
    # tbs already ends with the CA key string, so only the signature is
    # appended. The CA key is substituted by rebuilding tbs when needed.
    return algo, blob + put(put(b"ssh-ed25519") + put(raw))


def swap_cakey(tbs, old_cakey, new_cakey):
    assert tbs.endswith(put(old_cakey))
    return tbs[:len(tbs) - len(put(old_cakey))] + put(new_cakey)


def write_cert(path, algo, blob):
    with open(path, "w") as f:
        f.write("%s %s edcase\n" % (algo, base64.b64encode(blob).decode()))


def sshkeyv(path):
    p = subprocess.run([BIN, "verify", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    return p.returncode, (p.stdout.decode() + p.stderr.decode()).strip()


def openssl_ok(capk, tbs, raw, work):
    der = os.path.join(work, "k.der")
    pem = os.path.join(work, "k.pem")
    with open(der, "wb") as f:
        f.write(ED_SPKI + capk)
    if subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                       "-in", der, "-out", pem],
                      stderr=subprocess.DEVNULL).returncode != 0:
        return None
    mf = os.path.join(work, "m.bin")
    sf = os.path.join(work, "s.bin")
    with open(mf, "wb") as f:
        f.write(tbs)
    with open(sf, "wb") as f:
        f.write(raw)
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                        "-inkey", pem, "-rawin", "-sigfile", sf, "-in", mf],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def y_without_sqrt():
    """A y for which (y^2-1)/(d y^2+1) is not a square, so no point has it."""
    for y in range(2, 500):
        v = (D * y * y + 1) % P
        if v == 0:
            continue
        u = (y * y - 1) % P
        xx = u * pow(v, -1, P) % P
        if pow(xx, (P - 1) // 2, P) != 1:
            return y
    raise AssertionError("no such y below 500, which cannot happen")


def main():
    d = sys.argv[1]
    work = os.path.join(d, "edwork")
    os.makedirs(work, exist_ok=True)
    found = find_cert(d)
    if found is None:
        print("  CORPUS GAP: no certificate signed by an ed25519 CA")
        print("0 cases, 0 refused, 0 accepted, 0 oracle differs")
        return 1
    algo, blob, tbs, cakey, capk, raw = found

    cases = []
    # The control. It must verify, or every refusal below is meaningless.
    cases.append(("control, unmodified", algo, blob, capk, tbs, raw, True,
                  None))

    # S + L.
    s = int.from_bytes(raw[32:], "little")
    assert s < L, "ssh-keygen wrote an unreduced S, which cannot happen"
    s2 = s + L
    raw2 = raw[:32] + s2.to_bytes(32, "little")
    a2, b2 = rebuild(algo, tbs, cakey, raw2)
    cases.append(("S + L, which leaves the equation true", a2, b2, capk,
                  tbs, raw2, False, "group order"))

    # A non-canonical y in the CA public key: y + p encodes the same point.
    #
    # Only a y below 19 can be respelled this way, because the encoding
    # has 255 bits for y and p is 2^255 - 19, so y + p fits only when
    # y < 19. The CA key's own y is far above that, and the first version
    # of this script therefore skipped the case entirely and reported
    # nothing missing. A small y that is on the curve is used instead: the
    # signature cannot verify against it, so what is asserted is the
    # REASON, which must name the encoding and not the equation.
    small = None
    for y in range(0, 19):
        v = (D * y * y + 1) % P
        if v == 0:
            continue
        xx = (y * y - 1) * pow(v, -1, P) % P
        if xx == 0 or pow(xx, (P - 1) // 2, P) == 1:
            small = y
            break
    assert small is not None, "no on-curve y below 19"
    pk2 = (small + P).to_bytes(32, "little")
    ck2 = put(b"ssh-ed25519") + put(pk2)
    tbs2 = swap_cakey(tbs, cakey, ck2)
    a3, b3 = rebuild(algo, tbs2, ck2, raw)
    cases.append(("the CA key's y is %d + p, a second spelling of an "
                  "on-curve point" % small, a3, b3, pk2, tbs2, raw, False,
                  "canonical"))

    # A y with no square root.
    yb = y_without_sqrt()
    pk3 = yb.to_bytes(32, "little")
    ck3 = put(b"ssh-ed25519") + put(pk3)
    tbs3 = swap_cakey(tbs, cakey, ck3)
    a4, b4 = rebuild(algo, tbs3, ck3, raw)
    cases.append(("the CA key's y = %d has no square root" % yb, a4, b4,
                  pk3, tbs3, raw, False, "square root"))

    refused = accepted = oracle_differs = wrong_reason = 0
    for label, a, b, capk_c, tbs_c, raw_c, want_good, reason in cases:
        path = os.path.join(work, "case.pub")
        write_cert(path, a, b)
        rc, out = sshkeyv(path)
        ok = rc == 0
        ow = openssl_ok(capk_c, tbs_c, raw_c, work)
        mark = "    "
        if ok == want_good:
            if want_good:
                refused += 0
            else:
                refused += 1
        else:
            if want_good:
                mark = "  CONTROL FAILED "
                accepted += 1
            else:
                mark = "  ACCEPTED "
                accepted += 1
        if not ok and reason is not None and reason not in out:
            wrong_reason += 1
            mark = "  WRONG REASON "
        agree = (ow is None) or (ow == ok)
        if not agree:
            oracle_differs += 1
        print("%s%s: sshkeyv %s, openssl %s%s"
              % (mark, label, "good" if ok else "refused",
                 {None: "could not be asked", True: "good",
                  False: "refused"}[ow],
                 "" if ok else " -- " + out.split(": ", 2)[-1]))
    print("%d cases, %d refused, %d wrong, %d wrong reason, "
          "%d oracle differs"
          % (len(cases), refused, accepted, wrong_reason, oracle_differs))
    return 1 if (accepted or wrong_reason) else 0


if __name__ == "__main__":
    sys.exit(main())
