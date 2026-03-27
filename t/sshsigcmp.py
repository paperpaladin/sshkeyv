#!/usr/bin/env python3
"""Detached SSHSIG signatures against ssh-keygen -Y and against openssl.

Two oracles with different strengths. ssh-keygen -Y verify is OpenSSH's
own answer, including its view of the namespace and of whether the signer
is allowed. openssl is given the signed blob this script reconstructs from
the format specification, so it checks the arithmetic with no OpenSSH in
the path; if sshkeyv and openssl agreed while ssh-keygen disagreed, the
reconstruction would be wrong rather than the verifier.

The namespace is the case worth having. It is inside the signed blob, so a
verifier that reads it out of the file and then signs over what it read
accepts a signature made for any purpose at all: a signature over a commit
would verify as a signature over an email. So every signature is also
checked against the WRONG namespace, and all three must refuse.

Counts: compared, agree, differ, refused-by-all. Refusals are counted
apart from disagreements.

Usage: sshsigcmp.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")
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


def pem_body(path, label):
    with open(path) as f:
        text = f.read()
    lines = []
    seen = False
    for l in text.splitlines():
        if l.startswith("-----BEGIN " + label):
            seen = True
            continue
        if l.startswith("-----END "):
            break
        if seen:
            lines.append(l.strip())
    return base64.b64decode("".join(lines), validate=True)


def parse_sshsig(b):
    assert b[:6] == b"SSHSIG"
    o = 6
    (ver,) = struct.unpack(">I", b[o:o + 4]); o += 4
    pk, o = sshstr(b, o)
    ns, o = sshstr(b, o)
    res, o = sshstr(b, o)
    ha, o = sshstr(b, o)
    sig, o = sshstr(b, o)
    assert o == len(b)
    return ver, pk, ns.decode(), res, ha.decode(), sig


def signed_blob(ns, res, ha, msg):
    import hashlib
    h = hashlib.new(ha, msg).digest()
    return (b"SSHSIG" + put(ns.encode()) + put(res) + put(ha.encode())
            + put(h))


def armour(body):
    b64 = base64.b64encode(body).decode()
    out = ["-----BEGIN SSH SIGNATURE-----"]
    for i in range(0, len(b64), 70):
        out.append(b64[i:i + 70])
    out.append("-----END SSH SIGNATURE-----")
    return "\n".join(out) + "\n"


def openssl_ok(pk, sig_blob, blob, work):
    name, o = sshstr(pk, 0)
    name = name.decode()
    pem = os.path.join(work, "k.pem")
    if name == "ssh-ed25519":
        raw, _ = sshstr(pk, o)
        der = os.path.join(work, "k.der")
        with open(der, "wb") as f:
            f.write(ED_SPKI + raw)
        if subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                           "-in", der, "-out", pem],
                          stderr=subprocess.DEVNULL).returncode != 0:
            return None
    else:
        pub = os.path.join(work, "k.pub")
        with open(pub, "w") as f:
            f.write("%s %s\n" % (name, base64.b64encode(pk).decode()))
        p = subprocess.run(["ssh-keygen", "-e", "-m", "pkcs8", "-f", pub],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if p.returncode != 0:
            return None
        with open(pem, "wb") as f:
            f.write(p.stdout)
    try:
        salg, so = sshstr(sig_blob, 0)
        raw, _ = sshstr(sig_blob, so)
        salg = salg.decode()
    except Exception:
        return None
    mf = os.path.join(work, "m.bin")
    sf = os.path.join(work, "s.bin")
    with open(mf, "wb") as f:
        f.write(blob)
    if name == "ssh-ed25519":
        with open(sf, "wb") as f:
            f.write(raw)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                            "-inkey", pem, "-rawin", "-sigfile", sf,
                            "-in", mf],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return r.returncode == 0
    if name == "ssh-rsa":
        digest = {"ssh-rsa": "-sha1", "rsa-sha2-256": "-sha256",
                  "rsa-sha2-512": "-sha512"}.get(salg)
        if digest is None:
            return None
        with open(sf, "wb") as f:
            f.write(raw)
    elif name.startswith("ecdsa-sha2-"):
        try:
            r1, o2 = sshstr(raw, 0)
            s1, _ = sshstr(raw, o2)
        except Exception:
            return None
        digest = {"nistp256": "-sha256", "nistp384": "-sha384",
                  "nistp521": "-sha512"}[name[len("ecdsa-sha2-"):]]
        with open(sf, "wb") as f:
            f.write(der_sig(r1, s1))
    else:
        return None
    r = subprocess.run(["openssl", "dgst", digest, "-verify", pem,
                        "-signature", sf, mf],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_int(v):
    v = v.lstrip(b"\x00") or b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return b"\x02" + der_len(len(v)) + v


def der_sig(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + der_len(len(body)) + body


def keygen_verify(sigpath, ns, msgpath, keyline, work):
    signers = os.path.join(work, "signers")
    with open(signers, "w") as f:
        f.write("signer@example.com %s\n" % " ".join(keyline.split()[:2]))
    with open(msgpath, "rb") as f:
        msg = f.read()
    p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", signers,
                        "-I", "signer@example.com", "-n", ns,
                        "-s", sigpath],
                       input=msg, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    return p.returncode == 0


def sshkeyv_verify(sigpath, ns, keypath, msgpath):
    cmd = [BIN, "sigverify", "-s", sigpath, "-n", ns, msgpath]
    if keypath:
        cmd += ["--key", keypath]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, (p.stdout.decode() + p.stderr.decode()).strip()


def main():
    d = sys.argv[1]
    work = os.path.join(d, "sswork")
    os.makedirs(work, exist_ok=True)
    compared = agree = differ = refused_all = 0
    bad = []
    hashalgs = set()
    keytypes = set()
    sigs = [n for n in sorted(os.listdir(d)) if n.endswith(".sig")]
    for name in sigs:
        sigpath = os.path.join(d, name)
        body = pem_body(sigpath, "SSH SIGNATURE")
        ver, pk, ns, res, ha, sigb = parse_sshsig(body)
        hashalgs.add(ha)
        kname, _ = sshstr(pk, 0)
        keytypes.add(kname.decode())
        # The message is named in the corpus by the signature's own name.
        msgname = ("msg_empty" if name.endswith("_empty.sig")
                   else "msg_big" if name.endswith("_big.sig") else "msg")
        msgpath = os.path.join(d, msgname)
        keypath = os.path.join(d, name.split("_")[1] + ".pub")
        with open(keypath) as f:
            keyline = f.readline().strip()
        with open(msgpath, "rb") as f:
            msg = f.read()

        cases = [
            ("correct", sigpath, ns, msgpath, True),
            ("wrong namespace", sigpath,
             "other" if ns != "other" else "file", msgpath, False),
            ("wrong message", sigpath, ns,
             os.path.join(d, "msg_big" if msgname != "msg_big" else "msg"),
             False),
        ]
        # One bit flipped in the raw signature.
        salg, so = sshstr(sigb, 0)
        raw, _ = sshstr(sigb, so)
        m = bytearray(raw)
        m[len(m) // 2] ^= 1
        bad_sigb = put(salg) + put(bytes(m))
        bad_body = (b"SSHSIG" + struct.pack(">I", ver) + put(pk) + put(
            ns.encode()) + put(res) + put(ha.encode()) + put(bad_sigb))
        bpath = os.path.join(work, "bad.sig")
        with open(bpath, "w") as f:
            f.write(armour(bad_body))
        cases.append(("one bit flipped in the signature", bpath, ns,
                      msgpath, False))

        for label, sp, cns, mp, want in cases:
            with open(mp, "rb") as f:
                cmsg = f.read()
            cbody = pem_body(sp, "SSH SIGNATURE")
            _, cpk, cns_file, cres, cha, csigb = parse_sshsig(cbody)
            blob = signed_blob(cns_file, cres, cha, cmsg)
            ow = openssl_ok(cpk, csigb, blob, work)
            # openssl is only asked about the arithmetic, so it has no
            # opinion about the namespace being the wrong one: its verdict
            # for that case is good, and that is exactly the point.
            kv = keygen_verify(sp, cns, mp, keyline, work)
            rc, out = sshkeyv_verify(sp, cns, keypath, mp)
            ok = rc == 0
            compared += 1
            if ok == kv == want:
                agree += 1
                if not want:
                    refused_all += 1
            else:
                differ += 1
                bad.append("%s %s: sshkeyv %s, ssh-keygen %s, openssl %s, "
                           "wanted %s -- %s"
                           % (name, label, ok, kv, ow, want,
                              out.splitlines()[-1] if out else ""))
            if label != "wrong namespace" and ow is not None and ow != want:
                differ += 1
                bad.append("%s %s: openssl says %s, wanted %s"
                           % (name, label, ow, want))
    for b in bad[:20]:
        print("  " + b)
    print("  %d signature files, hash algorithms %s, key types %s"
          % (len(sigs), " ".join(sorted(hashalgs)),
             " ".join(sorted(keytypes))))
    gap = len(hashalgs) < 2 or len(keytypes) < 3 or not sigs
    if gap:
        print("  CORPUS GAP: need both hash algorithms and three key types")
    print("%d compared, %d agree, %d differ, %d refused by all"
          % (compared, agree, differ, refused_all))
    return 1 if (differ or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
