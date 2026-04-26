#!/usr/bin/env python3
"""Bleichenbacher's low-exponent RSA signature forgery, built and refused.

This is the case a PKCS#1 v1.5 verifier written the obvious way accepts.
The obvious way is to recover the block, skip forward past the 0xff run,
and look for the DigestInfo. A verifier that does that can be given a
signature constructed with no private key at all: pick the block

    00 01 FF 00 <DigestInfo> <anything>

take its integer cube root rounded up, and cube it again. The cube is at
most about 3s^2 above the chosen block, which for a 3072-bit modulus
leaves the low 2000-odd bits free to be anything, and the DigestInfo sits
well above that. So the recovered block has the right digest in roughly
the right place, one 0xff byte of padding instead of three hundred, and
rubbish after it.

Daniel Bleichenbacher described this at Crypto 2006 and it broke several
implementations, including ones in widely used libraries. The forgery needs
the public exponent to be small, which 3 is and 65537 is not, and e = 3
keys are still in use.

So the test is: build a real forgery against a real e = 3 key, confirm the
block really does have the digest where a lenient verifier would find it,
and require sshkeyv to refuse it. openssl is asked too.

A 512-bit modulus is also put to sshkeyv, which must refuse it for being
too small before doing any arithmetic.

Usage: forge.py CORPUSDIR
"""
import base64
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")
SHA256_DI_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def put(b):
    return struct.pack(">I", len(b)) + b


def mpint(v):
    if v == 0:
        return put(b"")
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return put(b)


def icbrt(n):
    """Integer cube root, rounded down."""
    if n < 0:
        raise ValueError
    x = 1 << ((n.bit_length() + 2) // 3 + 1)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def rsa_pub_from_openssl(work, bits, e):
    """Generate an RSA key with openssl and return (n, e). The private key
    is written into the work directory and never leaves it; the work
    directory is inside the corpus, which the suite deletes."""
    key = os.path.join(work, "k.pem")
    p = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA",
         "-pkeyopt", "rsa_keygen_bits:%d" % bits,
         "-pkeyopt", "rsa_keygen_pubexp:%d" % e,
         "-out", key],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if p.returncode != 0:
        return None
    t = subprocess.run(["openssl", "rsa", "-in", key, "-noout", "-text"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if t.returncode != 0:
        return None
    text = t.stdout.decode()
    # The modulus is the hex block after "modulus:".
    lines = text.splitlines()
    mod = []
    collecting = False
    for ln in lines:
        if ln.startswith("modulus:"):
            collecting = True
            continue
        if collecting:
            if not ln.startswith("    "):
                break
            mod.append(ln.strip())
    n = int("".join(mod).replace(":", ""), 16)
    return n, e


def cert_blob(capub_blob, sig_blob, subject_blob, keyid):
    """A minimal ed25519 user certificate with a given CA key and
    signature. Everything before the signature is what the signature
    covers."""
    nonce = b"\x11" * 32
    o = 0
    name, o = sshstr(subject_blob, 0)
    pk, o = sshstr(subject_blob, o)
    body = (put(b"ssh-ed25519-cert-v01@openssh.com")
            + put(nonce)
            + put(pk)
            + struct.pack(">Q", 7)
            + struct.pack(">I", 1)
            + put(keyid.encode())
            + put(put(b"alice"))
            + struct.pack(">Q", 0)
            + struct.pack(">Q", 2 ** 64 - 1)
            + put(b"")
            + put(b"")
            + put(b"")
            + put(capub_blob))
    return body, body + put(sig_blob)


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


def main():
    d = sys.argv[1]
    work = os.path.join(d, "forgework")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(d, "ed25519.pub")) as f:
        subject = base64.b64decode(f.readline().split()[1], validate=True)

    results = []

    kp = rsa_pub_from_openssl(work, 3072, 3)
    if kp is None:
        print("  openssl would not generate an e = 3 key; the forgery case "
              "cannot be built and is NOT being counted as a pass")
        return 1
    n, e = kp
    k = (n.bit_length() + 7) // 8
    capub = put(b"ssh-rsa") + mpint(e) + mpint(n)

    # The signature blob's length must be right, so the body is built once
    # with a placeholder of the correct size to learn the signed bytes.
    placeholder = put(b"rsa-sha2-256") + put(b"\x00" * k)
    body, _ = cert_blob(capub, placeholder, subject, "forged")
    digest = hashlib.sha256(body).digest()

    # 00 01 FF 00 DigestInfo, then as many free bytes as the modulus allows.
    di = SHA256_DI_PREFIX + digest
    head = b"\x00\x01\xff\x00" + di
    target = int.from_bytes(head + b"\x00" * (k - len(head)), "big")
    s = icbrt(target)
    if s ** 3 < target:
        s += 1
    cube = s ** 3
    assert cube >= target
    assert cube < n, "the cube must be below the modulus"
    recovered = cube.to_bytes(k, "big")
    # The forgery is only interesting if the block really does hold the
    # DigestInfo where a lenient verifier would look for it. Asserted here,
    # so that a refusal cannot be credited to a forgery that was never
    # built.
    assert recovered[:4] == b"\x00\x01\xff\x00", recovered[:8].hex()
    assert recovered[4:4 + len(di)] == di, "the DigestInfo is not intact"
    print("    the forged block is %s... with the DigestInfo at byte 4 and "
          "%d free bytes after it"
          % (recovered[:8].hex(), k - 4 - len(di)))

    forged_sig = put(b"rsa-sha2-256") + put(s.to_bytes(k, "big"))
    _, blob = cert_blob(capub, forged_sig, subject, "forged")
    path = os.path.join(work, "forged-cert.pub")
    with open(path, "w") as f:
        f.write("ssh-ed25519-cert-v01@openssh.com %s forged\n"
                % base64.b64encode(blob).decode())
    p = subprocess.run([BIN, "verify", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    out = (p.stdout.decode() + p.stderr.decode()).strip()
    results.append(("Bleichenbacher forgery against an e = 3 key",
                    p.returncode != 0, out))

    # openssl over the same bytes.
    pem = os.path.join(work, "ca.pem")
    pub = os.path.join(work, "ca.pub")
    with open(pub, "w") as f:
        f.write("ssh-rsa %s\n" % base64.b64encode(capub).decode())
    c = subprocess.run(["ssh-keygen", "-e", "-m", "pkcs8", "-f", pub],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    ossl = None
    if c.returncode == 0:
        with open(pem, "wb") as f:
            f.write(c.stdout)
        with open(os.path.join(work, "m.bin"), "wb") as f:
            f.write(body)
        with open(os.path.join(work, "s.bin"), "wb") as f:
            f.write(s.to_bytes(k, "big"))
        o = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pem,
                            "-signature", os.path.join(work, "s.bin"),
                            os.path.join(work, "m.bin")],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        ossl = o.returncode == 0
    print("    openssl's verdict on the forgery: %s"
          % {None: "could not be asked", True: "GOOD", False: "refused"}[ossl])
    if ossl:
        results.append(("openssl accepts the forgery", False,
                        "which would mean the forgery is valid"))

    # A 512-bit modulus. It need not be a real RSA key: the refusal must
    # happen on the size, before any arithmetic.
    small_n = (1 << 511) | 1
    capub2 = put(b"ssh-rsa") + mpint(3) + mpint(small_n)
    ph = put(b"rsa-sha2-256") + put(b"\x00" * 64)
    _, blob2 = cert_blob(capub2, ph, subject, "small")
    path2 = os.path.join(work, "small-cert.pub")
    with open(path2, "w") as f:
        f.write("ssh-ed25519-cert-v01@openssh.com %s small\n"
                % base64.b64encode(blob2).decode())
    p2 = subprocess.run([BIN, "verify", path2], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
    out2 = (p2.stdout.decode() + p2.stderr.decode()).strip()
    results.append(("a 512-bit modulus", p2.returncode != 0
                    and "below 1024 bits" in out2, out2))

    refused = 0
    wrong = 0
    for label, good, why in results:
        if good:
            refused += 1
            print("    refused: %s -- %s" % (label, why.split(": ", 2)[-1]))
        else:
            wrong += 1
            print("  NOT REFUSED: %s -- %s" % (label, why))
    print("%d cases, %d refused, %d wrong" % (len(results), refused, wrong))
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
