#!/usr/bin/env python3
"""Certificate CA signatures against openssl, with OpenSSH out of the loop.

openssl is the oracle that matters here. It does the signature arithmetic
with no OpenSSH code in the path at all: the signed region and the
signature are pulled out of the certificate by this script, the CA public
key is converted to a SubjectPublicKeyInfo, and `openssl dgst -verify` or
`openssl pkeyutl -verify -rawin` gives the verdict. ssh-keygen is not
asked, because ssh-keygen wrote these signatures and a program agreeing
with itself proves nothing.

Three key types need three routes to a SubjectPublicKeyInfo:

  RSA and ECDSA: ssh-keygen -e -m pkcs8 converts the public key. That does
  put ssh-keygen back in the path, but only as a format converter, and the
  conversion is checked separately against sshkeyv's own PKCS8 writer.

  Ed25519: ssh-keygen refuses to convert it, so the 12-byte
  SubjectPublicKeyInfo prefix is prepended here. It is a constant:
  SEQUENCE, SEQUENCE, OID 1.3.101.112, BIT STRING of 33 bytes.

Every signature is then corrupted, one bit at a time at several
positions, and both sshkeyv and openssl must refuse. A corrupted
signature reported as good is a failed project. Refusals are counted
apart from disagreements, always.

Usage: sigcmp.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def sshstr(b, o):
    # The length check is not decoration. Python slicing past the end
    # returns a short slice silently, so without it a corrupted length
    # field reads as the same bytes as the original and this script tells
    # you openssl accepted a corruption it never saw. That happened once,
    # on the P-521 certificate, where a flipped bit in a length prefix
    # read back as the same 66-byte value.
    if len(b) - o < 4:
        raise ValueError("no room for a length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("string at %d claims %d bytes, %d left"
                         % (o, n, len(b) - o - 4))
    return b[o + 4:o + 4 + n], o + 4 + n


def split_cert(blob):
    """(tbs, ca_key_blob, sig_blob)."""
    name, o = sshstr(blob, 0)
    plain = name.decode()[:-len("-cert-v01@openssh.com")]
    _, o = sshstr(blob, o)                      # nonce
    nmat = {"ssh-ed25519": 1, "ssh-rsa": 2}.get(plain, 2)
    for _ in range(nmat):
        _, o = sshstr(blob, o)
    o += 8 + 4                                   # serial, type
    for _ in range(2):                           # key id, principals
        _, o = sshstr(blob, o)
    o += 16                                      # valid after, valid before
    for _ in range(3):                           # critical, ext, reserved
        _, o = sshstr(blob, o)
    cakey, o = sshstr(blob, o)
    tbs = blob[:o]
    sig, o = sshstr(blob, o)
    assert o == len(blob)
    return tbs, cakey, sig


def spki(cakey, work):
    """A PEM SubjectPublicKeyInfo for a CA key blob, or None."""
    name, o = sshstr(cakey, 0)
    name = name.decode()
    pem = os.path.join(work, "ca.pem")
    if name == "ssh-ed25519":
        pk, _ = sshstr(cakey, o)
        der = os.path.join(work, "ca.der")
        with open(der, "wb") as f:
            f.write(ED25519_SPKI_PREFIX + pk)
        p = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER",
                            "-in", der, "-out", pem],
                           stderr=subprocess.DEVNULL)
        return pem if p.returncode == 0 else None
    pub = os.path.join(work, "ca.pub")
    with open(pub, "w") as f:
        f.write("%s %s\n" % (name, base64.b64encode(cakey).decode()))
    p = subprocess.run(["ssh-keygen", "-e", "-m", "pkcs8", "-f", pub],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        return None
    with open(pem, "wb") as f:
        f.write(p.stdout)
    return pem


def openssl_verify(pem, cakey_name, sig_blob, tbs, work):
    """True, False, or None when openssl cannot be driven on this input.

    None rather than False for a signature blob that will not parse: that
    is this script failing to form a question, not openssl answering one,
    and the two must not be mixed."""
    try:
        return _openssl_verify(pem, cakey_name, sig_blob, tbs, work)
    except Exception:
        return None


def _openssl_verify(pem, cakey_name, sig_blob, tbs, work):
    sigalg, o = sshstr(sig_blob, 0)
    sigalg = sigalg.decode()
    raw, _ = sshstr(sig_blob, o)
    tbsf = os.path.join(work, "tbs.bin")
    with open(tbsf, "wb") as f:
        f.write(tbs)
    sigf = os.path.join(work, "sig.bin")
    if cakey_name == "ssh-ed25519":
        with open(sigf, "wb") as f:
            f.write(raw)
        p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                            "-inkey", pem, "-rawin", "-sigfile", sigf,
                            "-in", tbsf],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return p.returncode == 0
    if cakey_name == "ssh-rsa":
        digest = {"ssh-rsa": "-sha1", "rsa-sha2-256": "-sha256",
                  "rsa-sha2-512": "-sha512"}.get(sigalg)
        if digest is None:
            return None
        with open(sigf, "wb") as f:
            f.write(raw)
        p = subprocess.run(["openssl", "dgst", digest, "-verify", pem,
                            "-signature", sigf, tbsf],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return p.returncode == 0
    if cakey_name.startswith("ecdsa-sha2-"):
        # The SSH form is two mpints; openssl wants a DER SEQUENCE of two
        # INTEGERs.
        r, o2 = sshstr(raw, 0)
        s, o2 = sshstr(raw, o2)
        der = der_ecdsa_sig(r, s)
        with open(sigf, "wb") as f:
            f.write(der)
        digest = {"nistp256": "-sha256", "nistp384": "-sha384",
                  "nistp521": "-sha512"}[cakey_name[len("ecdsa-sha2-"):]]
        p = subprocess.run(["openssl", "dgst", digest, "-verify", pem,
                            "-signature", sigf, tbsf],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        return p.returncode == 0
    return None


def der_int(v):
    v = v.lstrip(b"\x00") or b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return b"\x02" + der_len(len(v)) + v


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_ecdsa_sig(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + der_len(len(body)) + body


def sshkeyv_verify(path):
    p = subprocess.run([BIN, "verify", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    return p.returncode, p.stdout.decode().strip()


def write_cert(path, algo, blob, comment="x"):
    with open(path, "w") as f:
        f.write("%s %s %s\n" % (algo, base64.b64encode(blob).decode(),
                                comment))


def main():
    d = sys.argv[1]
    work = os.path.join(d, "sigwork")
    os.makedirs(work, exist_ok=True)
    compared = agree = differ = noverifier = 0
    corrupt_total = corrupt_refused = corrupt_accepted = 0
    oracle_silent = 0
    bad = []
    by_ca = {}
    for name in sorted(os.listdir(d)):
        if not name.endswith("-cert.pub"):
            continue
        path = os.path.join(d, name)
        with open(path) as f:
            parts = f.readline().split()
        algo = parts[0]
        blob = base64.b64decode(parts[1], validate=True)
        tbs, cakey, sigb = split_cert(blob)
        caname, _ = sshstr(cakey, 0)
        caname = caname.decode()
        by_ca[caname] = by_ca.get(caname, 0) + 1
        pem = spki(cakey, work)
        if pem is None:
            oracle_silent += 1
            bad.append("%s: could not build a SubjectPublicKeyInfo for %s"
                       % (name, caname))
            continue
        want = openssl_verify(pem, caname, sigb, tbs, work)
        if want is None:
            oracle_silent += 1
            bad.append("%s: openssl could not be driven for %s"
                       % (name, caname))
            continue
        rc, line = sshkeyv_verify(path)
        compared += 1
        if rc == 5:
            noverifier += 1
        elif (rc == 0) == want:
            agree += 1
        else:
            differ += 1
            bad.append("%s: sshkeyv rc=%d (%r), openssl says %s"
                       % (name, rc, line, want))
        if not want:
            bad.append("%s: openssl refuses a signature ssh-keygen made"
                       % name)
            differ += 1

        # Corruption. One bit at a time, at the first, middle and last
        # byte of the RAW signature, at a byte inside the subject key, and
        # at the last byte of the CA key. Both sides must refuse every one.
        #
        # The offsets are computed into the raw signature rather than into
        # the signature blob, and that distinction cost a detour. Flipping
        # a bit in the signature's ALGORITHM NAME leaves the signature
        # itself intact: sshkeyv refuses the certificate, correctly,
        # because the name no longer goes with the key, but openssl is not
        # shown the name and says the signature is good, which it is. The
        # first version of this script counted that as openssl accepting a
        # corruption, 23 times.
        signame, so = sshstr(sigb, 0)
        raw_sig, _ = sshstr(sigb, so)
        raw_off = len(blob) - len(raw_sig)
        spots = [raw_off, raw_off + len(raw_sig) // 2, len(blob) - 1,
                 40, len(tbs) - 1]
        for spot in spots:
            if spot < 0 or spot >= len(blob):
                continue
            m = bytearray(blob)
            m[spot] ^= 1
            cpath = os.path.join(work, "corrupt.pub")
            write_cert(cpath, algo, bytes(m))
            try:
                ctbs, ccakey, csig = split_cert(bytes(m))
            except Exception:
                # The flip landed in a length field and the blob no longer
                # parses, so there is nothing to hand openssl. sshkeyv's
                # refusal is already counted above.
                #
                # The first version of this put the ORIGINAL tbs, CA key
                # and signature here instead of skipping, so openssl was
                # handed an intact certificate and said it was good, and
                # the script reported "openssl ACCEPTS the corruption" 23
                # times. An oracle asked the wrong question answers
                # confidently.
                ctbs = None
            crc, cline = sshkeyv_verify(cpath)
            corrupt_total += 1
            if crc != 0:
                corrupt_refused += 1
            else:
                corrupt_accepted += 1
                bad.append("%s: A ONE-BIT CHANGE AT %d WAS ACCEPTED: %r"
                           % (name, spot, cline))
            # And openssl must refuse it too, so that "refused" is not just
            # sshkeyv being broken in a convenient direction.
            cpem = spki(ccakey, work) if ctbs is not None else None
            if cpem is not None:
                ow = openssl_verify(cpem, caname, csig, ctbs, work)
                if ow:
                    differ += 1
                    bad.append("%s: openssl ACCEPTS the corruption at %d"
                               % (name, spot))
    # Terminal findings first: an accepted corruption is the one failure
    # that means the project failed, so it must not be pushed off the end
    # of a truncated list.
    bad.sort(key=lambda s: 0 if "ACCEPTED" in s or "ACCEPTS" in s else 1)
    for b in bad[:20]:
        print("  " + b)
    print("  CA key types: " + "  ".join("%s %d" % (k, v)
                                         for k, v in sorted(by_ca.items())))
    gap = len(by_ca) < 3
    if gap:
        print("  CORPUS GAP: fewer than three CA key types")
    print("%d compared, %d agree, %d differ, %d no verifier, "
          "%d oracle could not be driven" % (compared, agree, differ,
                                             noverifier, oracle_silent))
    print("%d corruptions, %d refused, %d accepted"
          % (corrupt_total, corrupt_refused, corrupt_accepted))
    return 1 if (differ or corrupt_accepted or oracle_silent or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
