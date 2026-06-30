#!/usr/bin/env python3
"""The OpenSSH private key container, against ssh-keygen and a python parse.

Three oracles, each covering what the others cannot:

  ssh-keygen -y -f KEY prints the public key out of an unencrypted private
  key. That is the strongest check here, because it is OpenSSH reading the
  private section itself: if sshkeyv reads the key material from the wrong
  offset the two lines differ.

  ssh-keygen -l -f KEY works on an ENCRYPTED key too, because the public
  half of the container is in clear. So the bits, the kind and the comment
  are checked for the passphrase-protected keys as well. It is NOT the
  authority on whether a container is well formed, and using it that way
  was a defect here: -l never reads the private section, so it declared
  three deliberately broken containers fine and sshkeyv was recorded as
  over-refusing them.

  A python parse of the container with struct gives the cipher, the KDF
  name, the salt and the rounds. Nothing in OpenSSH prints those, which is
  the reason `sshkeyv priv` exists, so they have no other oracle.

The malformed cases are at the end with ssh-keygen as the authority on
which files are malformed, counted apart as always.

Usage: privcmp.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")
MAGIC = b"openssh-key-v1\0"


def pem_body(path):
    with open(path) as f:
        text = f.read()
    lines = [l for l in text.splitlines()
             if l and not l.startswith("-----")]
    return base64.b64decode("".join(lines), validate=True)


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


def python_container(b):
    assert b[:len(MAGIC)] == MAGIC
    o = len(MAGIC)
    cipher, o = sshstr(b, o)
    kdf, o = sshstr(b, o)
    kdfopt, o = sshstr(b, o)
    (nkeys,) = struct.unpack(">I", b[o:o + 4]); o += 4
    pub = []
    for _ in range(nkeys):
        p, o = sshstr(b, o)
        pub.append(p)
    priv, o = sshstr(b, o)
    assert o == len(b), "trailing bytes"
    d = {
        "container-bytes": str(len(b)),
        "cipher": cipher.decode(),
        "kdf": kdf.decode(),
        "encrypted": "no" if cipher == b"none" else "yes",
        "nkeys": str(nkeys),
        "public-blob-bytes": str(len(pub[0])),
        "private-section-bytes": str(len(priv)),
    }
    if kdf == b"bcrypt":
        salt, p2 = sshstr(kdfopt, 0)
        (rounds,) = struct.unpack(">I", kdfopt[p2:p2 + 4])
        d["kdf-salt-bytes"] = str(len(salt))
        d["kdf-salt"] = salt.hex()
        d["kdf-rounds"] = str(rounds)
    else:
        d["kdf-options-bytes"] = str(len(kdfopt))
    name, _ = sshstr(pub[0], 0)
    d["public-line"] = "%s %s" % (name.decode(),
                                  base64.b64encode(pub[0]).decode())
    return d, cipher != b"none"


def fields(path):
    p = subprocess.run([BIN, "priv", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    got = {}
    for line in p.stdout.decode().splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3:
            got[parts[1]] = parts[2]
    return p.returncode, got, p.stderr.decode().strip()


MALFORMED = [
    ("magic is wrong", lambda b: b.replace(MAGIC, b"openssh-key-v2\0", 1)),
    ("magic is truncated", lambda b: b[8:]),
    ("nkeys is 0", lambda b: set_nkeys(b, 0)),
    ("nkeys is 2", lambda b: set_nkeys(b, 2)),
    ("nkeys is 2^32-1", lambda b: set_nkeys(b, 0xffffffff)),
    ("truncated after the magic", lambda b: b[:len(MAGIC)]),
    ("truncated mid public key", lambda b: b[:len(MAGIC) + 40]),
    ("one byte short", lambda b: b[:-1]),
    ("four trailing bytes", lambda b: b + b"\0\0\0\0"),
    ("private section truncated by one byte", lambda b: trim_private(b)),
    # The two check words made to differ, which is exactly what a wrong
    # passphrase produces, and the padding made wrong. Neither can occur
    # in a corpus ssh-keygen wrote, and without them the checks for both
    # survive mutation.
    ("the two check words differ", lambda b: break_checkint(b)),
]

# These need a container whose padding is not empty, and ed25519's is: its
# private section happens to land on a multiple of 8. ecdsa256's has six
# bytes of padding. Without a base that has any, the padding check
# survives mutation while looking tested.
MALFORMED_PADDED = [
    ("the padding is zeros", lambda b: zero_padding(b)),
    ("the padding counts down", lambda b: reverse_padding(b)),
]


def private_offset(b):
    o = len(MAGIC)
    for _ in range(3):
        _, o = sshstr(b, o)
    (nkeys,) = struct.unpack(">I", b[o:o + 4]); o += 4
    for _ in range(nkeys):
        _, o = sshstr(b, o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    return o + 4, n


def break_checkint(b):
    o, n = private_offset(b)
    m = bytearray(b)
    m[o + 7] ^= 1
    return bytes(m)


def padding_len(b):
    """(padding length, private section offset, private section length).

    The padding is 1, 2, 3, ... up to one less than the block size, so the
    LAST byte is the padding length and the bytes before it count down to
    1. Reading it that way rather than walking back over non-zero bytes
    matters: the comment sits immediately before the padding and is also
    non-zero, so a walk runs straight into it and the resulting case
    tests the length check rather than the value check."""
    o, n = private_offset(b)
    if n == 0:
        return 0, o, n
    k = b[o + n - 1]
    if k == 0 or k > 15 or k > n:
        return 0, o, n
    for i in range(k):
        if b[o + n - 1 - i] != k - i:
            return 0, o, n
    return k, o, n


def reverse_padding(b):
    k, o, n = padding_len(b)
    assert k > 0, "the base container has no padding to break"
    m = bytearray(b)
    for i in range(k):
        m[o + n - k + i] = k - i
    return bytes(m)


def zero_padding(b):
    k, o, n = padding_len(b)
    assert k > 0, "the base container has no padding to break"
    m = bytearray(b)
    for i in range(k):
        m[o + n - 1 - i] = 0
    return bytes(m)


def set_nkeys(b, n):
    o = len(MAGIC)
    _, o = sshstr(b, o)
    _, o = sshstr(b, o)
    _, o = sshstr(b, o)
    return b[:o] + struct.pack(">I", n) + b[o + 4:]


def trim_private(b):
    o = len(MAGIC)
    for _ in range(3):
        _, o = sshstr(b, o)
    (nkeys,) = struct.unpack(">I", b[o:o + 4]); o += 4
    for _ in range(nkeys):
        _, o = sshstr(b, o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    return b[:o] + struct.pack(">I", n - 1) + b[o + 4:o + 4 + n - 1]


def write_pem(path, body):
    b64 = base64.b64encode(body).decode()
    with open(path, "w") as f:
        f.write("-----BEGIN OPENSSH " "PRIVATE KEY-----\n")
        for i in range(0, len(b64), 70):
            f.write(b64[i:i + 70] + "\n")
        f.write("-----END OPENSSH " "PRIVATE KEY-----\n")
    # ssh-keygen refuses to read a private key whose mode lets others see
    # it, and prints a banner instead of an answer. Without this the
    # oracle's refusal is about the mode and not about the bytes.
    os.chmod(path, 0o600)


def main():
    d = sys.argv[1]
    compared = differ = refused = 0
    bad = []
    plain = enc = 0
    kdfs = set()
    ciphers = set()
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if not os.path.isfile(path) or name.endswith((".pub", ".sig",
                                                      ".rfc4716", ".pkcs8")):
            continue
        try:
            body = pem_body(path)
        except Exception:
            continue
        if not body.startswith(MAGIC):
            continue
        want, is_enc = python_container(body)
        ciphers.add(want["cipher"])
        kdfs.add(want["kdf"])
        if is_enc:
            enc += 1
        else:
            plain += 1
            y = subprocess.run(["ssh-keygen", "-y", "-f", path],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
            if y.returncode == 0:
                # ssh-keygen -y appends the comment; the first two fields
                # are the algorithm and the blob.
                parts = y.stdout.decode().split()
                want["public-line"] = "%s %s" % (parts[0], parts[1])
        l = subprocess.run(["ssh-keygen", "-l", "-f", path],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if l.returncode == 0:
            line = l.stdout.decode().strip()
            comment = line.rsplit(" (", 1)[0].split(" ", 2)[2]
            # ssh-keygen substitutes a file path when the key it found
            # carries no comment, and prints the words "no comment" in
            # other cases. Neither is a comment. The path it substitutes
            # may be the .pub file, because -l prefers that file when it
            # is given a private key's name and one exists beside it.
            if not is_enc and comment not in ("no comment", path,
                                              path + ".pub"):
                want["private-comment"] = comment
        rc, got, err = fields(path)
        for k in sorted(want):
            compared += 1
            if k not in got:
                refused += 1
                bad.append("%s: no value for %s (rc=%d %s)"
                           % (name, k, rc, err))
            elif got[k] != want[k]:
                differ += 1
                bad.append("%s: %s = %r, oracle says %r"
                           % (name, k, got[k], want[k]))
        if not is_enc and "public-halves-match" not in got:
            differ += 1
            bad.append("%s: the two public halves were not compared" % name)

    # Malformed containers, with ssh-keygen as the authority.
    work = os.path.join(d, "privrefuse")
    os.makedirs(work, exist_ok=True)
    base = pem_body(os.path.join(d, "ed25519"))
    padded = pem_body(os.path.join(d, "ecdsa256"))
    both = over = under = 0
    cases = ([(l, f, base) for l, f in MALFORMED]
             + [(l, f, padded) for l, f in MALFORMED_PADDED])
    for i, (label, f, base_i) in enumerate(cases):
        path = os.path.join(work, "case%02d" % i)
        try:
            write_pem(path, f(base_i))
        except Exception as e:
            bad.append("%s: could not build the case: %s" % (label, e))
            differ += 1
            continue
        a = subprocess.run([BIN, "priv", path], stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
        # An exit code outside sshkeyv's own set is a crash, not a
        # refusal. Counting it as a refusal is how a mutant that removes
        # the key-count check survives: with it gone, a container claiming
        # zero keys makes the code index an empty list and abort, and the
        # abort reads as a tidy refusal from the outside.
        if a.returncode not in (0, 1, 2, 3, 4, 5):
            differ += 1
            bad.append("%s: CRASHED with exit %d" % (label, a.returncode))
            continue
        # -y and not -l. ssh-keygen -l on a private key file reads only
        # the PUBLIC half of the container and never looks at the private
        # section, so it answered "fine" for three cases whose private
        # section was deliberately broken and they were recorded as
        # over-refusals. -y is the flag that reads the whole file.
        b = subprocess.run(["ssh-keygen", "-y", "-f", path],
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        why = a.stderr.decode().strip().replace("\n", " ")
        if a.returncode != 0 and b.returncode != 0:
            both += 1
            print("    refused by both: %s -- %s" % (label, why))
        elif a.returncode != 0:
            over += 1
            print("  OVER-REFUSED ssh-keygen reads it: %s -- %s" % (label, why))
        elif b.returncode != 0:
            under += 1
            print("  UNDER-REFUSED ssh-keygen refuses it: %s" % label)
        else:
            print("    read by both: %s" % label)

    for b in bad[:20]:
        print("  " + b)
    print("  %d unencrypted and %d encrypted containers; ciphers %s; KDFs %s"
          % (plain, enc, " ".join(sorted(ciphers)), " ".join(sorted(kdfs))))
    gap = plain == 0 or enc == 0 or len(ciphers) < 3
    if gap:
        print("  CORPUS GAP: need unencrypted and encrypted containers "
              "and at least three ciphers")
    print("%d compared, %d differ, %d refused; %d malformed refused by both, "
          "%d over-refused, %d under-refused"
          % (compared, differ, refused, both, over, under))
    return 1 if (differ or refused or over or under or gap) else 0


if __name__ == "__main__":
    sys.exit(main())
