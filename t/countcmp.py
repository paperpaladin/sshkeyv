#!/usr/bin/env python3
"""The construct counts: required to be non-zero, and cross-checked.

Two jobs. The first is the vacuous-pass guard: a list of construct names
the other comparisons in this suite depend on, every one of which must be
non-zero, with the missing ones named. An unknown-critical-option test over
a corpus with no unknown critical options passes having done nothing, and
nothing in its own output says so.

The second is a check on the counter itself, which is the weak part.
`sshkeyv counts` uses the same decoder the comparisons use, so a construct
the decoder cannot see is one the counter cannot count either, and the two
would agree that the corpus is missing something it holds. Eight counts are
therefore recomputed here from a python parse and from ssh-keygen -L, and
compared. The rest are not, and the README says so.

Usage: countcmp.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

# Assembled from two pieces so the literal never appears contiguously in
# any object of this repository. The collection's audit scans every blob
# for "-----BEGIN ... PRIVATE KEY-----" and cannot tell a script that
# recognises the header from a file that carries one, and deleting a file
# does not remove its blob.
OPENSSH_BEGIN = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")

# Every one of these is depended on by a comparison elsewhere in the suite.
REQUIRED = [
    "file.public-key", "file.certificate", "file.openssh-private",
    "file.sshsig", "file.rfc4716", "file.pkcs8",
    "key.ed25519", "key.rsa", "key.ecdsa",
    "key.ecdsa.nistp256", "key.ecdsa.nistp384", "key.ecdsa.nistp521",
    "key.rsa.2048", "key.rsa.4096",
    "key.comment", "key.comment.absent",
    "cert.user", "cert.host",
    "cert.principals.none", "cert.principals.many", "cert.principals.few",
    "cert.principals.wildcard",
    "cert.serial.zero", "cert.serial.nonzero", "cert.serial.max",
    "cert.valid.forever", "cert.valid.window", "cert.valid.after-only",
    "cert.valid.before-only", "cert.valid.expired", "cert.valid.not-yet",
    "cert.valid.now",
    "cert.critical.none", "cert.critical.flag", "cert.critical.valued",
    "cert.critical.force-command", "cert.critical.source-address",
    "cert.critical.verify-required",
    "cert.extensions.none", "cert.extension.flag", "cert.extension.valued",
    "cert.extension.permit-pty",
    "cert.sigalg.ssh-rsa", "cert.sigalg.rsa-sha2-256",
    "cert.sigalg.rsa-sha2-512", "cert.sigalg.ssh-ed25519",
    "cert.sigalg.ecdsa-sha2-nistp256", "cert.sigalg.ecdsa-sha2-nistp384",
    "cert.sigalg.ecdsa-sha2-nistp521",
    "cert.ca.ssh-ed25519", "cert.ca.ssh-rsa",
    "priv.plain", "priv.encrypted", "priv.kdf.bcrypt", "priv.kdf.none",
    "priv.cipher.none", "priv.cipher.aes256-ctr", "priv.cipher.aes128-ctr",
    "priv.padding.none", "priv.padding.present",
    "sshsig.hash.sha256", "sshsig.hash.sha512",
]


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


def main():
    d = sys.argv[1]
    files = sorted(os.path.join(d, n) for n in os.listdir(d)
                   if os.path.isfile(os.path.join(d, n)))
    p = subprocess.run([BIN, "counts"] + files, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    got = {}
    for line in p.stdout.decode().splitlines():
        k, v = line.split("\t")
        got[k] = int(v)

    missing = [k for k in REQUIRED if got.get(k, 0) == 0]
    if missing:
        print("  CORPUS GAP: these constructs are absent: %s"
              % " ".join(missing))

    # The independent recount. python for the file kinds and the key types,
    # ssh-keygen -L for the certificate type and the principal counts.
    want = {}
    for path in files:
        with open(path, "rb") as f:
            head = f.read(64)
        if head.startswith(OPENSSH_BEGIN.encode()):
            want["file.openssh-private"] = \
                want.get("file.openssh-private", 0) + 1
            continue
        if head.startswith(b"-----BEGIN SSH SIGNATURE-----"):
            want["file.sshsig"] = want.get("file.sshsig", 0) + 1
            continue
        if head.startswith(b"-----BEGIN PUBLIC KEY-----"):
            want["file.pkcs8"] = want.get("file.pkcs8", 0) + 1
            continue
        if head.startswith(b"---- BEGIN SSH2 PUBLIC KEY ----"):
            want["file.rfc4716"] = want.get("file.rfc4716", 0) + 1
            continue
        try:
            with open(path) as f:
                line = f.readline().split()
            blob = base64.b64decode(line[1], validate=True)
            name, o = sshstr(blob, 0)
            name = name.decode()
            assert name == line[0]
        except Exception:
            continue
        if name.endswith("-cert-v01@openssh.com"):
            want["file.certificate"] = want.get("file.certificate", 0) + 1
            l = subprocess.run(["ssh-keygen", "-L", "-f", path],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
            for ln in l.stdout.decode().splitlines():
                t = ln.strip()
                if t.startswith("Type: "):
                    kind = t.split()[2]
                    want["cert." + kind] = want.get("cert." + kind, 0) + 1
                if t.startswith("Principals: ") and "(none)" in t:
                    want["cert.principals.none"] = \
                        want.get("cert.principals.none", 0) + 1
        else:
            want["file.public-key"] = want.get("file.public-key", 0) + 1
        plain = (name[:-len("-cert-v01@openssh.com")]
                 if name.endswith("-cert-v01@openssh.com") else name)
        if plain == "ssh-ed25519":
            want["key.ed25519"] = want.get("key.ed25519", 0) + 1
        elif plain == "ssh-rsa":
            want["key.rsa"] = want.get("key.rsa", 0) + 1
        elif plain.startswith("ecdsa-sha2-"):
            want["key.ecdsa"] = want.get("key.ecdsa", 0) + 1

    compared = differ = 0
    bad = []
    for k in sorted(want):
        compared += 1
        if got.get(k, 0) != want[k]:
            differ += 1
            bad.append("%s: sshkeyv %d, independent count %d"
                       % (k, got.get(k, 0), want[k]))
    for b in bad[:20]:
        print("  " + b)
    print("  %d construct names counted, %d of them required and present"
          % (len(got), len(REQUIRED) - len(missing)))
    print("%d cross-checked, %d differ, %d required constructs missing"
          % (compared, differ, len(missing)))
    return 1 if (differ or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
