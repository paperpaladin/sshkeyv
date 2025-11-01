#!/usr/bin/env python3
"""Compare `sshkeyv fields` with ssh-keygen and with a python parse, field
by field.

Two oracles per file, and they cover different fields:

  ssh-keygen -l -f FILE gives the bit count, the key kind in brackets and
  the comment. That is OpenSSH's own opinion about the key, which is what
  anyone reading a key file sees.

  A python parse of the base64 blob with struct gives the key material:
  the ed25519 point, the ECDSA curve name and point, the RSA exponent and
  modulus. It knows the three blob layouts and nothing else.

Field by field, never as text. The two programs do not format anything the
same way and a whole-output diff can only say "different".

Prints "N compared, M differ, K refused, J declined" where a refusal is
sshkeyv having no value where an oracle has one, and a declined is neither
having one. Exits non-zero on a disagreement or a refusal.
"""
import base64
import os
import struct
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")


def sshstr(b, o):
    (n,) = struct.unpack(">I", b[o:o + 4])
    return b[o + 4:o + 4 + n], o + 4 + n


def mpint(b, o):
    v, o = sshstr(b, o)
    return v.lstrip(b"\x00"), o


def python_material(blob):
    """The key material out of the blob, knowing only the three layouts."""
    name, o = sshstr(blob, 0)
    name = name.decode()
    is_cert = name.endswith("-cert-v01@openssh.com")
    plain = name[:-len("-cert-v01@openssh.com")] if is_cert else name
    if is_cert:
        _, o = sshstr(blob, o)          # nonce
    out = {"algorithm": name, "plain-algorithm": plain,
           "is-cert": "yes" if is_cert else "no",
           "blob-bytes": str(len(blob))}
    if plain == "ssh-ed25519":
        pk, o = sshstr(blob, o)
        out["kind"] = "ED25519"
        out["bits"] = "256"
        out["ed25519-pk"] = pk.hex()
    elif plain == "ssh-rsa":
        e, o = mpint(blob, o)
        n, o = mpint(blob, o)
        out["kind"] = "RSA"
        out["bits"] = str(n[0].bit_length() + 8 * (len(n) - 1))
        out["rsa-e"] = e.hex()
        out["rsa-n"] = n.hex()
        out["rsa-n-bits"] = out["bits"]
    elif plain.startswith("ecdsa-sha2-"):
        cname, o = sshstr(blob, o)
        point, o = sshstr(blob, o)
        out["kind"] = "ECDSA"
        out["bits"] = plain[len("ecdsa-sha2-nistp"):]
        out["ecdsa-curve"] = cname.decode()
        out["ecdsa-point"] = point.hex()
    else:
        return None
    return out


def keygen_l(path):
    p = subprocess.run(["ssh-keygen", "-l", "-f", path],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        return None
    line = p.stdout.decode().strip()
    bits, rest = line.split(" ", 1)
    _fp, rest = rest.split(" ", 1)
    # The kind is the last parenthesised word; the comment is everything
    # between the fingerprint and it, and may hold spaces or be absent.
    kind = rest.rsplit("(", 1)[1].rstrip(")")
    comment = rest.rsplit(" (", 1)[0]
    return {"bits": bits, "kind": kind, "comment": comment}


def sshkeyv_fields(path):
    p = subprocess.run([BIN, "fields", path], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    got = {}
    for line in p.stdout.decode().splitlines():
        parts = line.split("\t", 2)
        if len(parts) == 3:
            got[parts[1]] = parts[2]
    return p.returncode, got, p.stderr.decode().strip()


def main():
    d = sys.argv[1]
    compared = differ = refused = declined = 0
    bad = []
    files = 0
    for name in sorted(os.listdir(d)):
        if not name.endswith(".pub"):
            continue
        path = os.path.join(d, name)
        with open(path) as f:
            line = f.readline().strip()
        try:
            blob = base64.b64decode(line.split()[1], validate=True)
        except Exception:
            continue
        want = python_material(blob)
        if want is None:
            continue
        kl = keygen_l(path)
        if kl is not None:
            # ssh-keygen appends -CERT to the kind of a certificate.
            want["kind"] = kl["kind"]
            want["bits"] = kl["bits"]
            # ssh-keygen prints the literal words "no comment" when a key
            # line has no comment field, which is indistinguishable from a
            # key whose comment is "no comment". So the presence of the
            # field is read off the line itself and ssh-keygen's text is
            # only believed when there is one.
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[2]:
                want["comment"] = kl["comment"]
                if kl["comment"] != parts[2]:
                    bad.append("%s: ssh-keygen comment %r, line has %r"
                               % (name, kl["comment"], parts[2]))
                    differ += 1
            else:
                want["comment-absent"] = "yes"
            # The python parse and ssh-keygen must agree about the kind
            # before either is used as an oracle, or a disagreement
            # between the two would be charged to sshkeyv.
            pk = python_material(blob)["kind"]
            if kl["kind"] not in (pk, pk + "-CERT"):
                bad.append("%s: ssh-keygen says kind %s, python says %s"
                           % (name, kl["kind"], pk))
                differ += 1
        files += 1
        rc, got, err = sshkeyv_fields(path)
        for k in sorted(want):
            compared += 1
            if k not in got:
                refused += 1
                bad.append("%s: no value for %s (sshkeyv rc=%d %s)"
                           % (name, k, rc, err))
            elif got[k] != want[k]:
                differ += 1
                bad.append("%s: %s = %r, oracle says %r"
                           % (name, k, got[k], want[k]))
    for b in bad[:20]:
        print("  " + b)
    print("%d files, %d compared, %d differ, %d refused, %d declined"
          % (files, compared, differ, refused, declined))
    return 1 if (differ or refused) else 0


if __name__ == "__main__":
    sys.exit(main())
