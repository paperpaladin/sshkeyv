#!/usr/bin/env python3
"""Certificate fields against `ssh-keygen -L -f` and a python parse.

Field by field. ssh-keygen -L prints an indented block with the principals
one per line and the options as name and value with a space between them,
and sshkeyv prints tab-separated pairs; a whole-output diff of the two can
only say "different", so this reads ssh-keygen's block into a dictionary
and asks about one name at a time.

The python parse is the second oracle and covers what ssh-keygen -L does
not print: the nonce, the reserved field, the length of the signed region,
and the byte lengths of the CA key and signature blobs. It knows the field
order from PROTOCOL.certkeys and nothing else.

Usage: certcmp.py CORPUSDIR
Prints the construct counts and then
"N certificates, M compared, K differ, J refused".
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


def seq_strings(b):
    out, o = [], 0
    while o < len(b):
        s, o = sshstr(b, o)
        out.append(s.decode())
    return out


def seq_opts(b):
    out, o = [], 0
    while o < len(b):
        name, o = sshstr(b, o)
        data, o = sshstr(b, o)
        out.append((name.decode(), data))
    return out


def python_cert(blob):
    name, o = sshstr(blob, 0)
    name = name.decode()
    plain = name[:-len("-cert-v01@openssh.com")]
    nonce, o = sshstr(blob, o)
    if plain == "ssh-ed25519":
        _, o = sshstr(blob, o)
    elif plain == "ssh-rsa":
        _, o = sshstr(blob, o)
        _, o = sshstr(blob, o)
    else:
        _, o = sshstr(blob, o)
        _, o = sshstr(blob, o)
    (serial,) = struct.unpack(">Q", blob[o:o + 8]); o += 8
    (ctype,) = struct.unpack(">I", blob[o:o + 4]); o += 4
    keyid, o = sshstr(blob, o)
    prin, o = sshstr(blob, o)
    (va,) = struct.unpack(">Q", blob[o:o + 8]); o += 8
    (vb,) = struct.unpack(">Q", blob[o:o + 8]); o += 8
    crit, o = sshstr(blob, o)
    ext, o = sshstr(blob, o)
    resv, o = sshstr(blob, o)
    cakey, o = sshstr(blob, o)
    tbs_len = o
    sig, o = sshstr(blob, o)
    if o != len(blob):
        raise ValueError("trailing bytes")
    ca_name, _ = sshstr(cakey, 0)
    sig_name, _ = sshstr(sig, 0)
    d = {
        "cert-algorithm": name,
        "cert-nonce": nonce.hex(),
        "cert-nonce-bytes": str(len(nonce)),
        "cert-serial": str(serial),
        "cert-type": str(ctype),
        "cert-type-name": "host" if ctype == 2 else "user",
        "cert-key-id": keyid.decode(),
        "cert-valid-after": str(va),
        "cert-valid-before": str(vb),
        "cert-reserved-bytes": str(len(resv)),
        "cert-ca-algorithm": ca_name.decode(),
        "cert-ca-blob-bytes": str(len(cakey)),
        "cert-signature-algorithm": sig_name.decode(),
        "cert-signature-blob-bytes": str(len(sig)),
        "cert-tbs-bytes": str(tbs_len),
    }
    ps = seq_strings(prin)
    d["cert-principal-count"] = str(len(ps))
    for i, p in enumerate(ps):
        d["cert-principal-%d" % i] = p
    for label, raw in (("critical", crit), ("extension", ext)):
        os_ = seq_opts(raw)
        d["cert-%s-count" % label] = str(len(os_))
        for i, (n, data) in enumerate(os_):
            d["cert-%s-%d-name" % (label, i)] = n
            d["cert-%s-%d-data" % (label, i)] = data.hex()
    return d, ps, seq_opts(crit), seq_opts(ext)


def keygen_L(path):
    """ssh-keygen -L into a dictionary of the names sshkeyv also prints."""
    p = subprocess.run(["ssh-keygen", "-L", "-f", path],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        return None
    d = {}
    section = None
    lists = {"Principals": [], "Critical Options": [], "Extensions": []}
    for line in p.stdout.decode().splitlines():
        t = line.strip()
        if not t or line.endswith(":") and not line.startswith("\t"):
            continue
        if t.startswith("Type: "):
            d["cert-algorithm"] = t.split()[1]
            d["cert-type-name"] = t.split()[2]
            section = None
        elif t.startswith("Key ID: "):
            d["cert-key-id"] = t[len("Key ID: "):].strip('"')
            section = None
        elif t.startswith("Serial: "):
            d["cert-serial"] = t.split(": ", 1)[1]
            section = None
        elif t.startswith("Signing CA: "):
            d["cert-signature-algorithm"] = t.rsplit("(using ", 1)[1].rstrip(")")
            section = None
        elif t.startswith("Valid:"):
            d["_valid"] = t[len("Valid:"):].strip()
            section = None
        elif t.startswith("Principals:"):
            section = "Principals"
            if "(none)" in t:
                section = None
        elif t.startswith("Critical Options:"):
            section = "Critical Options"
            if "(none)" in t:
                section = None
        elif t.startswith("Extensions:"):
            section = "Extensions"
            if "(none)" in t:
                section = None
        elif section:
            lists[section].append(t)
    d["cert-principal-count"] = str(len(lists["Principals"]))
    for i, p in enumerate(lists["Principals"]):
        d["cert-principal-%d" % i] = p
    d["cert-critical-count"] = str(len(lists["Critical Options"]))
    d["cert-extension-count"] = str(len(lists["Extensions"]))
    for i, o in enumerate(lists["Critical Options"]):
        d["cert-critical-%d-name" % i] = o.split(" ", 1)[0]
    for i, o in enumerate(lists["Extensions"]):
        d["cert-extension-%d-name" % i] = o.split(" ", 1)[0]
    return d


def main():
    d = sys.argv[1]
    certs = compared = differ = refused = 0
    bad = []
    # Construct counts. A critical-options comparison over certificates
    # with no critical options passes having checked nothing, so every
    # construct is counted and the suite asserts the counts are non-zero.
    counts = {k: 0 for k in (
        "user", "host", "principals-none", "principals-many", "serial-zero",
        "serial-nonzero", "critical-present", "critical-none",
        "extensions-present", "extensions-none", "ca-ed25519", "ca-rsa",
        "ca-ecdsa", "sigalg-ssh-rsa", "sigalg-rsa-sha2-256",
        "sigalg-rsa-sha2-512", "subject-rsa", "subject-ecdsa",
        "subject-ed25519", "valid-forever", "valid-window")}
    for name in sorted(os.listdir(d)):
        if not name.endswith("-cert.pub"):
            continue
        path = os.path.join(d, name)
        with open(path) as f:
            line = f.readline().strip()
        blob = base64.b64decode(line.split()[1], validate=True)
        want, ps, crit, ext = python_cert(blob)
        kl = keygen_L(path)
        if kl is None:
            bad.append("%s: ssh-keygen -L refused it" % name)
            differ += 1
            continue
        # The two oracles must agree with each other first.
        for k in sorted(set(want) & set(kl)):
            if want[k] != kl[k]:
                bad.append("%s: oracles disagree about %s: python %r, "
                           "ssh-keygen %r" % (name, k, want[k], kl[k]))
                differ += 1
        want.update({k: v for k, v in kl.items() if not k.startswith("_")})

        certs += 1
        counts[want["cert-type-name"]] += 1
        if not ps:
            counts["principals-none"] += 1
        if len(ps) > 5:
            counts["principals-many"] += 1
        counts["serial-zero" if want["cert-serial"] == "0"
               else "serial-nonzero"] += 1
        counts["critical-present" if crit else "critical-none"] += 1
        counts["extensions-present" if ext else "extensions-none"] += 1
        ca = want["cert-ca-algorithm"]
        if ca == "ssh-ed25519":
            counts["ca-ed25519"] += 1
        elif ca == "ssh-rsa":
            counts["ca-rsa"] += 1
        else:
            counts["ca-ecdsa"] += 1
        sa = want["cert-signature-algorithm"]
        if sa in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
            counts["sigalg-" + sa] += 1
        subj = line.split()[0]
        if subj.startswith("ssh-rsa"):
            counts["subject-rsa"] += 1
        elif subj.startswith("ecdsa"):
            counts["subject-ecdsa"] += 1
        else:
            counts["subject-ed25519"] += 1
        if (want["cert-valid-after"] == "0"
                and want["cert-valid-before"] == str(2 ** 64 - 1)):
            counts["valid-forever"] += 1
        else:
            counts["valid-window"] += 1

        p = subprocess.run([BIN, "fields", path], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        got = {}
        for ln in p.stdout.decode().splitlines():
            parts = ln.split("\t", 2)
            if len(parts) == 3:
                got[parts[1]] = parts[2]
        for k in sorted(want):
            compared += 1
            if k not in got:
                refused += 1
                bad.append("%s: no value for %s (rc=%d %s)"
                           % (name, k, p.returncode,
                              p.stderr.decode().strip()))
            elif got[k] != want[k]:
                differ += 1
                bad.append("%s: %s = %r, oracle says %r"
                           % (name, k, got[k], want[k]))
    for b in bad[:25]:
        print("  " + b)
    print("  counts: " + "  ".join("%s %d" % (k, counts[k])
                                   for k in sorted(counts)))
    zero = [k for k in counts if counts[k] == 0]
    if zero:
        print("  CORPUS GAP: no certificate in the corpus has: %s"
              % " ".join(sorted(zero)))
    print("%d certificates, %d compared, %d differ, %d refused"
          % (certs, compared, differ, refused))
    return 1 if (differ or refused or zero) else 0


if __name__ == "__main__":
    sys.exit(main())
