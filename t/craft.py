#!/usr/bin/env python3
"""Certificates ssh-keygen will not write, built by hand.

ssh-keygen sorts the critical options and extensions lists when it signs,
removes duplicates, refuses an empty principal and always writes a 32-byte
nonce. So the corpus cannot hold any of those shapes, and they are exactly
the shapes a server rejects while ssh-keygen -L prints them without a
word. Two construct counts stay at zero until this script runs, and
t/countcmp.py says which they are.

Two things were learned building this and both are in the README.

ssh-keygen -L VERIFIES the CA signature before it prints anything. It is
not a dumb field printer: a certificate with one bit flipped in its
signature gets "invalid key: incorrect signature" and no output at all.
So a crafted certificate cannot simply be assembled and shown to it.

The way round that is the second finding. A certificate whose CA key is
the Ed25519 identity point, signed with R = identity and S = 0, satisfies
the verification equation for any body at all, and ssh-keygen -L accepts
it and prints every field. Every certificate here is "signed" that way.
That is a working demonstration of why sshkeyv reports a small-order
signing key as MEANINGLESS rather than good, and it is what makes
ssh-keygen a real oracle for these shapes instead of no oracle at all.

Usage: craft.py CORPUSDIR
Prints "N crafted, M shown identically, K refused by both, J differ".
"""
import base64
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "target", "release", "sshkeyv")


def put(b):
    return struct.pack(">I", len(b)) + b


def sshstr(b, o):
    if len(b) - o < 4:
        raise ValueError("no length at %d" % o)
    (n,) = struct.unpack(">I", b[o:o + 4])
    if len(b) - o - 4 < n:
        raise ValueError("short string at %d" % o)
    return b[o + 4:o + 4 + n], o + 4 + n


def build(subject_pk, cakey, sig, **kw):
    nonce = kw.get("nonce", b"\x33" * 32)
    principals = kw.get("principals", [b"alice"])
    critical = kw.get("critical", [])
    extensions = kw.get("extensions", [(b"permit-pty", b"")])
    reserved = kw.get("reserved", b"")
    body = (put(b"ssh-ed25519-cert-v01@openssh.com")
            + put(nonce)
            + put(subject_pk)
            + struct.pack(">Q", kw.get("serial", 5))
            + struct.pack(">I", kw.get("ctype", 1))
            + put(kw.get("keyid", b"crafted"))
            + put(b"".join(put(p) for p in principals))
            + struct.pack(">Q", kw.get("valid", (0, 2 ** 64 - 1))[0])
            + struct.pack(">Q", kw.get("valid", (0, 2 ** 64 - 1))[1])
            + put(b"".join(put(n) + put(v) for n, v in critical))
            + put(b"".join(put(n) + put(v) for n, v in extensions))
            + put(reserved)
            + put(cakey))
    return body + put(sig)


def bisect_principals(work, subject_pk, cakey, sig):
    def loads(n):
        blob = build(subject_pk, cakey, sig,
                     principals=[b"p%04d" % i for i in range(n)])
        p = os.path.join(work, "probe-cert.pub")
        with open(p, "w") as f:
            f.write("ssh-ed25519-cert-v01@openssh.com %s p\n"
                    % base64.b64encode(blob).decode())
        return subprocess.run(["ssh-keygen", "-L", "-f", p],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    lo, hi = 1, 1024
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if loads(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def main():
    d = sys.argv[1]
    work = os.path.join(d, "crafted")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(d, "ed25519.pub")) as f:
        sub = base64.b64decode(f.readline().split()[1], validate=True)
    _, o = sshstr(sub, 0)
    subject_pk, _ = sshstr(sub, o)
    # The identity point as the CA key, with R = identity and S = 0 as the
    # signature. The verification equation holds for any body, so
    # ssh-keygen -L will read whatever is built below.
    ident = (1).to_bytes(32, "little")
    cakey = put(b"ssh-ed25519") + put(ident)
    sig = put(b"ssh-ed25519") + put(ident + bytes(32))

    def opt(name, value=b""):
        return (name, put(value) if value else b"")

    cases = {
        # The two constructs the corpus cannot otherwise hold.
        "unordered-critical": dict(
            critical=[opt(b"source-address", b"10.0.0.0/8"),
                      opt(b"force-command", b"/bin/true")]),
        "unordered-extensions": dict(
            extensions=[(b"permit-user-rc", b""), (b"permit-pty", b"")]),
        # Duplicates, which sshd takes the first of and ssh-keygen -L
        # prints twice.
        "duplicate-critical": dict(
            critical=[opt(b"force-command", b"/bin/true"),
                      opt(b"force-command", b"/bin/false")]),
        "duplicate-extension": dict(
            extensions=[(b"permit-pty", b""), (b"permit-pty", b"")]),
        # A nonce of zero bytes. OpenSSH writes 32 and the nonce is what
        # stops a chosen-prefix attack on the signature hash.
        "empty-nonce": dict(nonce=b""),
        "short-nonce": dict(nonce=b"\x01"),
        # Principals ssh-keygen -n cannot express.
        "principal-with-comma": dict(principals=[b"alice,bob"]),
        "principal-empty": dict(principals=[b""]),
        # 256 is the most OpenSSH will load and 257 is one too many. The
        # boundary is bisected below rather than trusted.
        "max-principals": dict(
            principals=[b"p%04d" % i for i in range(256)]),
        "too-many-principals": dict(
            principals=[b"p%04d" % i for i in range(257)]),
        # A certificate type that is neither user nor host, which
        # ssh-keygen refuses with "unknown/unsupported certificate type".
        "type-3": dict(ctype=3),
        # A window that ends before it starts. ssh-keygen -L prints it
        # without a word, so sshkeyv reads it too and says NEVER valid
        # from the valid command instead of refusing to parse.
        "window-backwards": dict(valid=(2000000000, 1000000000)),
        # A reserved field with something in it. PROTOCOL.certkeys says it
        # is currently unused.
        "reserved-nonempty": dict(reserved=b"something"),
        # Option data that is not one string, which ssh-keygen -L calls
        # Option corrupt and dies on.
        "force-command-two-strings": dict(
            critical=[(b"force-command", put(b"a") + put(b"b"))]),
        "force-command-raw-bytes": dict(
            critical=[(b"force-command", b"notastring")]),
    }

    crafted = identical = refused_both = differ = 0
    for name, kw in cases.items():
        blob = build(subject_pk, cakey, sig, **kw)
        path = os.path.join(work, "%s-cert.pub" % name)
        with open(path, "w") as f:
            f.write("ssh-ed25519-cert-v01@openssh.com %s crafted\n"
                    % base64.b64encode(blob).decode())
        crafted += 1
        env = dict(os.environ, TZ="UTC0")
        theirs = subprocess.run(["ssh-keygen", "-L", "-f", path], env=env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        mine = subprocess.run([BIN, "show", path], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if theirs.returncode == 0 and mine.returncode == 0:
            if theirs.stdout == mine.stdout:
                identical += 1
            else:
                differ += 1
                print("  %s: show differs from ssh-keygen -L" % name)
                a = mine.stdout.decode().splitlines()
                b = theirs.stdout.decode().splitlines()
                for i in range(max(len(a), len(b))):
                    x = a[i] if i < len(a) else "<missing>"
                    y = b[i] if i < len(b) else "<missing>"
                    if x != y:
                        print("      sshkeyv    %r" % x)
                        print("      ssh-keygen %r" % y)
        elif theirs.returncode != 0 and mine.returncode != 0:
            refused_both += 1
            print("    refused by both: %s -- %s"
                  % (name, mine.stderr.decode().strip().split(": ", 2)[-1]))
        elif theirs.returncode != 0:
            # ssh-keygen died and sshkeyv printed something. That is not
            # automatically wrong: ssh-keygen calls fatal() on a corrupt
            # option and prints nothing at all, where sshkeyv names the
            # option on its line and carries on. Reported, counted apart,
            # and the reason ssh-keygen gave is printed so that a
            # signature complaint cannot hide among them.
            err = theirs.stderr.decode()
            print("    sshkeyv reads what ssh-keygen -L dies on: %s -- %s"
                  % (name, err.strip().splitlines()[-1]
                     if theirs.stderr else "no message"))
            if "signature" in err:
                differ += 1
                print("  the crafted signature stopped being valid, so "
                      "ssh-keygen is not acting as an oracle here")
            elif "invalid key:" in err:
                # ssh-keygen refused the certificate structurally rather
                # than dying inside its option printer, so sshkeyv reading
                # it is an under-refusal. Counting only the option-printer
                # case as allowed is what makes the 256-principal and
                # certificate-type checks load-bearing: without this
                # branch both mutants survived.
                differ += 1
                print("  UNDER-REFUSED %s: ssh-keygen refuses it "
                      "structurally" % name)
        else:
            differ += 1
            print("  UNDER-REFUSED %s: ssh-keygen -L reads it, sshkeyv "
                  "will not: %s"
                  % (name, mine.stderr.decode().strip()))

    # The window-backwards case has an answer only the valid command
    # gives, so it is asked for here. Without this nothing exercises the
    # empty-window branch at all and the check for it survives mutation.
    wb = os.path.join(work, "window-backwards-cert.pub")
    if os.path.exists(wb):
        v = subprocess.run([BIN, "valid", wb], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        line = v.stdout.decode().strip()
        if v.returncode != 4 or "NEVER valid" not in line:
            differ += 1
            print("  the backwards window is not reported: rc=%d %r"
                  % (v.returncode, line))
        else:
            print("    valid on the backwards window: %s"
                  % line.split(": ", 1)[1])

    # The constructs these files exist for.
    files = [os.path.join(work, n) for n in sorted(os.listdir(work))]
    c = subprocess.run([BIN, "counts"] + files, stdout=subprocess.PIPE)
    counts = {}
    for line in c.stdout.decode().splitlines():
        k, v = line.split("\t")
        counts[k] = int(v)
    need = ["cert.critical.unordered", "cert.extensions.unordered",
            "cert.nonce.empty", "cert.principals.many",
            "cert.reserved.nonempty", "cert.valid.backwards"]
    # Bisect ssh-keygen for the principal limit instead of believing the
    # number in src/cert.rs. A limit that moves in a future OpenSSH turns
    # this red rather than quietly becoming an over-refusal.
    limit = bisect_principals(work, subject_pk, cakey, sig)
    print("    ssh-keygen loads at most %d principals" % limit)
    if limit != 256:
        differ += 1
        print("  the measured principal limit is %d, but src/cert.rs says "
              "256" % limit)
    missing = [k for k in need if counts.get(k, 0) == 0]
    if missing:
        differ += 1
        print("  CRAFTED GAP: these are still not counted: %s"
              % " ".join(missing))
    print("  constructs the crafted set adds: %s"
          % " ".join("%s %d" % (k, counts.get(k, 0)) for k in need))
    print("%d crafted, %d shown identically, %d refused by both, %d differ"
          % (crafted, identical, refused_both, differ))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
