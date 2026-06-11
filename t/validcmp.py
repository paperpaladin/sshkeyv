#!/usr/bin/env python3
"""The two verdicts: is the certificate in its window, and does it
authorise a name.

This comparison is the weakest in the suite and says so. There is no
program here that answers either question: ssh-keygen -L prints the window
and the principal list and makes no judgement, and no sshd is installed,
so the authority that would actually accept or refuse the certificate is
not available on this machine. What is checked instead:

  - the window sshkeyv acts on is the window ssh-keygen -L prints, parsed
    by python from ssh-keygen's text, under TZ=UTC0
  - the verdict at seven instants per certificate, computed by python
    from that window, equals sshkeyv's verdict and sshkeyv's exit status
  - the principal list sshkeyv acts on is the list ssh-keygen -L prints
  - the two documented rules hold: an empty list authorises everyone, and
    a non-empty list is compared exactly

The seven instants are the ones that separate an inclusive bound from an
exclusive one: one second before the start, the start, one second after,
one second before the end, the end, one second after, and now. A verdict
test at "now" alone cannot see an off-by-one at either edge, and five of
the seven fall outside anything the clock would reach during a test run.

Usage: validcmp.py CORPUSDIR
Prints "N certificates, M verdicts compared, K differ"
and "N authorisation questions, K differ".
"""
import base64
import calendar
import os
import struct
import subprocess
import sys
import time as _time

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")
FOREVER = 2 ** 64 - 1
ENV = dict(os.environ, TZ="UTC0")


def parse_iso(s):
    return calendar.timegm(_time.strptime(s, "%Y-%m-%dT%H:%M:%S"))


def keygen_window_and_principals(path):
    p = subprocess.run(["ssh-keygen", "-L", "-f", path], env=ENV,
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if p.returncode != 0:
        return None
    after, before = 0, FOREVER
    principals = []
    section = None
    for line in p.stdout.decode().splitlines():
        t = line.strip()
        if t.startswith("Valid:"):
            v = t[len("Valid:"):].strip()
            if v == "forever":
                pass
            elif v.startswith("from "):
                a, b = v[len("from "):].split(" to ")
                after, before = parse_iso(a), parse_iso(b)
            elif v.startswith("before "):
                before = parse_iso(v[len("before "):])
            elif v.startswith("after "):
                after = parse_iso(v[len("after "):])
            else:
                raise ValueError("unknown Valid: form %r" % v)
            section = None
        elif t.startswith("Principals:"):
            section = None if "(none)" in t else "p"
        elif t.endswith(":") or t.startswith(("Type:", "Public key:",
                                              "Signing CA:", "Key ID:",
                                              "Serial:")):
            section = None
        elif t.startswith(("Critical Options:", "Extensions:")):
            section = None
        elif section == "p":
            principals.append(t)
    return after, before, principals


def main():
    d = sys.argv[1]
    certs = verdicts = vdiffer = auth = adiffer = 0
    bad = []
    globs = 0
    for name in sorted(os.listdir(d)):
        if not name.endswith("-cert.pub"):
            continue
        path = os.path.join(d, name)
        w = keygen_window_and_principals(path)
        if w is None:
            bad.append("%s: ssh-keygen -L refused it" % name)
            vdiffer += 1
            continue
        after, before, principals = w
        certs += 1
        if any(c in p for p in principals for c in "*?!"):
            globs += 1

        instants = [after - 1, after, after + 1,
                    before - 1, before, before + 1, int(_time.time())]
        for at in instants:
            if at < 0 or at > FOREVER:
                continue
            want_ok = after <= at <= before
            p = subprocess.run([BIN, "valid", "--at", str(at), path],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
            verdicts += 1
            got_ok = p.returncode == 0
            line = p.stdout.decode().strip()
            if got_ok != want_ok:
                vdiffer += 1
                bad.append("%s at %d: sshkeyv says %s (%r), window is "
                           "[%d, %d]" % (name, at,
                                         "valid" if got_ok else "not valid",
                                         line, after, before))
            # The word on the line has to match the exit status, or a
            # caller reading one and a human reading the other disagree.
            elif want_ok and "valid," not in line:
                vdiffer += 1
                bad.append("%s at %d: exit 0 but the line says %r"
                           % (name, at, line))
            elif not want_ok and ("expired" not in line
                                  and "not yet valid" not in line):
                vdiffer += 1
                bad.append("%s at %d: exit 4 but the line says %r"
                           % (name, at, line))

        # The combined verdict. Every question is asked in one run and
        # the exit status is the worst answer, so a certificate that is
        # expired AND for the wrong principal AND the wrong kind must
        # still exit 4 and must print all three lines. A command that
        # stopped at the first no would need running three times.
        kind = subprocess.run(["ssh-keygen", "-L", "-f", path], env=ENV,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL)
        is_host = " host certificate" in kind.stdout.decode()
        now = int(_time.time())
        in_window = after <= now <= before
        for flag, want_kind_ok in (("--host", is_host),
                                   ("--user", not is_host)):
            questions = [
                (principals[0] if principals else "anybody", True),
                ("definitely-not-listed", not principals),
            ]
            for who, want_auth in questions:
                p = subprocess.run([BIN, "valid", flag, "--principal", who,
                                    path],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
                lines = p.stdout.decode().strip().splitlines()
                want_ok = in_window and want_kind_ok and want_auth
                verdicts += 1
                if (p.returncode == 0) != want_ok:
                    vdiffer += 1
                    bad.append("%s %s %s: rc=%d, wanted %s -- %r"
                               % (name, flag, who, p.returncode, want_ok,
                                  lines))
                # Every question must produce a line, whatever the answer.
                want_lines = 2
                if not want_kind_ok:
                    want_lines = 3
                if len(lines) != want_lines:
                    vdiffer += 1
                    bad.append("%s %s %s: printed %d lines, wanted %d: %r"
                               % (name, flag, who, len(lines), want_lines,
                                  lines))

        # Authorisation: every listed principal must be authorised, and a
        # name that is not listed must not be, unless the list is empty.
        questions = list(principals) + ["definitely-not-listed",
                                        "alice", "web1.example.com"]
        for q in questions:
            want_ok = (not principals) or (q in principals)
            p = subprocess.run([BIN, "authorises", q, path],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
            auth += 1
            if (p.returncode == 0) != want_ok:
                adiffer += 1
                bad.append("%s authorises %r: sshkeyv rc=%d, want %s (%r)"
                           % (name, q, p.returncode, want_ok,
                              p.stdout.decode().strip()))
    for b in bad[:20]:
        print("  " + b)
    print("  %d certificates hold a principal with a wildcard character"
          % globs)
    if globs == 0:
        print("  CORPUS GAP: no certificate has a wildcard principal")
    print("%d certificates, %d verdicts compared, %d differ"
          % (certs, verdicts, vdiffer))
    print("%d authorisation questions, %d differ" % (auth, adiffer))
    return 1 if (vdiffer or adiffer or globs == 0) else 0


if __name__ == "__main__":
    sys.exit(main())
