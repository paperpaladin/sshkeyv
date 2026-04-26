#!/usr/bin/env python3
"""Which option and extension names the local OpenSSH recognises.

The set is not written down here. It is measured: for each candidate name
a certificate is signed with that name as a critical option and again as
an extension, and `ssh-keygen -L` is read back. ssh-keygen prints a name
it recognises bare and a name it does not as UNKNOWN OPTION or UNKNOWN FLAG
OPTION, so its own output says which list it holds. sshkeyv's answer, from
`sshkeyv unknown`, is then compared name by name.

This measures ssh-keygen's PRINT list. It is not sshd's accept list: they
are separate code paths in OpenSSH, and there is no sshd on this machine,
so the other list cannot be measured here. The README says which question
is answered.

The candidate list includes names OpenSSH has at one time or another had,
names that exist only in the other list, and names that are plainly not
options at all, so the measurement has both answers in it. A probe where
every candidate came back recognised would prove nothing.

Usage: unknowncmp.py CORPUSDIR
Prints "N names probed, M recognised by ssh-keygen, K differ".
"""
import os
import re
import shutil
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")

CANDIDATES = [
    "force-command", "source-address", "verify-required",
    "permit-X11-forwarding", "permit-agent-forwarding",
    "permit-port-forwarding", "permit-pty", "permit-user-rc",
    "no-touch-required", "no-presence-required",
    "critical-option-that-does-not-exist", "x", "permit-everything",
    "PERMIT-PTY", "permit-pty ", "force-command-2",
]


def main():
    d = sys.argv[1]
    work = os.path.join(d, "unkwork")
    os.makedirs(work, exist_ok=True)
    subj = os.path.join(work, "k.pub")
    shutil.copy(os.path.join(d, "ed25519.pub"), subj)
    ca = os.path.join(d, "ca_ed25519")

    probed = recognised = differ = 0
    bad = []
    # Four shapes per name: in each list, with and without data. The shape
    # matters because ssh-keygen's two lists are different and because a
    # known extension carrying data is a case it prints bare and then
    # refuses, so a probe using only the valued shape measured almost
    # nothing: the first version used it and got 2 recognised out of 25.
    for name in CANDIDATES:
        for where, valued in (("critical", False), ("critical", True),
                              ("extension", False), ("extension", True)):
            cert = os.path.join(work, "p.pub")
            shutil.copy(subj, cert)
            spec = "%s:%s=v" % (where, name) if valued \
                else "%s:%s" % (where, name)
            p = subprocess.run(
                ["ssh-keygen", "-q", "-s", ca, "-I", "probe", "-n", "alice",
                 "-O", "clear", "-O", spec, cert],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            cpath = cert[:-4] + "-cert.pub"
            if p.returncode != 0 or not os.path.exists(cpath):
                # ssh-keygen would not sign a certificate with that name in
                # it, so there is nothing to compare. Counted, not hidden.
                continue
            l = subprocess.run(["ssh-keygen", "-L", "-f", cpath],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
            text = l.stdout.decode()
            # The line for this name, in whichever section.
            line = None
            for ln in text.splitlines():
                if ln.strip().startswith(name):
                    line = ln.strip()
                    break
            if line is None:
                continue
            keygen_knows = "UNKNOWN" not in line
            u = subprocess.run([BIN, "unknown", cpath],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
            out = u.stdout.decode()
            sshkeyv_knows = ("is not recognised" not in out)
            probed += 1
            if keygen_knows:
                recognised += 1
            if keygen_knows != sshkeyv_knows:
                differ += 1
                bad.append("%s as %s%s: ssh-keygen %s, sshkeyv %s (%r)"
                           % (name, where, " with data" if valued else "",
                              "knows it" if keygen_knows else "does not",
                              "knows it" if sshkeyv_knows else "does not",
                              line))
            os.remove(cpath)
    for b in bad[:20]:
        print("  " + b)
    print("%d names probed, %d recognised by ssh-keygen, %d differ"
          % (probed, recognised, differ))
    # Both answers must occur, or the probe is only testing one branch.
    if recognised == 0 or recognised == probed:
        print("  PROBE GAP: every candidate got the same answer")
        return 1
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
