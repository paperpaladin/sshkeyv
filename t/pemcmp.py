#!/usr/bin/env python3
"""The PEM armour itself, against the two readers that disagree about it.

Everything else in the suite feeds sshkeyv a well formed BEGIN/END block
and argues about what is inside it. Nothing bent the armour, so the
label-match rule, the missing-END rule and the leading-line rule in
src/pem.rs were written and never exercised: the only files that reached
them came out of ssh-keygen and openssl, which both write the same tidy
shape.

Two containers in this project are PEM, and the programs that read them
do not agree about how strict to be:

  the OpenSSH private key container, read by `ssh-keygen -y -f`, which is
  strict. It refuses a blank line before BEGIN and refuses a blank line
  after END.

  PKCS8 SubjectPublicKeyInfo, read by `openssl pkey -pubin`, which is
  lenient. It accepts a blank line before BEGIN, a line of prose before
  BEGIN, and anything at all after END.

So there is no single right answer, and a comparison that picked one
oracle would report the other's behaviour as a defect. Each case is asked
of the oracle for its own container, and the places where sshkeyv agrees
with one oracle and not the other are listed in KNOWN with what each
program does. A disagreement that is not in KNOWN is a failure, and so is
a KNOWN entry that has stopped disagreeing, because a record of a
difference that no longer exists is worse than no record.

Usage: pemcmp.py CORPUSDIR
"""
import os
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")

# (name, text -> text). Every one of them produces a file whose base64
# body is untouched, so anything either program says is about the armour.
CASES = [
    ("unmodified", lambda t: t),
    ("a blank line before BEGIN", lambda t: "\n" + t),
    ("a line of prose before BEGIN", lambda t: "here is a key:\n" + t),
    ("leading spaces on the BEGIN line", lambda t: "    " + t),
    ("a blank line after END", lambda t: t + "\n"),
    ("a line of prose after END", lambda t: t + "that was the key\n"),
    ("the END label does not match BEGIN", lambda t: relabel_end(t)),
    ("no END line", lambda t: drop_line(t, -1)),
    ("no BEGIN line", lambda t: drop_line(t, 0)),
    ("the END line is one dash short", lambda t: short_dash(t)),
    ("a header field after BEGIN", lambda t: header(t)),
    ("a blank line inside the body", lambda t: blank_inside(t)),
    ("trailing spaces on a body line", lambda t: trail_space(t)),
    ("CRLF line endings throughout", lambda t: t.replace("\n", "\r\n")),
    ("one body character outside the alphabet", lambda t: bad_char(t)),
    ("one body line removed", lambda t: drop_line(t, 2)),
]


def lines(t):
    return t.rstrip("\n").split("\n")


def join(ls):
    return "\n".join(ls) + "\n"


def relabel_end(t):
    ls = lines(t)
    ls[-1] = "-----END SOMETHING ELSE-----"
    return join(ls)


def drop_line(t, i):
    ls = lines(t)
    del ls[i]
    return join(ls)


def short_dash(t):
    ls = lines(t)
    ls[-1] = ls[-1][:-1]
    return join(ls)


def header(t):
    ls = lines(t)
    return join([ls[0], "Proc-Type: 4,ENCRYPTED", ""] + ls[1:])


def blank_inside(t):
    ls = lines(t)
    return join(ls[:2] + [""] + ls[2:])


def trail_space(t):
    ls = lines(t)
    ls[2] = ls[2] + "   "
    return join(ls)


def bad_char(t):
    ls = lines(t)
    # A character that is in no base64 alphabet, in the middle of a body
    # line, so the length stays a multiple of four and only the alphabet
    # check can refuse it.
    ls[2] = ls[2][:10] + "!" + ls[2][11:]
    return join(ls)


# Where sshkeyv agrees with one oracle and not the other, with what each
# program actually does. Measured, not guessed: the first run of this
# script is what produced the list, and src/pem.rs carried a comment
# claiming ssh-keygen tolerates leading whitespace, which it does not.
KNOWN = {
    ("openssh", "a blank line before BEGIN"):
        "openssl accepts one on a PKCS8 file and sshkeyv does too; "
        "ssh-keygen -y refuses it on this container",
    ("openssh", "CRLF line endings throughout"):
        "openssl reads a CRLF PKCS8 file and sshkeyv reads both; "
        "ssh-keygen -y refuses the CR",
    ("pkcs8", "a line of prose before BEGIN"):
        "openssl skips anything before BEGIN; sshkeyv refuses a non-blank "
        "line there, which is ssh-keygen's rule applied to both containers",
    ("pkcs8", "a blank line inside the body"):
        "openssl refuses a body with a blank line in it; ssh-keygen -y "
        "reads one, and sshkeyv reads both",
}


def run(*a, **kw):
    return subprocess.run(a, stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw).returncode == 0


def main():
    d = sys.argv[1]
    work = os.path.join(d, "pem")
    os.makedirs(work, exist_ok=True)
    # One of each container. The private key is the unencrypted ed25519
    # one, because ssh-keygen -y on an encrypted container asks for a
    # passphrase rather than answering the question.
    sources = [("openssh", os.path.join(d, "ed25519"),
                lambda p: run("ssh-keygen", "-y", "-f", p)),
               ("pkcs8", os.path.join(d, "ecdsa256.pkcs8"),
                lambda p: run("openssl", "pkey", "-pubin", "-in", p,
                              "-noout"))]

    n = agree = over = under = 0
    seen = set()
    bad = []
    for kind, src, oracle in sources:
        with open(src) as f:
            base = f.read()
        for i, (label, f) in enumerate(CASES):
            path = os.path.join(work, "%s-%02d" % (kind, i))
            text = f(base)
            with open(path, "w") as g:
                g.write(text)
            # ssh-keygen refuses a world-readable private key before it
            # looks at a byte of it, so without this every openssh case
            # reads as "the oracle refuses it" including the unmodified
            # one, and the whole comparison measures the file mode.
            os.chmod(path, 0o600)
            n += 1
            theirs = oracle(path)
            mine = run(BIN, "check", path)
            if theirs == mine:
                agree += 1
                if (kind, label) in KNOWN:
                    bad.append("%s/%s is recorded as a disagreement and both "
                               "programs now %s it"
                               % (kind, label, "read" if mine else "refuse"))
                continue
            seen.add((kind, label))
            if (kind, label) in KNOWN:
                print("    known: %s/%s -- %s"
                      % (kind, label, KNOWN[(kind, label)]))
                continue
            if mine:
                under += 1
                bad.append("UNDER-REFUSED %s/%s: the oracle refuses it, "
                           "sshkeyv reads it" % (kind, label))
            else:
                over += 1
                bad.append("OVER-REFUSED %s/%s: the oracle reads it, "
                           "sshkeyv refuses it" % (kind, label))

    for k in KNOWN:
        if k not in seen:
            bad.append("%s/%s is recorded as a disagreement and did not "
                       "disagree" % k)
    for line in bad:
        print("  " + line)
    print("%d cases, %d agree, %d over-refused, %d under-refused, "
          "%d known disagreements" % (n, agree, over, under, len(KNOWN)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
