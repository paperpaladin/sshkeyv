#!/usr/bin/env python3
"""Malformed public key lines, with ssh-keygen as the authority on whether
each one is malformed.

A refusal needs an outside authority as much as an answer does. Without
one, a parser that refuses valid input looks exactly like a careful parser:
the suite goes green and the program is useless. So each case here is put
to ssh-keygen -l as well, and the three outcomes are counted apart:

  refused by both      the case is malformed and sshkeyv says so
  over-refused         ssh-keygen reads it and sshkeyv will not; a defect
  under-refused        sshkeyv reads it and ssh-keygen will not; a defect

Cases where ssh-keygen and sshkeyv disagree are printed with the reason
sshkeyv gave, because "both refused" is only interesting when the reasons
are about the same thing.

Usage: refusecmp.py CORPUSDIR
"""
import base64
import os
import struct
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")


def sshstr(n, b):
    return struct.pack(">I", len(b)) + b


def cases(good_line):
    """(name, line) pairs. The good line is an ed25519 public key."""
    algo, b64, *rest = good_line.split()
    blob = base64.b64decode(b64)
    name, rest_blob = blob[4:4 + 11], blob[4 + 11:]
    out = []

    def mk(label, newblob, newalgo=None):
        out.append((label, "%s %s" % (newalgo or algo,
                                      base64.b64encode(newblob).decode())))

    out.append(("empty line", ""))
    out.append(("algorithm only", algo))
    out.append(("unknown algorithm", "ssh-nonesuch %s" % b64))
    out.append(("blob is not base64", "%s !!!!" % algo))
    out.append(("blob is base64 of nothing", "%s " % algo))
    # The two spellings of the algorithm name disagree.
    mk("name inside the blob is wrong",
       sshstr(0, b"ssh-ed25518") + rest_blob)
    mk("name outside the blob is wrong", blob, "ssh-rsa")
    # Truncation at every structural boundary.
    for cut in (1, 4, 5, 14, 15, 18, 19, 50):
        mk("blob truncated to %d bytes" % cut, blob[:cut])
    # A length field that points past the end.
    mk("key length claims 2^31",
       sshstr(0, b"ssh-ed25519") + struct.pack(">I", 1 << 31) + b"\x00" * 32)
    mk("key length claims 2^32-1",
       sshstr(0, b"ssh-ed25519") + struct.pack(">I", 0xffffffff) + b"\x00" * 32)
    # The right length field, the wrong amount of key.
    mk("ed25519 key is 31 bytes",
       sshstr(0, b"ssh-ed25519") + sshstr(0, b"\x01" * 31))
    mk("ed25519 key is 33 bytes",
       sshstr(0, b"ssh-ed25519") + sshstr(0, b"\x01" * 33))
    # Trailing rubbish after a complete key.
    mk("four trailing bytes", blob + b"\x00\x00\x00\x00")
    # An RSA key whose modulus mpint is negative, and one with a padded
    # modulus. Both are spellings OpenSSH's own writer never produces.
    rsa = (sshstr(0, b"ssh-rsa") + sshstr(0, b"\x01\x00\x01")
           + sshstr(0, b"\x80" + b"\x11" * 255))
    out.append(("rsa modulus is negative",
                "ssh-rsa " + base64.b64encode(rsa).decode()))
    rsa2 = (sshstr(0, b"ssh-rsa") + sshstr(0, b"\x01\x00\x01")
            + sshstr(0, b"\x00\x00" + b"\x11" * 255))
    out.append(("rsa modulus has two leading zero octets",
                "ssh-rsa " + base64.b64encode(rsa2).decode()))
    # An ECDSA key whose curve name does not match the algorithm, and one
    # with a compressed point.
    ec = (sshstr(0, b"ecdsa-sha2-nistp256") + sshstr(0, b"nistp384")
          + sshstr(0, b"\x04" + b"\x22" * 64))
    out.append(("ecdsa curve name does not match the algorithm",
                "ecdsa-sha2-nistp256 " + base64.b64encode(ec).decode()))
    ec2 = (sshstr(0, b"ecdsa-sha2-nistp256") + sshstr(0, b"nistp256")
           + sshstr(0, b"\x02" + b"\x22" * 32))
    out.append(("ecdsa point is compressed",
                "ecdsa-sha2-nistp256 " + base64.b64encode(ec2).decode()))
    return out


def main():
    d = sys.argv[1]
    with open(os.path.join(d, "ed25519.pub")) as f:
        good = f.readline().strip()
    work = os.path.join(d, "refuse")
    os.makedirs(work, exist_ok=True)
    both = over = under = 0
    notes = []
    all_cases = cases(good)
    for i, (label, line) in enumerate(all_cases):
        path = os.path.join(work, "case%02d.pub" % i)
        with open(path, "w") as f:
            f.write(line + "\n")
        a = subprocess.run([BIN, "fields", path], stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
        b = subprocess.run(["ssh-keygen", "-l", "-f", path],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        why = a.stderr.decode().strip().replace("\n", " ")
        if a.returncode != 0 and b.returncode != 0:
            both += 1
            notes.append("    refused by both: %s -- %s" % (label, why))
        elif a.returncode != 0:
            over += 1
            notes.append("  OVER-REFUSED ssh-keygen reads it: %s -- %s"
                         % (label, why))
        elif b.returncode != 0:
            under += 1
            notes.append("  UNDER-REFUSED ssh-keygen refuses it: %s" % label)
        else:
            notes.append("    read by both: %s" % label)
    for n in notes:
        print(n)
    print("%d cases, %d refused by both, %d over-refused, %d under-refused"
          % (len(all_cases), both, over, under))
    return 1 if (over or under) else 0


if __name__ == "__main__":
    sys.exit(main())
