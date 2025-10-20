#!/usr/bin/env python3
"""A third parser for the SSH wire format, in Python, with struct and no
key knowledge at all.

It exists because ssh-keygen writes the corpus and ssh-keygen reads it
back, so one bug present in both halves of OpenSSH would be invisible. This
file knows that a string is a four-byte big-endian length followed by that
many bytes, and nothing else. It does not know what a key is.

It walks top-level strings from offset 0 until the blob ends or a length
runs past the end, and prints index, offset, length and the bytes, using
the same text-or-hex rule `sshkeyv blob` uses. A blob that is not a flat
list of strings, which every certificate is not, stops partway through at
a particular offset, and the offset is part of what is compared: two
parsers that stop at different places disagree even when every line they
both printed matches.

Usage: wire.py CORPUSDIR
Prints "N blobs, M lines compared, K differ, J stop-offsets differ".
"""
import os
import struct
import subprocess
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "target", "release", "sshkeyv")


def blob_of_file(path):
    """The base64 field out of a public key line or a bare blob.
    Deliberately a different code path from sshkeyv's."""
    with open(path, "rb") as f:
        raw = f.read()
    line = None
    for l in raw.decode("utf-8", "replace").splitlines():
        if l.strip():
            line = l.strip()
            break
    if line is None:
        return None
    parts = line.split()
    if len(parts) >= 2 and ("-" in parts[0] or "@" in parts[0]):
        field = parts[1]
    else:
        field = parts[0]
    import base64
    try:
        return base64.b64decode(field, validate=True)
    except Exception:
        return None


def render(s):
    if s and all(0x20 <= c < 0x7f for c in s):
        return "text:" + s.decode()
    return "hex:" + s.hex()


def walk(b):
    """Returns (lines, stop_offset). stop_offset is len(b) when the blob is
    a flat list of strings and the offset of the bad length otherwise."""
    lines = []
    o = 0
    i = 0
    while o < len(b):
        if len(b) - o < 4:
            return lines, o
        (n,) = struct.unpack(">I", b[o:o + 4])
        if len(b) - o - 4 < n:
            return lines, o
        # The offset printed is where the string starts, which is its own
        # length field, not its data. sshkeyv prints the same.
        lines.append("%d\t%d\t%d\t%s" % (i, o, n, render(b[o + 4:o + 4 + n])))
        o += 4 + n
        i += 1
    return lines, o


def main():
    d = sys.argv[1]
    names = sorted(os.listdir(d))
    blobs = 0
    compared = 0
    differ = 0
    stopdiff = 0
    bad = []
    for name in names:
        # RFC4716 containers join this comparison when the reader for
        # them exists; a container neither side reads proves nothing.
        if not name.endswith(".pub"):
            continue
        path = os.path.join(d, name)
        b = blob_of_file(path)
        if b is None:
            continue
        want, want_stop = walk(b)
        p = subprocess.run([BIN, "blob", path], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        got = []
        for line in p.stdout.decode().splitlines():
            if line.startswith(name) or "\t" not in line:
                continue
            got.append(line)
        # sshkeyv names the offset of the length field it could not follow;
        # a clean walk to the end prints nothing on stderr.
        err = p.stderr.decode()
        if "claims" in err or "want" in err:
            got_stop = int(err.rsplit("at offset ", 1)[1].split()[0]
                           .rstrip(",")) if "at offset " in err else -1
        else:
            got_stop = len(b)
        blobs += 1
        if got_stop != want_stop:
            stopdiff += 1
            bad.append("%s: stop offset %d, python says %d"
                       % (name, got_stop, want_stop))
        n = max(len(got), len(want))
        for k in range(n):
            compared += 1
            g = got[k] if k < len(got) else "<missing>"
            w = want[k] if k < len(want) else "<missing>"
            if g != w:
                differ += 1
                bad.append("%s line %d: %r vs python %r" % (name, k, g, w))
    for b in bad[:20]:
        print("  " + b)
    print("%d blobs, %d lines compared, %d differ, %d stop-offsets differ"
          % (blobs, compared, differ, stopdiff))
    return 1 if (differ or stopdiff) else 0


if __name__ == "__main__":
    sys.exit(main())
