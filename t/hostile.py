#!/usr/bin/env python3
"""Malformed input, in bulk, with the measurement being crashes and hangs.

Three families, all built from the real corpus so that every mutant is a
near miss rather than noise:

  every prefix of every file, at a stride, which is truncation at every
  structural boundary and in the middle of every length field;

  single bytes overwritten with 0xff, 0x7f, 0x80 and 0x00 across the first
  part of each file, which is where a length field becomes an index;

  the base64 payload of each key line mangled in place, so the container
  survives and the blob inside it does not.

What is measured is not opinions. A refusal is fine and a successful read
is fine; a signal, a Rust panic or a run that does not finish is not. The
release profile is panic = abort, so a panic shows up as exit 134, which
this program cannot produce any other way.

`make hostile` runs the whole sweep. `make test` passes --sample to take
a fraction of it, because the whole thing takes minutes and the suite
should not.

Usage: hostile.py CORPUSDIR [--sample N]
Prints "N inputs, M read, K refused, J crashed, I timed out".
"""
import base64
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# SSHKEYV_BIN lets the crash detection be pointed at a build that is known
# to abort, so that the sweep is watched finding something before it is
# believed when it finds nothing. make overread builds exactly that.
BIN = os.environ.get("SSHKEYV_BIN") or os.path.join(
    HERE, "..", "target", "release", "sshkeyv")
# sshkeyv's own exit codes. Anything else is a crash.
OK_CODES = {0, 1, 2, 3, 4, 5}


def mutants(data, name):
    """Yield (label, bytes)."""
    n = len(data)
    stride = max(1, n // 60)
    for cut in range(0, n, stride):
        yield ("prefix %d" % cut, data[:cut])
    yield ("prefix %d" % (n - 1), data[:n - 1])
    head = min(n, 140)
    for i in range(head):
        for v in (0xff, 0x7f, 0x80, 0x00):
            if data[i] == v:
                continue
            m = bytearray(data)
            m[i] = v
            yield ("byte %d -> %02x" % (i, v), bytes(m))
    # The base64 payload of a key line, mangled where the container stays
    # intact.
    try:
        parts = data.decode().split()
        if len(parts) >= 2:
            blob = bytearray(base64.b64decode(parts[1], validate=True))
            for i in range(0, min(len(blob), 80)):
                for v in (0xff, 0x00):
                    m = bytearray(blob)
                    m[i] = v
                    line = "%s %s %s\n" % (
                        parts[0], base64.b64encode(bytes(m)).decode(),
                        " ".join(parts[2:]))
                    yield ("blob byte %d -> %02x" % (i, v), line.encode())
    except Exception:
        pass


def run_batch(work, items):
    """Returns (codes, crashed) for a list of (label, bytes)."""
    paths = []
    for i, (label, b) in enumerate(items):
        p = os.path.join(work, "m%04d" % i)
        with open(p, "wb") as f:
            f.write(b)
        paths.append(p)
    try:
        r = subprocess.run([BIN, "check"] + paths, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=120)
        rc = r.returncode
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if rc not in OK_CODES:
        return None, "exit %d" % rc
    # check prints one line per file, so the split between read and
    # refused is per file and not per batch. Counting a whole batch as
    # refused because one file in it was would have reported 3000 refusals
    # and no reads, which is the shape of a sweep that is not measuring
    # anything.
    out = r.stdout.decode(errors="replace")
    ok = sum(1 for l in out.splitlines() if ": ok," in l)
    refused = sum(1 for l in out.splitlines() if ": REFUSED: " in l)
    if ok + refused != len(paths):
        return None, "check printed %d lines for %d files" % (
            ok + refused, len(paths))
    return (ok, refused), None


def main():
    d = sys.argv[1]
    sample = None
    if "--sample" in sys.argv:
        sample = int(sys.argv[sys.argv.index("--sample") + 1])
    work = os.path.join(d, "hostile")
    os.makedirs(work, exist_ok=True)
    rng = random.Random(20261021)

    sources = []
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            sources.append((name, f.read()))

    all_items = []
    for name, data in sources:
        for label, b in mutants(data, name):
            all_items.append(("%s: %s" % (name, label), b))
    total = len(all_items)
    if sample is not None and sample < total:
        all_items = rng.sample(all_items, sample)

    read = refused = crashed = timed = 0
    bad = []
    BATCH = 200
    for i in range(0, len(all_items), BATCH):
        chunk = all_items[i:i + BATCH]
        rc, err = run_batch(work, chunk)
        if err is None:
            read += rc[0]
            refused += rc[1]
            continue
        # Something in this batch crashed or hung. Find which.
        for label, b in chunk:
            one = [(label, b)]
            rc1, err1 = run_batch(work, one)
            if err1 is None:
                read += rc1[0]
                refused += rc1[1]
            elif err1 == "timeout":
                timed += 1
                bad.append("TIMED OUT %s" % label)
            else:
                crashed += 1
                bad.append("CRASHED (%s) %s" % (err1, label))
                with open(os.path.join(work, "crash-%d" % crashed), "wb") as f:
                    f.write(b)
    # Terminal findings first: a crash must not be pushed off the end of
    # the list by a pile of timeouts or the other way round.
    bad.sort(key=lambda s: 0 if s.startswith("CRASHED") else 1)
    for b in bad[:20]:
        print("  " + b)
    print("  built from %d corpus files, %d mutants available%s"
          % (len(sources), total,
             ", %d sampled" % len(all_items) if sample else ""))
    print("%d inputs, %d read, %d refused, %d crashed, %d timed out"
          % (len(all_items), read, refused, crashed, timed))
    return 1 if (crashed or timed) else 0


if __name__ == "__main__":
    sys.exit(main())
