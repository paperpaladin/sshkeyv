#!/usr/bin/env python3
"""Mutate the source, rebuild, and require the suite to notice.

Run it with `make mutants`, not as part of `make test`: each mutant is a
full rebuild plus a set of comparison scripts.

Each entry is one edit to one file. The edit must match exactly once,
which is checked, because a mutation that silently applies nowhere
reports a kill it has not earned. Each entry also names WHICH comparisons
to run, which is the point of the exercise: a curve mutant checked only
by the base64 comparison would report a survivor it has not earned
either.

A mutant is killed when one of the named comparisons exits non-zero.
Survivors are printed with the reason, and an entry marked "survives"
that dies is reported too, because the table is a record of what is and
is not tested and a record that has stopped being true is worse than
none.

Every mutant below was run before being written down, and the survivors
are survivors because nothing in the corpus can reach them, not because
nobody looked.

Usage: mutants.py [--only SUBSTRING]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Each comparison, as (script, extra arguments). "C" is replaced by the
# corpus directory.
SCRIPTS = {
    "b64":      ("b64cmp.py", []),
    "wire":     ("wire.py", ["C"]),
    "hash":     ("hashcmp.py", []),
    "fp":       ("fpcmp.py", ["C", "sha256", "md5", "sha1", "bubblebabble"]),
    "big":      ("bigcmp.py", ["C"]),
    "field":    ("fieldcmp.py", ["C"]),
    "cert":     ("certcmp.py", ["C"]),
    "show":     ("showcmp.sh", ["C"]),
    "time":     ("timecmp.sh", []),
    "valid":    ("validcmp.py", ["C"]),
    "priv":     ("privcmp.py", ["C"]),
    "sig":      ("sigcmp.py", ["C"]),
    "check":    ("checkcmp.sh", ["C"]),
    "unknown":  ("unknowncmp.py", ["C"]),
    "craft":    ("craft.py", ["C"]),
    "count":    ("countcmp.py", ["C"]),
    "convert":  ("convertcmp.py", ["C"]),
    "sshsig":   ("sshsigcmp.py", ["C"]),
    "curve":    ("curvecmp.py", []),
    "eccase":   ("eccases.py", ["C"]),
    "ca":       ("cacmp.sh", ["C"]),
    "forge":    ("forge.py", ["C"]),
    "small":    ("smallorder.py", ["C"]),
    "edcase":   ("edcases.py", ["C"]),
    "refuse":   ("refusecmp.py", ["C"]),
    "det":      ("determinism.sh", ["C"]),
    "pem":      ("pemcmp.py", ["C"]),
}

# (name, file, from, to, comparisons, expected)
MUTANTS = [
    ("wire: a string may claim one byte more than remains", "src/wire.rs",
     "        if self.remaining() < n {\n            return Err(format!(\n"
     "                \"{}: string at offset {} claims {} bytes, {} left\",",
     "        if self.remaining() + 1 < n {\n            return Err(format!(\n"
     "                \"{}: string at offset {} claims {} bytes, {} left\",",
     ["wire", "refuse", "field", "check"], "survives"),
    ("wire: trailing bytes after a key blob are ignored", "src/key.rs",
     "        if !self.algo.cert {\n            r.end()?;\n        }",
     "", ["refuse"], "killed"),
    ("wire: a boolean-free reader accepts a short mpint", "src/wire.rs",
     "        if b[0] & 0x80 != 0 {\n            return Err(format!(\n"
     "                \"{}: mpint at offset {} is negative\",",
     "        if false {\n            return Err(format!(\n"
     "                \"{}: mpint at offset {} is negative\",",
     ["refuse"], "killed"),
    ("b64: a length that is not a multiple of 4 is accepted", "src/b64.rs",
     "    if s.len() % 4 != 0 {", "    if false {", ["b64"], "killed"),
    ("b64: the unused bits of the last character need not be zero",
     "src/b64.rs",
     "    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {",
     "    if false {", ["b64", "field"], "survives"),
    ("hash: the padding stops two bytes after the message", "src/hash.rs",
     "    while (n + lenbytes) % block != 0 {",
     "    while (n + lenbytes) % block != 0 && n < data.len() + 2 {",
     ["hash"], "killed"),
    ("hash: MD5's length is written big-endian", "src/hash.rs",
     "    let tail: Vec<u8> = m[n - 8..].iter().rev().cloned().collect();\n"
     "    m[n - 8..].copy_from_slice(&tail);", "",
     ["hash", "fp"], "killed"),
    ("hash: SHA-1's fourth round constant is the third's", "src/hash.rs",
     "                _ => (b ^ c ^ d, 0xca62c1d6),",
     "                _ => (b ^ c ^ d, 0x8f1bbcdc),", ["hash", "fp"],
     "killed"),
    ("fp: a certificate is fingerprinted whole", "src/fp.rs",
     "        digest(kind, &subject),", "        digest(kind, &k.blob),",
     ["fp"], "killed"),
    ("fp: the bubblebabble seed never advances", "src/fp.rs",
     "                seed = (seed * 5 + b0 * 7 + b1) % 36;", "",
     ["fp"], "killed"),
    ("cert: principals read as a comma-separated name-list",
     "src/cert.rs",
     "        let principals = string_seq(r.string()?, \"principals\")?;",
     "        let principals = {\n            let s = r.text()?;\n"
     "            if s.is_empty() { Vec::new() } else "
     "{ s.split(',').collect() }\n        };",
     ["cert", "valid"], "killed"),
    ("cert: the signed range is taken after the signature", "src/cert.rs",
     "        let tbs = r.consumed();\n        let signature = r.string()?;",
     "        let signature = r.string()?;\n        let tbs = r.consumed();",
     ["sig", "ca"], "killed"),
    ("cert: an empty validity window is not reported", "src/ask.rs",
     "    if a > b {", "    if false {", ["craft", "valid"], "killed"),
    ("cert: the principal limit is 1024", "src/cert.rs",
     "pub const MAX_PRINCIPALS: usize = 256;",
     "pub const MAX_PRINCIPALS: usize = 1024;", ["craft"], "killed"),
    ("cert: a certificate type other than 1 or 2 is accepted",
     "src/cert.rs",
     "        if cert_type != TYPE_USER && cert_type != TYPE_HOST {",
     "        if false {", ["cert", "craft"], "killed"),
    ("show: Principals: has no trailing space", "src/show.rs",
     "        println!(\"        Principals: \");",
     "        println!(\"        Principals:\");", ["show"], "killed"),
    ("show: the unknown-option length is the string's, not the data's",
     "src/show.rs", "            o.data.len()",
     "            o.data.len() - 4", ["show", "craft"], "killed"),
    ("show: a known flag extension prints as unknown", "src/show.rs",
     "    if !in_critical && FLAG_EXTENSIONS.contains(&o.name) {",
     "    if false {", ["show", "unknown"], "killed"),
    ("time: the year-of-era expression drops its last term",
     "src/time.rs",
     "    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;",
     "    let yoe = (doe - doe / 1460 + doe / 36524) / 365;",
     ["time", "show"], "killed"),
    ("time: days_from_civil is one day out", "src/time.rs",
     "    let doy = (153 * mp + 2) / 5 + d as u64 - 1;",
     "    let doy = (153 * mp + 2) / 5 + d as u64;", ["time"], "killed"),
    ("time: the forever sentinel prints as a date", "src/time.rs",
     "        (0, FOREVER) => \"forever\".to_string(),",
     "        (0, 1) => \"forever\".to_string(),", ["show"], "killed"),
    ("bignum: Knuth D never adds the divisor back", "src/bignum.rs",
     "                qhat -= 1;\n                let mut c = 0u64;\n"
     "                for i in 0..n {\n                    let s = u[i + j] "
     "as u64 + vn.l[i] as u64 + c;\n                    u[i + j] = s as u32;"
     "\n                    c = s >> 32;\n                }\n"
     "                u[j + n] = (u[j + n] as u64 + c) as u32;", "",
     ["big"], "killed"),
    ("bignum: the qhat estimate is never corrected", "src/bignum.rs",
     "                if qhat >= b\n                    || qhat * vn.l[n - 2]"
     " as u64\n                        > (rhat << 32) | u[j + n - 2] as u64\n"
     "                {", "                if qhat >= b {",
     ["big"], "killed"),
    ("bignum: a subtraction may go negative", "src/bignum.rs",
     "        debug_assert!(self.cmp(o) != std::cmp::Ordering::Less);", "",
     ["big"], "survives"),
    ("rsa: the recovered block is searched for the DigestInfo",
     "src/rsa.rs", "    if em != want {",
     "    if !em.windows(di.len()).any(|w| w == di.as_slice()) {",
     ["forge", "sig"], "killed"),
    ("rsa: a modulus below 1024 bits is accepted", "src/rsa.rs",
     "    if bits < 1024 {", "    if false {", ["forge"], "killed"),
    ("rsa: the signature length need not equal the modulus length",
     "src/rsa.rs", "    if sig.len() != k {", "    if false {",
     ["sig", "forge"], "killed"),
    ("ed25519: S is not required to be below the group order",
     "src/ed25519.rs", "    if s.cmp(&big_l) != std::cmp::Ordering::Less {",
     "    if false {", ["edcase"], "killed"),
    ("ed25519: a y at or above p is accepted", "src/ed25519.rs",
     "    if y.cmp(&f.p) != std::cmp::Ordering::Less {", "    if false {",
     ["edcase"], "killed"),
    ("ed25519: x = 0 with the sign bit set is accepted", "src/ed25519.rs",
     "    if x.is_zero() && x_sign == 1 {", "    if false {",
     ["small"], "killed"),
    ("ed25519: a small-order signing key is not reported", "src/sig.rs",
     "                Ok(()) => match crate::ed25519::small_order(pk) {\n"
     "                    Ok(true) =>",
     "                Ok(()) => match crate::ed25519::small_order(pk) {\n"
     "                    Ok(false) =>", ["small"], "killed"),
    ("ed25519: the square root correction is dropped", "src/ed25519.rs",
     "    if f.mul(&f.sqr(&x), &v) != u {\n        x = f.mul(&x, &sqrt_m1());"
     "\n    }", "", ["sig", "ca"], "killed"),
    ("ecdsa: r or s may be zero", "src/ecdsa.rs",
     "    if rn.is_zero() || sn.is_zero() {", "    if false {",
     ["eccase"], "killed"),
    ("ecdsa: r or s may be at or above the group order", "src/ecdsa.rs",
     "    if rn.cmp(&pr.n) != std::cmp::Ordering::Less\n        || sn.cmp("
     "&pr.n) != std::cmp::Ordering::Less\n    {", "    if false {",
     ["eccase"], "killed"),
    ("ecdsa: the public point need not be on the curve", "src/ecdsa.rs",
     "    if lhs != rhs {\n        return Err(\"the public point is not on "
     "the curve\".to_string());\n    }", "", ["eccase"], "killed"),
    ("ecdsa: a coordinate may be at or above the field prime",
     "src/ecdsa.rs",
     "    if qx.cmp(&pr.p) != std::cmp::Ordering::Less\n        || qy.cmp("
     "&pr.p) != std::cmp::Ordering::Less\n    {", "    if false {",
     ["eccase"], "killed"),
    ("ecdsa: the digest is not truncated to the order's bit length",
     "src/ecdsa.rs", "    if dbits > nbits {", "    if false {",
     ["sig", "ca", "sshsig"], "survives"),
    ("ecdsa: P-384 uses SHA-256", "src/ecdsa.rs",
     "        Curve::P384 => hash::sha384(msg).to_vec(),",
     "        Curve::P384 => hash::sha256(msg).to_vec(),",
     ["sig", "sshsig"], "killed"),
    ("ecdsa: one hex digit of the P-521 order is dropped", "src/ecdsa.rs",
     "                    6409\"),", "                    409\"),",
     ["curve"], "killed"),
    ("privkey: the private section's RSA fields are read in public order",
     "src/privkey.rs", "            if algo.plain == \"ssh-rsa\" {",
     "            if false {", ["priv"], "killed"),
    ("privkey: the two check words need not match", "src/privkey.rs",
     "        if c1 != c2 {", "        if false {", ["priv"], "killed"),
    ("privkey: the padding is not checked", "src/privkey.rs",
     "            if p as usize != i + 1 {", "            if false {",
     ["priv"], "killed"),
    ("privkey: the two copies of the public key need not agree",
     "src/privshow.rs", "    if p.public != c.public[0] {",
     "    if false {", ["priv"], "killed"),
    ("privkey: a container may hold any number of keys",
     "src/privkey.rs", "        if nkeys != 1 {", "        if false {",
     ["priv"], "killed"),
    ("convert: the EC point loses its last byte on the PKCS8 read path",
     "src/convert.rs", "        w.string(curve.name().as_bytes());\n"
     "        w.string(key);",
     "        w.string(curve.name().as_bytes());\n"
     "        w.string(&key[..key.len() - 1]);", ["convert", "det"],
     "killed"),
    ("convert: a long-form DER length that fits in short form is accepted",
     "src/der.rs", "        if v < 0x80 {", "        if false {",
     ["convert"], "survives"),
    ("convert: the RFC4716 continuation backslash is ignored",
     "src/convert.rs", "    match l.strip_suffix('\\\\') {\n        Some(s) "
     "=> (s, true),", "    match None::<&str> {\n        Some(s) => "
     "(s, true),", ["convert"], "killed"),
    ("sshsig: the namespace in the file is not compared", "src/main.rs",
     "    if s.namespace != namespace.as_str() {", "    if false {",
     ["sshsig"], "killed"),
    ("sshsig: the message is hashed with SHA-512 whatever the file says",
     "src/sshsig.rs", "            \"sha256\" => hash::sha256(msg).to_vec(),",
     "            \"sha256\" => hash::sha512(msg).to_vec(),",
     ["sshsig"], "killed"),
    ("counts: an unordered options list is not noticed", "src/counts.rs",
     "    names.windows(2).all(|w| w[0] <= w[1])", "    true",
     ["craft"], "killed"),
    ("key: the two spellings of the algorithm name need not agree",
     "src/key.rs", "        if inner != name {", "        if false {",
     ["refuse"], "killed"),
    ("pem: the END label need not match the BEGIN label", "src/pem.rs",
     "            if name != label {", "            if false {",
     ["pem"], "killed"),
    ("pem: a block with no END line is accepted", "src/pem.rs",
     "    if !closed {", "    if false {", ["pem"], "killed"),
    ("pem: leading whitespace on a line is trimmed away", "src/pem.rs",
     "    for l in lines.by_ref() {\n        let l = l.trim_end();",
     "    for l in lines.by_ref() {\n        let l = l.trim();",
     ["pem"], "killed"),
    ("verify: an untrusted CA is accepted", "src/main.rs",
     "                if !trusted.is_empty()\n                    && !trusted"
     ".iter().any(|t| t == c.signature_key)\n                {",
     "                if false {", ["ca"], "killed"),
]


# Why each survivor survives. Every one of these is unreachable from the
# corpus or equivalent, and each says which, because "survivor" on its
# own is a result nobody can act on. A survivor whose reason is not here
# is reported as a table error.
SURVIVOR_REASONS = {
    "wire: a string may claim one byte more than remains":
        "equivalent in effect. self.bytes(n) applies its own exact check "
        "immediately afterwards and refuses the same inputs; only the "
        "wording of the message and the offset in it change, and the "
        "offsets differ by four, so an input could tell them apart. The "
        "malformed sweep contains such inputs and does not look at "
        "messages. Its size is not quoted here because it moves by a few "
        "between runs: the corpus is freshly generated and a key whose "
        "modulus has a leading zero octet makes a longer line.",
    "b64: the unused bits of the last character need not be zero":
        "removing it makes sshkeyv AGREE with python's base64 on four "
        "inputs it currently over-refuses, and no comparison here fails "
        "on an over-refusal becoming an acceptance. The strictness is a "
        "decision recorded in the README, not a property with an oracle.",
    "bignum: a subtraction may go negative":
        "unreachable. Every call to sub() is guarded by a cmp() at the "
        "call site, so the assertion has never fired and no input makes "
        "it fire. It is there for the next caller.",
    "ecdsa: the digest is not truncated to the order's bit length":
        "unreachable for the three curves OpenSSH uses. SHA-256 with "
        "P-256 and SHA-384 with P-384 are the same width as the order, "
        "and SHA-512 with P-521 is nine bits narrower, so the branch "
        "never runs. It is written out because leaving it out would be "
        "right by accident.",
    "convert: a long-form DER length that fits in short form is accepted":
        "removing it makes sshkeyv agree with openssl, which reads BER "
        "lengths. Same shape as the base64 one: the comparison counts "
        "over-refusals and does not fail on them, because the "
        "strictness is a decision and openssl is not wrong.",
}


def build_tree(dst):
    os.makedirs(dst, exist_ok=True)
    for f in ("Cargo.toml", "Cargo.lock", "Makefile"):
        shutil.copy(os.path.join(ROOT, f), dst)
    for sub in ("src", "t"):
        shutil.copytree(os.path.join(ROOT, sub), os.path.join(dst, sub),
                        dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__"))


def main():
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]

    work = tempfile.mkdtemp(prefix="sshkeyv.mutants.")
    corpus = os.path.join(work, "corpus")
    subprocess.run(["sh", os.path.join(HERE, "mkcorpus.sh"), corpus],
                   stdout=subprocess.DEVNULL, check=True)

    killed = survived = wrong = skipped = 0
    rows = []
    for name, rel, old, new, comps, expect in MUTANTS:
        if only and only not in name:
            skipped += 1
            continue
        tree = os.path.join(work, "tree")
        shutil.rmtree(tree, ignore_errors=True)
        build_tree(tree)
        path = os.path.join(tree, rel)
        with open(path) as f:
            src = f.read()
        n = src.count(old)
        if n != 1:
            wrong += 1
            rows.append(("PATTERN MATCHED %d TIMES" % n, name, ""))
            print("  PATTERN MATCHED %d TIMES: %s" % (n, name))
            continue
        with open(path, "w") as f:
            f.write(src.replace(old, new, 1))
        b = subprocess.run(["cargo", "build", "--release", "--offline"],
                           cwd=tree, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE)
        if b.returncode != 0:
            wrong += 1
            rows.append(("DOES NOT COMPILE", name, ""))
            print("  DOES NOT COMPILE: %s" % name)
            print("      " + b.stderr.decode().strip().splitlines()[0])
            continue
        died = None
        for c in comps:
            script, extra = SCRIPTS[c]
            args = [corpus if a == "C" else a for a in extra]
            runner = (["sh"] if script.endswith(".sh") else ["python3"])
            r = subprocess.run(runner + [os.path.join(tree, "t", script)]
                               + args, cwd=tree, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=900)
            if r.returncode != 0:
                died = c
                break
        if died:
            killed += 1
            got = "killed"
        else:
            survived += 1
            got = "survives"
        rows.append((got, name, died or " ".join(comps)))
        if got != expect:
            wrong += 1
            print("  TABLE IS WRONG: %s is recorded as %s and %s"
                  % (name, expect, got))
        print("  %-8s %-62s %s" % (got, name[:62], died or ""))
    shutil.rmtree(work, ignore_errors=True)
    missing = [n for got, n, _ in rows
               if got == "survives" and n not in SURVIVOR_REASONS]
    if missing:
        wrong += len(missing)
        for n in missing:
            print("  SURVIVOR WITH NO REASON RECORDED: %s" % n)
    if not only:
        print()
        print("survivors:")
        for got, n, _ in rows:
            if got == "survives":
                print("  %s" % n)
                for ln in SURVIVOR_REASONS.get(n, "").split(". "):
                    if ln.strip():
                        print("      %s." % ln.strip().rstrip("."))
    print("%d mutants, %d killed, %d survived, %d table errors"
          % (killed + survived, killed, survived, wrong))
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
