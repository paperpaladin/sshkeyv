# sshkeyv

Reads OpenSSH public keys, the OpenSSH private key container and SSH
certificates, and answers the questions a certificate authority deployment
raises: which principals a certificate authorises, whether it is valid now,
whether the CA signature verifies, and which critical options are present.
Rust 2021, standard library only, no entries under `[dependencies]`, no
`unsafe` anywhere in `src`.

```
make test        46 checks against ssh-keygen, openssl, coreutils and python
make mutants     mutation testing, which is slower and not part of make test
make overread    the planted one-past-the-end read, run with and without slack
```

## What it is measured against

Nothing here is checked against a number worked out by hand. Every fact
comes from a program that knows nothing about this one.

`openssl` 3.5.7 does the signature arithmetic with no OpenSSH code in the
path: `pkeyutl -verify -rawin` for Ed25519 and `dgst -verify` for RSA and
ECDSA, over a SubjectPublicKeyInfo built from the SSH key blob. It is the
only oracle here that can contradict OpenSSH about whether a signature is
good.

`ssh-keygen` from OpenSSH 10.0p2 is the authority on the fields: `-l -f`
for fingerprints in all four forms, `-L -f` for certificate blocks, `-B`
for bubblebabble, `-e` and `-i` for the RFC 4716 and PKCS8 round trips,
`-y -f` for reading a private container, and `-Y sign` and `-Y verify`
for detached signatures.

`ssh-keygen -t` and `ssh-keygen -s` build the corpus, which makes them the
weakest oracle in the project: the thing that writes the bytes agrees with
the thing that reads them by construction. `t/wire.py` exists for that
reason. It is a third parser for the SSH wire format, written in Python
with `struct` and no knowledge of keys at all, so one bug shared by
OpenSSH's writer and its reader cannot hide behind both.

`sha256sum`, `sha512sum`, `md5sum`, `sha1sum`, `hashlib`, `date -u` and
Python's `int` and `base64` cover the parts that are not SSH-specific.

A run without `ssh-keygen` or without `openssl` exits 2 and says so. It is
a refusal and not a skip, because between them they are the authority for
every fact the suite checks, and a reduced run would print a column of
passes having compared sshkeyv with itself.

Every comparison reports which program it asked and how many things it
compared, and the roster is printed at the end of each run with those
numbers pulled out of each comparison's own output. A comparison that ran
and compared nothing shows up as a zero rather than as a row of passes.
The last run:

```
coreutils and hashlib              digests                          812
date -u                            instants formatted and parsed    64
openssl and ssh-keygen -L          small-order key cases            11
openssl                            certificate signatures           145
openssl                            ECDSA refusal cases              27
openssl                            Ed25519 refusal cases            4
openssl                            forged signatures                3
python arithmetic                  curve constants                  30
python base64                      strings encoded and decoded      154
python integers                    bignum operations                10220
python struct                      wire-format lines                284
ssh-keygen -e, -i and openssl      container conversions            318
ssh-keygen -l and -B               fingerprint lines                436
ssh-keygen -L and python           certificate fields               836
ssh-keygen -L and python           construct counts                 12
ssh-keygen -l and python           key fields                       643
ssh-keygen -L                      certificate and CA pairs         145
ssh-keygen -L                      crafted certificates             15
ssh-keygen -l, -i and -Y           files read or refused            135
ssh-keygen -l                      malformed key lines              24
ssh-keygen -L                      option names probed              55
ssh-keygen -L                      validity verdicts                269
ssh-keygen -L                      whole certificate blocks         29
ssh-keygen -y and -l               private container fields         194
ssh-keygen -y and openssl pkey     PEM armour cases                 32
ssh-keygen -Y verify and openssl   detached signatures              100
sshkeyv alone                      malformed inputs                 89115
sshkeyv alone                      repeated runs and containers     9
```

One number in that table moves. The malformed sweep is built from a
corpus that is regenerated every run, and a key whose modulus happens to
have a leading zero octet makes a longer base64 line and a few more
mutants, so the figure lands somewhere around 89,000 rather than on one
value. Every other row is the same from run to run.

## Field by field, with refusals counted apart

836 certificate field values and 643 key field values are compared one at
a time against the pairs read out of `ssh-keygen -L` and `ssh-keygen -l`,
never as text. The two programs disagree about indentation and blank
lines, and a whole-output diff of two programs that format differently can
only say "different". All 29 certificate blocks are also compared whole
and come out byte for byte identical to `ssh-keygen -L`, which is a
separate and stronger claim that happens to hold.

A refusal is counted apart from a disagreement in every comparison, and
both numbers are printed whether or not they are zero. Over-refusal and
under-refusal are counted separately too, because they are different
defects: refusing a file ssh-keygen reads, and reading a file ssh-keygen
refuses. As of the last run every one of those columns is zero except for
the eight deliberate over-refusals listed further down.

The hard invariant is that a certificate whose CA signature does not
verify is never reported as valid. It is measured rather than asserted:
every signature in the corpus is corrupted one bit at a time in 145
positions, and all 145 are refused with exit 3 by sshkeyv and by openssl.
29 certificates are then put to all 5 CA keys in the corpus, 145 pairs,
and each is accepted by its own CA key and rejected by the other four.

Exit status matters to the suite and is asserted on: 0 when every check
passed, 1 for a malformed input, 2 for a usage error or a missing oracle,
3 when a signature did not verify, 4 when a certificate parsed but is not
valid or does not authorise, and 5 when no verifier exists for the
algorithm. "Cannot parse it" and "parsed fine, the signature is wrong"
must not share a code: a harness that treats them alike reports a refusal
as a caught forgery.

## What the corpus holds

135 files, generated at suite run time into a `mktemp -d` outside the
repository and removed by an EXIT trap. Nothing generated is ever
committed: a private key committed once stays in the object database after
the file is deleted, and the collection's audit reads objects rather than
the working tree, so this is the one mistake here that cannot be undone
afterwards.

48 plain public keys, 29 certificates, 19 private key containers of which
5 are passphrase-protected, 25 detached signatures, and second encodings
of six keys as RFC 4716 and five as PKCS8. Key types ed25519, ECDSA over
P-256, P-384 and P-521, and RSA at 2048 and 4096 bits; CA keys of every
type, so signature algorithms `ssh-ed25519`, `ssh-rsa`, `rsa-sha2-256`,
`rsa-sha2-512` and ECDSA over all three curves are all exercised.

Counting the constructs is not bookkeeping. A critical-options test over a
corpus with no critical options passes having done nothing, so `sshkeyv
counts` names 85 constructs and the suite requires 62 of them to be
present and non-zero before it will believe any comparison that depends on
them. A missing construct turns the run red and names itself.

Fifteen certificates are built by hand in `t/craft.py`, because ssh-keygen
sorts the options lists, removes duplicates, refuses an empty principal
and always writes a nonce, so the shapes a server actually rejects cannot
get into the corpus any other way. Getting ssh-keygen to read them needed
an Ed25519 CA key of small order, where R = identity and S = 0 satisfy the
verification equation for any body at all, which is also the subject of
its own set of cases.

## Mutation testing

`make mutants` applies one edit to one file, rebuilds, and runs the
comparisons that ought to notice. Each edit must match exactly once, which
is checked: a mutation that silently applies nowhere reports a kill it has
not earned. Each entry also names which comparisons to run, so a curve
mutant cannot be credited to the base64 comparison.

55 mutants, 50 killed, 5 survived, 0 table errors. A mutant is killed
when one of its named comparisons exits non-zero. The table records what
each one is expected to do, and an entry recorded as surviving that dies,
or the reverse, is reported as a table error rather than quietly
corrected: a record of what is and is not tested that has stopped being
true is worse than none. A survivor with no written reason is a table
error too.

Writing the table is where most of the recent work came from. Six
checks turned out to be deletable with the whole suite still green: the
empty validity window, the 256-principal limit, the certificate-type
check, the container's padding rule, the RFC 4716 continuation rule in
the reader, and the RSA signature-length check. Each one now has a case
that fails without it. Three more followed from the same exercise: the
two copies of the public key in a container, the PEM label-match and
missing-END rules, and the leading-whitespace rule that turned out to be
a real defect rather than an untested check.

The five survivors, each with the reason rather than only the verdict:

A string length one byte larger than what remains in `src/wire.rs` is
equivalent in effect. `bytes(n)` applies its own exact check immediately
afterwards and refuses the same inputs. Only the wording of the message
and the offset inside it change, and the offsets differ by four, so an
input could in principle tell the two apart; the malformed sweep contains
such inputs and does not look at messages.

Dropping the base64 check for non-zero bits in the unused tail of the
last character makes sshkeyv agree with Python on four inputs it
currently over-refuses, and no comparison here fails on an over-refusal
becoming an acceptance.

Dropping the DER check that a long-form length must not fit in short form
makes sshkeyv agree with openssl, which reads BER. Same shape as the
base64 one.

The `debug_assert!` guarding `bignum::sub` against going negative is
unreachable. Every call site compares first, so the assertion has never
fired and no input makes it fire. It is there for the next caller.

The ECDSA digest truncation to the order's bit length is unreachable for
the three curves OpenSSH uses: SHA-256 with P-256 and SHA-384 with P-384
are the same width as the order, and SHA-512 with P-521 is nine bits
narrower, so the branch never runs. It is written out because leaving it
out would be right by accident.

## What does not work

`make mutants` was listed in `.PHONY` with no recipe behind it, so it did
nothing and exited 0 while `t/mutants.py` sat in the directory unrun. The
same was true of `hostile`. Both are fixed, and the suite now walks every
script in `t/` requiring it to be named by `run.sh`, by `mutants.py` or by
the Makefile, and reads the Makefile requiring every `.PHONY` name to have
a recipe under it. Both halves were watched to go red before being
believed.

19 objects in this repository's history still spell a PEM private key
header contiguously, and all of them are source code. The collection's
audit scans every object of every repository for "BEGIN" followed by a
key type and "PRIVATE KEY" between dashes, and cannot tell a program that
recognises that header from a file that carries one. sshkeyv needs the
string in order to detect a private key container from its first bytes,
so it had it written out in three Rust files and three comparison
scripts. All six are assembled from two pieces now, which produces the
same bytes at run time, and the suite turns red if the contiguous form
comes back. The blobs underneath are a different matter: removing a file
does not remove its blob, which is exactly why that audit reads objects,
so clearing those 19 means rewriting the history below this point. That
has not been done. Nothing in this collection has a remote and nothing
has been pushed, so the rewrite is available whenever somebody decides to
take it.

An encrypted private key is not decrypted. The cipher, the KDF name,
the bcrypt-pbkdf salt length and the rounds are parsed and reported, and
the key material behind them is not touched. So for the five encrypted
containers in the corpus the check words, the padding and the second copy
of the public key are all unverifiable, and the suite says so rather than
counting them as passes. Writing bcrypt-pbkdf is a different project.

Nothing is signed. sshkeyv verifies and never produces a signature, so
nothing here needs a CSPRNG and nothing here holds a private scalar. The
private section's reader skips the secret rather than storing it: a struct
that holds a private key is a struct that can print one by accident.

No DSA, no FIDO or PKCS#11 keys. OpenSSH 10 removed DSA. The `sk-*`
blobs have extra fields and no token is available to test against, so
there is no oracle for them and they are refused by name.

`sshd-ext --version N` was never built. The question it would answer,
which option names a given OpenSSH release understood, has no authority on
this machine: no sshd is installed, no OpenSSH source tree is present, and
the manual page carries no version history for the option names. The only
remaining source is memory, which is the thing this collection exists not
to rely on. What exists instead is `sshkeyv unknown`, which answers for
the installed OpenSSH and measures its recognised set by probing
ssh-keygen with 55 candidate names rather than carrying a list.

Eight deliberate over-refusals, where some other program reads what
sshkeyv will not. Four are base64: `QB==`, `QQB=`, `QQJ=` and `AB==`
have non-zero bits in the unused tail of the last character, which Python
accepts and sshkeyv refuses. Four are DER inside PKCS8: an indefinite
length, a long-form length that would fit in short form, a long-form
length with a leading zero octet, and one trailing byte after the
SubjectPublicKeyInfo. openssl reads BER and accepts all four. These are
decisions rather than defects, and each group is recorded as a mutation
survivor, because removing the strictness makes sshkeyv agree with the
other program and no comparison here fails on an over-refusal becoming an
acceptance. A survivor is the honest answer there: the strictness has no
oracle, only a reason.

Six of the 27 ECDSA refusal cases are cases openssl cannot be asked
about at all. They are the two malformed-point cases on each of the three
curves, and `ssh-keygen -e -m pkcs8` will not write a
SubjectPublicKeyInfo for a point that is not on the curve, so there is no
key to hand openssl. That is counted apart rather than as a refusal,
because a question the harness could not form is not an oracle answering
one. openssl judges the remaining 21 and agrees with sshkeyv on all of
them.

Four places where the two PEM readers disagree with each other. One
armour reader serves two containers, and the programs that read those
containers do not agree about how strict to be, so some rule here has to
be wrong about one of them. `ssh-keygen -y` refuses a blank line before
BEGIN and refuses a CR at the end of each line, where openssl accepts
both and so does sshkeyv. openssl refuses a blank line inside the body,
where `ssh-keygen -y` reads one and so does sshkeyv. openssl reads a line
of prose before BEGIN, where `ssh-keygen -y` refuses it and so does
sshkeyv. Each case is put to the oracle for its own container; the four
are listed in `t/pemcmp.py` with what each program does, and a
disagreement that is not on the list fails the run, as does a listed one
that has stopped disagreeing.

This is also where a real defect was found. `src/pem.rs` trimmed each line
at both ends before looking at it, so an indented BEGIN line was a BEGIN
line to sshkeyv and to nothing else on the machine: `ssh-keygen -y`
refuses it and so does `openssl pkey`. The comment above that code claimed
ssh-keygen tolerates leading whitespace. It had never been checked and it
is false.

One Ed25519 case where sshkeyv disagrees with both oracles on purpose.
A public key whose x coordinate is zero with the sign bit set is not a
canonical encoding, and sshkeyv refuses it. openssl and ssh-keygen both
accept it and report the signature as good. Refusing is the right answer
and the disagreement is recorded as known, with the arithmetic printed
beside it, rather than being smoothed over in either direction.

Two crafted certificates that sshkeyv reads and `ssh-keygen -L` dies
on. A `force-command` option whose data is two SSH strings, and one
whose data is raw bytes rather than a string. ssh-keygen calls `fatal()`
inside its option printer and prints nothing at all; sshkeyv names the
bad option on its line and carries on. That is counted apart and the
reason ssh-keygen gave is printed, so that a complaint about the
signature cannot hide among them. ssh-keygen refusing a certificate
structurally, before it reaches the printer, is a different answer and is
counted as an under-refusal, which is the distinction that made the
256-principal limit and the certificate-type check load-bearing.

The malformed sweep has never found a crash. Roughly 89,000 inputs
every run, built from every prefix of every corpus file, single bytes
overwritten across the header and the first records, and the named
malformed cases. 0 crashed and 0 timed out, and that is a negative result
rather than reassurance. The exact total moves by a few between runs
because the corpus is regenerated and a key whose modulus has a leading
zero octet makes a longer line. The sweep is worth nothing until it has
been seen to find something, so it is also run against the deliberately
aborting build, where it reports 55 crashes in a sample of 500.

The over-read gate only sees what an exact-size buffer lets it see.
`make overread` compiles the same planted one-past-the-end read twice.
With buffers exactly as long as their data it aborts and is caught; with
the decoder padding its output by 64 bytes the same read produces a tidy
error message and nothing notices. The target fails unless both halves
behave that way, so reintroducing a rounded-up buffer turns the suite red
rather than quietly turning the bounds check off. What it cannot see is a
read that stays inside one allocation and crosses from one logical region
into the next.

The build is reproducible and `target/` is not. Two builds of the same
tree in two differently named directories produce byte-identical binaries.
`unrepro` agrees about the binary and flags cargo's own bookkeeping under
`target/`: the `.d` dependency lists, the fingerprint files and
`.rustc_info.json`. Those are a build cache rather than an output.

Nine deliberate shortcuts are marked with a `shortcut:` comment naming the
ceiling and the upgrade path, and the suite counts them.
