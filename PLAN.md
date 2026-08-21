# PLAN

## Contract

```
sshkeyv fields [FILE...]            one "name value" line per field, tab separated
sshkeyv fp [-E HASH] [FILE...]      fingerprints, the shape ssh-keygen -l prints
sshkeyv show [FILE...]              certificate fields, the shape ssh-keygen -L prints
sshkeyv check [FILE...]             parse fully; print ok or the refusal
sshkeyv priv [FILE...]              private key container header, no decryption
sshkeyv verify [--ca FILE] FILE     check the CA signature over a certificate
sshkeyv valid [--at TIME] [--principal NAME] [--host] FILE
sshkeyv authorises NAME FILE        does this certificate authorise NAME
sshkeyv sigverify --key FILE -n NS -s SIGFILE [FILE]
sshkeyv convert -m FORMAT FILE      rfc4716, pkcs8 or openssh
sshkeyv counts [FILE...]            how many of each construct the files hold
sshkeyv unknown [FILE...]           options the local OpenSSH does not know
sshkeyv blob [FILE...]              the top-level SSH strings of a blob
```

This list said `sshd-ext --version N` where it now says `unknown`. That
command was never built and the plan item for it is blocked below, for
want of any authority on this machine for a per-release table. `unknown`
is what exists: the same question asked of the installed OpenSSH, whose
recognised set is measured by probing it. A contract naming a command
that does not exist is the sort of thing a reader checks the code
against once and then stops trusting the file.

Five more commands exist and are not in the contract because they are
there for the suite rather than for a user: `time`, `curve`, `big`,
`hash` and `b64`. Each exposes one internal piece so that an outside
oracle can be put beside it.

`FILE` is a public key line, a certificate line, an OpenSSH private key
container, an RFC4716 block or a PEM SubjectPublicKeyInfo. The format is
detected from the bytes, not from the name.

Exit status: 0 when every requested check passed, 1 when the input is
malformed or unreadable, 2 on a usage error, 3 when a signature did not
verify, 4 when a certificate parsed but is not currently valid or does not
authorise the principal asked about, and 5 when sshkeyv has no verifier
for the algorithm named. 5 was missing from this list while `src/sig.rs`
and the Makefile both named it. The numbers are distinct because the
suite asserts on the difference. "Cannot parse it" and "parsed fine, the
signature is wrong" are not the same answer and must not share an exit code:
a harness that treats them alike reports a refusal as a caught forgery.

Pure Rust 2021 with no dependencies. No crypto crate, no base64 crate, no
bignum crate, `std` only. Zero `unsafe` in the tree, asserted by the suite.

## Hard invariant

**A certificate whose CA signature does not verify is never reported as
valid, and a refusal to parse is counted separately from a wrong answer,
everywhere.**

Concretely:

- For every corpus file, the (field, value) pairs sshkeyv prints equal the
  pairs read out of `ssh-keygen -L` and `ssh-keygen -l`, compared field by
  field and never as text. The two programs disagree about spacing, and a
  whole-output diff can only say "different".
- For every certificate, the verdict from `sshkeyv verify` equals the verdict
  from `openssl pkeyutl -verify` or `openssl dgst -verify` over the same
  signed blob and the same public key, with OpenSSH out of the loop for the
  signature maths.
- For every signature in the corpus with one bit flipped, sshkeyv exits 3 and
  openssl refuses too. A single-bit mutation that sshkeyv reports as valid is
  a failed project, not a failed test.
- Refusals are counted apart from disagreements in every comparison, and
  both numbers are printed whether or not they are zero.

## Oracle

Ranked by how little we control them.

1. `openssl` 3.5.7. It does the signature maths with no OpenSSH code in the
   path: `pkeyutl -verify -rawin` for Ed25519, `dgst -verify` for the RSA
   PKCS#1 v1.5 and ECDSA cases. It is the only oracle here that can
   contradict OpenSSH about whether a signature is good.
2. `ssh-keygen` from OpenSSH 10.0p2, for the fields: `-l -f` for
   fingerprints in all three hash forms, `-L -f` for certificate fields,
   `-B -f` for the bubblebabble digest, `-e`/`-i` for the RFC4716 and PKCS8
   round trips, `-Y sign`/`-Y verify` for detached signatures.
3. `ssh-keygen -t ...` and `ssh-keygen -s` build the corpus. Weaker than the
   two above, because the thing that writes the bytes agrees with the thing
   that reads them by construction.
4. `t/wire.py`, a third parser for the SSH wire format in Python with
   `struct` and no key knowledge at all, compared against `sshkeyv fields`
   field by field. It exists so that one bug in OpenSSH's writer and reader
   together cannot hide.

A run without `ssh-keygen` or without `openssl` is a refusal, not a skip.
Between them they are the authority for every fact the suite checks, and a
reduced run would print a row of passes having compared sshkeyv with itself.

## Non-goals

- No decryption of an encrypted private key. The bcrypt-pbkdf header is
  parsed and reported; the key material behind it is not touched. Writing
  bcrypt-pbkdf is a different project and the header is the part people
  need to read.
- No signing. sshkeyv verifies and never produces a signature, so nothing
  here needs a CSPRNG and nothing here holds a private scalar.
- No DSA. OpenSSH 10 removed it.
- No FIDO or PKCS#11 key types (`sk-*`). The blob has extra fields and no
  token is available to test against.
- No host key database handling, no `known_hosts`, no `authorized_keys`
  option parsing. Those are files about keys rather than keys.

## Commit sequence

- [x] repository skeleton: Cargo.toml with no dependencies, Makefile with
      `all` first, LICENSE, .gitignore naming every generated artefact
  why: the collection's gate builds the default target of every commit, so
  the first commit has to build.
- [x] base64 decoder and encoder, strict about padding and alphabet
  why: every format here is base64 inside something, and a lenient decoder
  turns a corrupt file into a plausible key.
- [x] SSH wire format reader: u32, u64, string, bool, mpint, with the
      remaining-length check in one place
  why: every blob in the project is this format, and the bounds check wants
  to be written once.
- [x] public key line parser: algorithm name, blob, comment, and the rule
      that the name inside the blob must match the name outside it
  why: that check is the first thing a hand-edited key line fails.
- [x] SHA-256 and SHA-512, byte for byte against `sha256sum` and
      `sha512sum`
  why: the SHA256 fingerprint is the field everyone reads, so the hash is
  on the critical path before anything else can be compared, and the
  signature algorithms name SHA-512 as often as SHA-256.
- [x] `sshkeyv fp`: SHA256 fingerprint in base64 with no padding, and the
      bit count, against `ssh-keygen -l -f`
  why: the first field-by-field comparison with the oracle.
- [x] corpus generator: ed25519, ecdsa 256/384/521, rsa 2048/4096, into a
      mktemp -d outside the repository, deleted on exit
  why: no generated key may ever enter the tree, and a trap is the only
  thing that holds when the suite fails halfway.
- [x] t/run.sh: oracle refusal when ssh-keygen or openssl is missing, the
      staleness guard, and the last line in the form "N passed, M failed"
  why: a missing oracle must be a refusal; terminfo's guard is the pattern.
- [x] MD5 and `-E md5`, against `ssh-keygen -l -E md5`
  why: the colon-hex form is still what older deployments print.
- [x] bubblebabble digest and `-E bubblebabble`, against `ssh-keygen -B`
  why: a third fingerprint encoding of the same bytes, and ssh-keygen has a
  dedicated flag for it, so it is a free independent check on the SHA-1 and
  on the key blob.
- [x] SHA-1, needed by bubblebabble and by the ssh-rsa signature algorithm
  why: ssh-rsa with SHA-1 is still accepted by certificates in the field.
- [x] key bit counts for every type: rsa from the modulus, ecdsa from the
      curve, ed25519 fixed at 256
  why: ssh-keygen prints the bits first on every line, so a wrong count is
  a visible disagreement in the fingerprint comparison.
- [x] `sshkeyv fields`: the parsed key as tab-separated name and value
  why: t/wire.py arrived with the wire reader and compares the generic
  string walk; fields is the same idea once the key types are known.
- [x] RFC4716 writer, against `ssh-keygen -e`, and reader, against
      `ssh-keygen -i`
  why: a second encoding of the same key, which gives the two formats
  something to disagree about. The wrapped-line and continuation rules are
  where a hand-written reader breaks.
- [x] PKCS8 SubjectPublicKeyInfo writer for RSA and ECDSA, against
      `ssh-keygen -e -m pkcs8` byte for byte
  why: DER with an integer encoding and an OID, written from scratch, and
  the oracle gives the exact bytes.
- [x] PKCS8 reader, so `convert` round trips, against `ssh-keygen -i -m pkcs8`
  why: the reverse direction fails differently; a DER length read as
  short-form where it is long-form is the classic.
- [x] PEM armour reader: the BEGIN and END lines, the base64 body, the
      refusals for a mismatched label and a truncated body
  why: the private key container is PEM, and so is PKCS8.
- [x] openssh-key-v1 container header: magic, cipher, KDF name, number of
      keys, the public key, the length of the private section
  why: this is the file people actually have on disk and `ssh-keygen -l`
  reads it, so the header has an oracle.
- [x] bcrypt-pbkdf KDF options: salt length and rounds, reported without
      decrypting anything
  why: "how many rounds is this key protected with" is a question with no
  tool to answer it, and the answer is 24 bytes into the file.
- [x] unencrypted private section: the check integers, the key type, the
      public half, the comment, and the padding rule
  why: the two check integers being equal is the only integrity signal the
  format has, and it is what a wrong passphrase trips.
- [x] assert the private section's public half equals the container's
      public key
  why: a container whose two copies of the public key disagree is a file
  no tool reads the same way twice.
- [x] refusal cases for the container: bad magic, nkeys not 1, short
      private section, wrong padding
  why: a refusal needs its own oracle, which here is ssh-keygen refusing
  the same file.
- [x] certificate blob parse: nonce, public key, serial, type, key id,
      principals, validity, critical options, extensions, reserved, CA key,
      signature
  why: the centre of the project. Everything after this reads these fields.
- [x] the critical options and extensions lists: name and data strings,
      the lexical ordering rule, duplicate names
  why: an out-of-order options list is something sshd refuses and
  `ssh-keygen -L` prints without complaint.
- [x] `sshkeyv show`, compared against `ssh-keygen -L` field by field
  why: field by field and not file by file, because the indentation differs
  and a text diff can only say "different".
- [x] the unknown-option print forms: "UNKNOWN OPTION: <hex> (len N)" for
      an option with data and "UNKNOWN FLAG OPTION" for one without
  why: ssh-keygen has exact text for these and a certificate carrying one
  is the case that fails closed on a real server.
- [x] validity window: the two 64-bit times, the ssh-keygen date format,
      forever and never
  why: 0 and 2^64-1 are the real sentinels and they print specially.
- [x] `sshkeyv valid --at TIME`: not yet valid, expired, valid, and the
      remaining time
  why: "for how long is this good" is the question, and it needs a clock
  the test can set.
- [x] `sshkeyv authorises NAME`: the empty principal list meaning "all",
      the host versus user certificate distinction
  why: an empty list authorises everyone, which is the single most
  surprising rule in the format.
- [x] `sshkeyv counts`: every construct in the corpus counted and printed
  why: a critical-options test over a corpus with no critical options
  passes having done nothing. The counts are the guard against that and
  the suite asserts each one is non-zero.
- [x] bignum: comparison, add, subtract, multiply, divide with remainder,
      from and to big-endian bytes
  why: RSA needs it and nothing in std has it.
- [x] modular exponentiation, against `openssl` and python's pow
  why: the one operation RSA verification is.
- [x] RSA PKCS#1 v1.5 verification, with the DigestInfo prefix checked
      rather than searched for
  why: a verifier that looks for the digest anywhere in the padding accepts
  Bleichenbacher's forgery. The check is on the exact bytes of the whole
  padded block.
- [x] RSA against `openssl dgst -verify` over the same signed blob, for
      rsa-sha2-256, rsa-sha2-512 and ssh-rsa
  why: three signature algorithms over one key type, and openssl does the
  maths with no OpenSSH in the path.
- [x] Ed25519 field arithmetic over 2^255-19
  why: the verification equation needs inversion and a square root, and
  both are exponentiations with curve-specific exponents.
- [x] Ed25519 point decompression, scalar multiplication and the
      verification equation, against `openssl pkeyutl -verify -rawin`
  why: the default key type, and openssl will check it given a hand-built
  SubjectPublicKeyInfo.
- [x] Ed25519 refusals: a non-canonical encoding, a point not on the curve,
      an S value at or above the group order
  why: these are the cases a verifier written from the equation alone gets
  wrong, and each of them is a signature that must not verify.
- [x] certificate signature verification wired to the key types, exit 3 on
      failure
  why: the invariant. Up to here the pieces exist and nothing joins them.
- [x] single-bit corruption of every signature in the corpus, every one
      refused with exit 3
  why: the hard invariant, measured rather than asserted. Counted as
  refusals, never mixed into the disagreement count.
- [x] corruption of the certificate body rather than the signature
  why: a verifier that hashes the wrong range passes the first test and
  fails this one.
- [x] SSHSIG parse: the magic, version, namespace, reserved, hash
      algorithm, and the signed blob construction
  why: `ssh-keygen -Y sign` gives a second signature format over data we
  choose, so the verifier gets tested on something other than certificates.
- [x] SSHSIG verification against `ssh-keygen -Y verify` and against
      openssl, including a wrong namespace and a wrong message
  why: the namespace is in the signed blob, so a verifier that ignores it
  accepts a signature made for another purpose.
- [x] NIST P-256 field and curve arithmetic
  why: ecdsa-sha2-nistp256 is the second commonest key type in deployment.
- [x] ECDSA verification for P-256, P-384 and P-521, against `openssl dgst
      -verify` with the SSH (r,s) pair re-encoded as a DER Ecdsa-Sig-Value
  why: P-521 is the one with a bit length that is not a byte multiple, so
  it is where the padding rules show.
- [x] ECDSA refusals: r or s zero, r or s at or above the group order, a
      point not on the curve
  why: same class as the Ed25519 refusals, different arithmetic.
- [x] `sshkeyv verify --ca FILE`: the signer must be one of the keys given
  why: the difference between a certificate that is internally consistent
  and one issued by the CA you actually trust. Without it verify proves
  only that the signature matches the key the certificate names, and a
  certificate names its own CA.
- [x] `sshkeyv check`: read every layer of every container and report
  why: the command that would notice an option whose data is not a single
  string, or a container whose two copies of the public key disagree.
- [x] `sshkeyv unknown`: which critical options and extensions the local
      OpenSSH does not recognise, exit 4 when a critical one is unknown
  why: the actual question behind a certificate that fails closed. The set
  is measured from the installed ssh-keygen by probing it, not written
  down.
- [x] METHOD hard rule 4: the build is reproducible, measured
  why: two builds in the same directory match even when a build is
  hopelessly unreproducible, so the check moves the tree. unrepro agrees
  about the binary and flags only cargo's own cache under target/.
- [x] determinism, and the same key read out of three containers
  why: two properties with no external oracle. Rust's HashMap iterates in
  a different order every process by design, so a map on an output path
  is invisible until something repeats the run; and a container reader
  that drops a byte is invisible until the same key is read two ways.
- [x] `sshkeyv valid --principal NAME --host|--user`: one combined verdict
  why: the real question is all three at once, and a command that stops
  at the first no needs running three times to learn that a certificate
  is expired and for the wrong principal and the wrong kind.
- [x] the calendar arithmetic against `date -u`, both directions
  why: civil_from_days and its inverse are the kind of code that is right
  for 2026 and wrong for 1900, 2100 or a leap day, and date is an oracle
  with nothing to do with SSH.
- [x] certificates ssh-keygen will not write, built by hand
  why: it sorts the options lists, removes duplicates, refuses an empty
  principal and always writes a nonce, so the shapes a server rejects
  cannot be in the corpus otherwise. Making ssh-keygen read them needed
  the identity-CA trick, which is itself the demonstration of why a
  small-order signing key matters.
- [x] Ed25519 keys of small order, reported rather than refused
  why: with A the identity, R = identity and S = 0 satisfy the
  verification equation for any message, and neither OpenSSH nor OpenSSL
  rejects such a key. Refusing it would disagree with both oracles about
  whether an equation holds, so the right answer is to agree and say what
  it means.
- [x] a real Bleichenbacher low-exponent forgery, built and refused
  why: the PKCS#1 v1.5 case that a verifier written the obvious way
  accepts, and the reason the block is compared whole rather than searched.
  Building the forgery is the only way to know the comparison is the thing
  doing the work.
- [ ] BLOCKED: `--version N`, a per-release table of which sshd understood
      which name.
  why: there is no authority for such a table on this machine. The
  installed OpenSSH answers for itself and nothing else does: no sshd is
  installed, no OpenSSH source tree is present, and the ssh-keygen manual
  page carries no version history for the option names. The only source
  would be memory, which METHOD says to leave out of the README rather
  than invent. What exists instead is the measured set of the OpenSSH on
  this machine, and the README says which question that answers.
- [x] exact-size allocation for every buffer that holds parsed input, and
      `make overread` with a planted one-past-the-end read that must be
      caught
  why: METHOD's buffer section. A Vec with spare capacity indexed by a
  separate length has the same blind spot as a C buffer larger than its
  data, and Rust's bounds check is against the Vec's length, not the
  data's.
- [x] hostile corpus: every prefix of every corpus file, single bytes
      overwritten across the header and the first records, and the named
      malformed cases
  why: a length field read as an index is where every parser of this shape
  breaks, and the measurement is crashes and hangs, not opinions.
- [x] mutation testing: one edit at a time, rebuild, run the suite, with
      the survivors written down
  why: the suite's own test. An equivalent mutant recorded honestly is
  worth more than a kill claimed. `make mutants` was in `.PHONY` with no
  recipe, so it did nothing and exited 0; the table found six checks
  nothing in the suite could see, and each is now watched.
- [x] the PEM armour bent sixteen ways, against ssh-keygen -y and
      openssl pkey
  why: every other comparison hands sshkeyv a tidy block and argues
  about the inside of it, so the label-match and missing-END rules had
  never been reached. It found an indented BEGIN line that sshkeyv read
  and nothing else on the machine will.
- [x] the two copies of the public key in a container, made to disagree
  why: the comparison that caught the RSA field swap had never been
  made to fail, and deleting it left the whole suite green.
- [x] openssl over the ECDSA refusal cases
  why: the Ed25519 refusals had an outside authority and these did not,
  while the docstring said they did and the roster said "sshkeyv alone".
- [x] every script in t/ reachable from `make test` or `make mutants`,
      and every `.PHONY` target holding a recipe
  why: the shape rather than the instance. Two names in one Makefile
  answered yes for doing nothing.
- [ ] README: the oracles, the measured numbers, what the corpus holds and
      what does not work
  why: a README that lists only successes is not finished.
