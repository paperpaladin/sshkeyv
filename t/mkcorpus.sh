#!/bin/sh
# Build the corpus. One argument: the directory to build it in, which the
# caller makes with mktemp -d and deletes.
#
# Nothing here is committed and nothing here is written inside the
# repository. Every file below holds or is derived from a private key, and
# a private key committed once stays in the object database after the file
# is deleted: `git rm` does not remove a blob and the collection's audit
# reads objects rather than the working tree. So the corpus lives outside
# the tree for its whole life and the suite's EXIT trap is what removes it.
#
# The passphrases are generated here and never printed. They go to
# ssh-keygen -N on a command line, which is visible in /proc for the
# lifetime of the process; that is acceptable for a throwaway key that
# exists for ninety seconds, and is noted so nobody copies the pattern for
# a key that matters.
set -eu

D=${1:?usage: mkcorpus.sh DIR}
mkdir -p "$D"
cd "$D"

kg() { ssh-keygen -q "$@"; }

# ---- plain keys, one per type and size ----------------------------------
kg -t ed25519 -N '' -C 'ed25519 plain'        -f ed25519
kg -t ecdsa -b 256 -N '' -C 'ecdsa 256'       -f ecdsa256
kg -t ecdsa -b 384 -N '' -C 'ecdsa 384'       -f ecdsa384
kg -t ecdsa -b 521 -N '' -C 'ecdsa 521'       -f ecdsa521
kg -t rsa -b 2048 -N '' -C 'rsa 2048'         -f rsa2048
kg -t rsa -b 4096 -N '' -C 'rsa 4096'         -f rsa4096

# A comment with spaces in it, and a key with no comment at all. Both are
# shapes the public key line parser has to get right: the comment is
# everything after the blob, spaces included, and an absent comment is not
# an empty one.
kg -t ed25519 -N '' -C 'a comment with spaces and a # in it' -f ed25519_comment
kg -t ed25519 -N '' -C ''                     -f ed25519_nocomment

# ---- keys with a passphrase --------------------------------------------
# Three KDF rounds settings and two ciphers, because the KDF header is the
# thing sshkeyv reports and it is four fields wide.
P1=$(head -c 18 /dev/urandom | base64)
P2=$(head -c 18 /dev/urandom | base64)
kg -t ed25519 -N "$P1" -C 'ed25519 encrypted'            -f ed25519_enc
kg -t ed25519 -N "$P2" -a 64 -C 'ed25519 64 rounds'      -f ed25519_enc64
kg -t ed25519 -N "$P1" -a 8 -Z aes128-ctr -C 'aes128'    -f ed25519_aes128
kg -t rsa -b 2048 -N "$P2" -a 32 -C 'rsa encrypted'      -f rsa2048_enc
kg -t ecdsa -b 256 -N "$P1" -C 'ecdsa encrypted'         -f ecdsa256_enc
unset P1 P2

# ---- certificate authorities -------------------------------------------
kg -t ed25519 -N '' -C 'ca ed25519'   -f ca_ed25519
kg -t rsa -b 2048 -N '' -C 'ca rsa'   -f ca_rsa
kg -t ecdsa -b 256 -N '' -C 'ca p256' -f ca_p256
kg -t ecdsa -b 521 -N '' -C 'ca p521' -f ca_p521

# ---- certificates ------------------------------------------------------
# Each one is a copy of a public key signed with particular options, and
# the file name says which case it is. ssh-keygen writes NAME-cert.pub
# beside NAME.pub, so each case gets its own copy of the subject key.
cert() {
    name=$1; shift
    ca=$1; shift
    subj=$1; shift
    cp "$subj.pub" "c_$name.pub"
    ssh-keygen -q -s "$ca" "$@" "c_$name.pub"
}

cert user_ed    ca_ed25519 ed25519   -I user_alice -n alice,bob -z 12345 \
                                     -V '-1h:+52w'
cert user_rsa   ca_rsa     ed25519   -I user_from_rsa_ca -n alice -z 1
cert user_p256  ca_p256    ed25519   -I user_from_p256_ca -n alice
cert user_p521  ca_p521    ed25519   -I user_from_p521_ca -n alice
cert rsa_sha1   ca_rsa     ed25519   -t ssh-rsa -I sig_ssh_rsa -n alice
cert rsa_sha256 ca_rsa     ed25519   -t rsa-sha2-256 -I sig_rsa_sha2_256 -n alice
cert rsa_sha512 ca_rsa     ed25519   -t rsa-sha2-512 -I sig_rsa_sha2_512 -n alice

# The subject key type varies too: the certificate blob embeds it, so a
# certificate over an RSA key has a different shape from one over ed25519.
cert subj_rsa   ca_ed25519 rsa2048   -I subject_rsa -n alice
cert subj_p384  ca_ed25519 ecdsa384  -I subject_p384 -n alice
cert subj_p521  ca_ed25519 ecdsa521  -I subject_p521 -n alice

# Validity windows. These are the whole reason anyone runs the tool.
cert expired    ca_ed25519 ed25519   -I expired_cert -n alice -V '-2w:-1w'
cert future     ca_ed25519 ed25519   -I not_yet_valid -n alice -V '+1w:+2w'
cert forever    ca_ed25519 ed25519   -I valid_forever -n alice -V 'always:forever'
cert after_only ca_ed25519 ed25519   -I no_expiry -n alice -V '20200101:forever'
cert before_only ca_ed25519 ed25519  -I no_start -n alice -V 'always:20300101'

# Principals: none at all, which authorises everyone, and a long list.
cp ed25519.pub c_noprincipals.pub
ssh-keygen -q -s ca_ed25519 -I no_principals c_noprincipals.pub
cert many       ca_ed25519 ed25519 -I many_principals \
  -n a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20

# Host certificates. The wildcard one is in the corpus because a principal
# holding a * means the certificate's effect depends on whether whoever
# reads it pattern-matches, and sshkeyv reports that rather than guessing.
cert host       ca_ed25519 ed25519 -h -I host_web -n web1.example.com,web2
cert host_rsa   ca_rsa     rsa2048 -h -I host_rsa -n db1.example.com
cert host_glob  ca_ed25519 ed25519 -h -I host_wildcard -n '*.example.com,web?'

# A principal with a comma in it cannot be made with -n, which splits on
# commas, so this one is built by hand further down if ever needed; the
# point it would make is already made by valid_principals being a sequence
# of strings rather than a name-list.

# Critical options and extensions, including the two cases that fail closed
# on a real server: an option the server does not know, and an extension
# the server does not know.
cert crit       ca_ed25519 ed25519 -I with_critical -n alice \
  -O force-command=/usr/bin/date -O source-address=10.0.0.0/8,192.168.0.0/16
cert crit_verify ca_ed25519 ed25519 -I verify_required -n alice \
  -O verify-required
cert unkcrit    ca_ed25519 ed25519 -I unknown_critical -n alice \
  -O critical:mystery=xyz
cert unkcrit_flag ca_ed25519 ed25519 -I unknown_critical_flag -n alice \
  -O critical:solo
cert unkext     ca_ed25519 ed25519 -I unknown_extension -n alice \
  -O extension:odd-ext
cert unkext_val ca_ed25519 ed25519 -I unknown_extension_valued -n alice \
  -O extension:odd-ext=somevalue
cert noext      ca_ed25519 ed25519 -I no_extensions -n alice \
  -O clear
cert serial_max ca_ed25519 ed25519 -I serial_max -n alice \
  -z 18446744073709551615

# ---- other encodings of the same keys ----------------------------------
# A second encoding of the same key gives the two formats something to
# disagree about.
for k in ed25519 ecdsa256 ecdsa384 ecdsa521 rsa2048 rsa4096; do
    ssh-keygen -e -f "$k.pub" > "$k.rfc4716"
done
for k in ecdsa256 ecdsa384 ecdsa521 rsa2048 rsa4096; do
    ssh-keygen -e -m pkcs8 -f "$k.pub" > "$k.pkcs8"
done

# ---- detached signatures ------------------------------------------------
printf 'the message that is signed\n' > msg
printf '' > msg_empty
head -c 100000 /dev/zero | tr '\0' 'z' > msg_big
for k in ed25519 rsa2048 ecdsa256 ecdsa384 ecdsa521; do
    for ns in file git; do
        ssh-keygen -Y sign -q -f "$k" -n "$ns" -O "hashalg=sha512" \
            < msg > "sig_${k}_${ns}.sig"
    done
    ssh-keygen -Y sign -q -f "$k" -n file -O hashalg=sha256 \
        < msg > "sig_${k}_sha256.sig"
    ssh-keygen -Y sign -q -f "$k" -n file < msg_empty > "sig_${k}_empty.sig"
    ssh-keygen -Y sign -q -f "$k" -n file < msg_big > "sig_${k}_big.sig"
done

echo "corpus built in $D"
