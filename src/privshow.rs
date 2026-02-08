// `sshkeyv priv`: what the container header says, as tab-separated fields.
//
// The fields nothing else prints are the reason this command exists: the
// cipher, the KDF, the salt length and the rounds. ssh-keygen will tell
// you a key is encrypted by asking for the passphrase and nothing else.

use crate::fields::hex;
use crate::privkey::{cipher_block, cipher_tag, Container, Private};

pub fn print(path: &str, body: &[u8]) -> Result<(), String> {
    let c = Container::parse(body)?;
    let f = |n: &str, v: &str| println!("{}\t{}\t{}", path, n, v);
    f("container-bytes", &body.len().to_string());
    f("cipher", c.cipher);
    f("kdf", c.kdf);
    f("encrypted", if c.encrypted() { "yes" } else { "no" });
    f("nkeys", &c.nkeys.to_string());
    let block = cipher_block(c.cipher).unwrap_or(0);
    f("cipher-block", &block.to_string());
    f("cipher-tag-bytes", &cipher_tag(c.cipher).to_string());
    match (c.salt, c.rounds) {
        (Some(s), Some(n)) => {
            f("kdf-salt-bytes", &s.len().to_string());
            f("kdf-salt", &hex(s));
            f("kdf-rounds", &n.to_string());
        }
        _ => f("kdf-options-bytes", &c.kdf_options.len().to_string()),
    }
    f("public-blob-bytes", &c.public[0].len().to_string());
    f("private-section-bytes", &c.private.len().to_string());
    // The public key the container carries in clear. Printed as a key line
    // so it can be put beside ssh-keygen -y, which reads the private key
    // and prints the same thing.
    let mut r = crate::wire::Reader::new(c.public[0], "container public key");
    let name = r.text()?;
    f(
        "public-line",
        &format!("{} {}", name, crate::b64::encode(c.public[0])),
    );
    if c.encrypted() {
        f("private-section", "encrypted, not parsed");
        return Ok(());
    }
    let p = Private::parse(c.private, block)?;
    f("checkint", &p.checkint.to_string());
    f("private-keytype", p.keytype);
    f("private-comment", p.comment);
    f("private-padding-bytes", &p.padding.len().to_string());
    // A container whose two copies of the public key disagree is a file no
    // tool reads the same way twice.
    if p.public != c.public[0] {
        return Err(format!(
            "{}: the public key in the private section does not match the \
             container's copy",
            path
        ));
    }
    f("public-halves-match", "yes");
    Ok(())
}
