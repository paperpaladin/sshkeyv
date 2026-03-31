// `sshkeyv counts`: how many of each construct a set of files holds.
//
// This exists because of the vacuous pass. A test for unknown critical
// options, run over a corpus with no unknown critical options in it,
// passes having done nothing at all, and nothing in its output says so.
// The counts are the guard: the suite asserts that each one the comparisons
// depend on is non-zero, and prints them all every run.
//
// The weakness is worth stating rather than hiding. The counter is the
// same decoder the comparisons use, so a construct the decoder cannot see
// is one the counter cannot count either, and the pair would agree that
// the corpus is missing something it holds. Two of the counts are put
// beside an independent python count in the suite for that reason; the
// rest are not.

use crate::cert::Cert;
use crate::key::{Material, PublicKey};
use crate::privkey::{Container, Private};
use crate::sshsig::Sshsig;
use crate::time;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Counts {
    pub n: BTreeMap<String, u64>,
}

impl Counts {
    fn bump(&mut self, k: &str) {
        *self.n.entry(k.to_string()).or_insert(0) += 1;
    }

    pub fn add_file(&mut self, path: &str, now: u64) {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => {
                self.bump("file.unreadable");
                return;
            }
        };
        let trimmed = text.trim_start();
        if trimmed.starts_with(concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----")) {
            self.bump("file.openssh-private");
            self.add_private(&text);
            return;
        }
        if trimmed.starts_with("-----BEGIN SSH SIGNATURE-----") {
            self.bump("file.sshsig");
            self.add_sshsig(&text);
            return;
        }
        if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
            self.bump("file.pkcs8");
            return;
        }
        if trimmed.starts_with("---- BEGIN SSH2 PUBLIC KEY ----") {
            self.bump("file.rfc4716");
            return;
        }
        let line = match text.lines().find(|l| !l.trim().is_empty()) {
            Some(l) => l,
            None => {
                self.bump("file.empty");
                return;
            }
        };
        let k = match PublicKey::parse_line(line) {
            Ok(k) => k,
            Err(_) => {
                self.bump("file.unparsed");
                return;
            }
        };
        if k.algo.cert {
            self.bump("file.certificate");
        } else {
            self.bump("file.public-key");
        }
        if k.comment.is_some() {
            self.bump("key.comment");
        } else {
            self.bump("key.comment.absent");
        }
        let m = match k.material() {
            Ok(m) => m,
            Err(_) => {
                self.bump("key.material.unparsed");
                return;
            }
        };
        match m {
            Material::Ed25519 { .. } => self.bump("key.ed25519"),
            Material::Rsa { n, .. } => {
                self.bump("key.rsa");
                self.bump(&format!("key.rsa.{}", crate::key::bitlen(n)));
            }
            Material::Ecdsa { curve, .. } => {
                self.bump("key.ecdsa");
                self.bump(&format!("key.ecdsa.{}", curve.name()));
            }
        }
        if k.algo.cert {
            if let Ok(c) = Cert::parse(&k.blob, k.algo) {
                self.add_cert(&c, now);
            }
        }
    }

    fn add_cert(&mut self, c: &Cert, now: u64) {
        self.bump(&format!("cert.{}", c.type_name()));
        if c.principals.is_empty() {
            self.bump("cert.principals.none");
        } else {
            self.bump(&format!(
                "cert.principals.{}",
                if c.principals.len() > 5 { "many" } else { "few" }
            ));
        }
        if c.principals.iter().any(|p| {
            p.contains('*') || p.contains('?') || p.contains('!')
        }) {
            self.bump("cert.principals.wildcard");
        }
        if c.serial == 0 {
            self.bump("cert.serial.zero");
        } else {
            self.bump("cert.serial.nonzero");
        }
        if c.serial == u64::MAX {
            self.bump("cert.serial.max");
        }
        if !c.reserved.is_empty() {
            self.bump("cert.reserved.nonempty");
        }
        if c.nonce.is_empty() {
            self.bump("cert.nonce.empty");
        }
        match (c.valid_after, c.valid_before) {
            (0, time::FOREVER) => self.bump("cert.valid.forever"),
            (0, _) => self.bump("cert.valid.before-only"),
            (_, time::FOREVER) => self.bump("cert.valid.after-only"),
            _ => self.bump("cert.valid.window"),
        }
        if now < c.valid_after {
            self.bump("cert.valid.not-yet");
        } else if now > c.valid_before {
            self.bump("cert.valid.expired");
        } else {
            self.bump("cert.valid.now");
        }
        if c.critical.is_empty() {
            self.bump("cert.critical.none");
        }
        for o in &c.critical {
            self.bump(&format!("cert.critical.{}", o.name));
            if o.data.is_empty() {
                self.bump("cert.critical.flag");
            } else {
                self.bump("cert.critical.valued");
            }
        }
        if c.extensions.is_empty() {
            self.bump("cert.extensions.none");
        }
        for o in &c.extensions {
            self.bump(&format!("cert.extension.{}", o.name));
            if o.data.is_empty() {
                self.bump("cert.extension.flag");
            } else {
                self.bump("cert.extension.valued");
            }
        }
        if !lexical(&c.critical.iter().map(|o| o.name).collect::<Vec<_>>()) {
            self.bump("cert.critical.unordered");
        }
        if !lexical(&c.extensions.iter().map(|o| o.name).collect::<Vec<_>>()) {
            self.bump("cert.extensions.unordered");
        }
        if let Ok(a) = c.signature_algo() {
            self.bump(&format!("cert.sigalg.{}", a));
        }
        if let Ok(a) = c.ca_algo() {
            self.bump(&format!("cert.ca.{}", a));
        }
    }

    fn add_private(&mut self, text: &str) {
        let pem = match crate::pem::parse(text) {
            Ok(p) => p,
            Err(_) => {
                self.bump("priv.unparsed");
                return;
            }
        };
        let c = match Container::parse(&pem.body) {
            Ok(c) => c,
            Err(_) => {
                self.bump("priv.unparsed");
                return;
            }
        };
        self.bump(&format!("priv.cipher.{}", c.cipher));
        self.bump(&format!("priv.kdf.{}", c.kdf));
        if let Some(r) = c.rounds {
            self.bump(&format!("priv.kdf.rounds.{}", r));
        }
        if c.encrypted() {
            self.bump("priv.encrypted");
            return;
        }
        self.bump("priv.plain");
        let block = crate::privkey::cipher_block(c.cipher).unwrap_or(8);
        match Private::parse(c.private, block) {
            Ok(p) => {
                self.bump(&format!("priv.keytype.{}", p.keytype));
                if p.padding.is_empty() {
                    self.bump("priv.padding.none");
                } else {
                    self.bump("priv.padding.present");
                }
            }
            Err(_) => self.bump("priv.section.unparsed"),
        }
    }

    fn add_sshsig(&mut self, text: &str) {
        let pem = match crate::pem::parse(text) {
            Ok(p) => p,
            Err(_) => {
                self.bump("sshsig.unparsed");
                return;
            }
        };
        match Sshsig::parse(&pem.body) {
            Ok(s) => {
                self.bump(&format!("sshsig.hash.{}", s.hash_algorithm));
                self.bump(&format!("sshsig.namespace.{}", s.namespace));
            }
            Err(_) => self.bump("sshsig.unparsed"),
        }
    }
}

/// Whether a list of names is in non-decreasing lexical order. OpenSSH's
/// sshd requires the critical options and extensions lists to be sorted
/// and refuses a certificate whose lists are not, so an unordered list is
/// a construct worth counting even though ssh-keygen -L prints it without
/// a word.
fn lexical(names: &[&str]) -> bool {
    names.windows(2).all(|w| w[0] <= w[1])
}
