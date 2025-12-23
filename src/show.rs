// `sshkeyv show`: the block ssh-keygen -L prints, reproduced.
//
// Reproduced exactly, so that the comparison is a diff of two whole
// outputs and there is nothing to interpret. The indentation is eight and
// sixteen spaces, the trailing space after "Principals:" when the list is
// not empty is ssh-keygen's and is kept, and the unknown-option text is
// copied word for word from ssh-keygen's show_options().
//
// The one deliberate difference is the time zone: ssh-keygen uses
// localtime and sshkeyv prints UTC. See src/time.rs.

use crate::cert::{Cert, Opt};
use crate::fp;
use crate::key::{algo, material, Material};
use crate::time;
use crate::wire::Reader;

/// The extension names ssh-keygen prints bare, with no value after them.
/// From show_options() in ssh-keygen.c. The list is version-specific: an
/// older ssh-keygen prints a name it does not know as UNKNOWN, and the
/// whole point of the sshd-ext command later on is that the server's list
/// is version-specific too.
const FLAG_EXTENSIONS: &[&str] = &[
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
    "no-touch-required",
];

/// Critical options whose data holds exactly one string, which is printed
/// after the name.
const STRING_CRITICAL: &[&str] = &["force-command", "source-address"];

/// Critical options ssh-keygen prints bare.
const FLAG_CRITICAL: &[&str] = &["verify-required"];

fn option_line(o: &Opt, in_critical: bool) -> String {
    if !in_critical && FLAG_EXTENSIONS.contains(&o.name) {
        return format!("                {}", o.name);
    }
    if in_critical && STRING_CRITICAL.contains(&o.name) {
        return match o.as_string() {
            Some(Ok(s)) => format!(
                "                {} {}",
                o.name,
                String::from_utf8_lossy(s)
            ),
            // ssh-keygen calls fatal() here and prints nothing more.
            // Refusing the whole file for one malformed option would hide
            // every other field, so sshkeyv says what is wrong on the line
            // and carries on.
            _ => format!(
                "                {} MALFORMED: data is not a single string",
                o.name
            ),
        };
    }
    if in_critical && FLAG_CRITICAL.contains(&o.name) {
        return format!("                {}", o.name);
    }
    if !o.data.is_empty() {
        return format!(
            "                {} UNKNOWN OPTION: {} (len {})",
            o.name,
            crate::fields::hex(o.data),
            o.data.len()
        );
    }
    format!("                {} UNKNOWN FLAG OPTION", o.name)
}

/// The label and fingerprint of a key blob, as "ED25519 SHA256:...".
fn key_line(blob: &[u8], kind: fp::Kind) -> Result<String, String> {
    let mut r = Reader::new(blob, "key blob");
    let name = r.text()?;
    let a = match algo(name) {
        Some(a) => a,
        None => return Err(format!("unknown key algorithm {:?}", name)),
    };
    let m: Material = material(&mut r, a.plain)?;
    r.end()?;
    Ok(format!("{} {}", m.label(), fp::digest(kind, blob)))
}

pub fn show(path: &str, c: &Cert, subject_blob: &[u8]) -> Result<(), String> {
    let kind = fp::Kind::Sha256;
    println!("{}:", path);
    println!(
        "        Type: {} {} certificate",
        c.algo.name,
        c.type_name()
    );
    println!(
        "        Public key: {}-CERT {}",
        c.subject.label(),
        fp::digest(kind, subject_blob)
    );
    println!(
        "        Signing CA: {} (using {})",
        key_line(c.signature_key, kind)?,
        c.signature_algo()?
    );
    println!("        Key ID: \"{}\"", c.key_id);
    println!("        Serial: {}", c.serial);
    println!("        Valid: {}", time::validity(c.valid_after, c.valid_before));
    if c.principals.is_empty() {
        println!("        Principals: (none)");
    } else {
        println!("        Principals: ");
        for p in &c.principals {
            println!("                {}", p);
        }
    }
    for (label, list, in_critical) in [
        ("Critical Options", &c.critical, true),
        ("Extensions", &c.extensions, false),
    ] {
        if list.is_empty() {
            println!("        {}: (none)", label);
        } else {
            println!("        {}: ", label);
            for o in list.iter() {
                println!("{}", option_line(o, in_critical));
            }
        }
    }
    Ok(())
}
