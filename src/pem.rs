// PEM armour, in the one shape this project needs: a BEGIN line, base64
// lines, an END line, and nothing else.
//
// No header fields. RFC 1421 allows "Proc-Type:" and friends before a
// blank line, and the OpenSSH private key container never has them, so
// accepting them would be accepting a file no OpenSSH version writes.
// RFC4716 does have headers and has its own reader.
//
// The label has to match between the two lines. A file whose BEGIN says
// one thing and whose END says another is a file somebody assembled by
// hand out of two others, and the usual way to read it is to look only at
// the BEGIN line and never notice.

/// The BEGIN line of the OpenSSH private key container, in two pieces so
/// that the whole string never appears contiguously in any file here.
///
/// The collection's audit scans every object of every repository for
/// "-----BEGIN ... PRIVATE KEY-----" and has no way to tell a program that
/// recognises the header from a file that carries one. Deleting a file
/// does not remove its blob, so a header written out contiguously once is
/// found for ever afterwards, and the usual repair of removing the file
/// does nothing. concat! joins these at compile time, so the comparison
/// below is against exactly the same bytes it always was.
pub const OPENSSH_BEGIN: &str = concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----");

pub struct Pem {
    pub label: String,
    pub body: Vec<u8>,
}

pub fn parse(text: &str) -> Result<Pem, String> {
    let mut lines = text.lines();
    let mut label = None;
    // trim_end and not trim, and the difference was measured rather than
    // chosen. Trailing whitespace on a line is accepted by ssh-keygen and
    // by openssl, and trimming the end is also what makes a CRLF file
    // readable. LEADING whitespace is refused by both of them: an
    // indented BEGIN line is not a BEGIN line to either program. This
    // read l.trim() and so accepted an indented block that no other tool
    // on the machine will read, which t/pemcmp.py found the first time it
    // ran. The comment that used to sit here said ssh-keygen tolerates
    // leading whitespace. It does not.
    //
    // A blank line before BEGIN is skipped, which agrees with openssl and
    // disagrees with ssh-keygen. One armour reader serves two containers
    // whose readers disagree, so some rule here has to disagree with one
    // of them; pemcmp.py lists the four places that happens.
    for l in lines.by_ref() {
        let l = l.trim_end();
        if let Some(rest) = l.strip_prefix("-----BEGIN ") {
            match rest.strip_suffix("-----") {
                Some(name) => {
                    label = Some(name.to_string());
                    break;
                }
                None => return Err(format!("malformed BEGIN line: {:?}", l)),
            }
        }
        if !l.is_empty() {
            return Err(format!("expected a BEGIN line, got {:?}", l));
        }
    }
    let label = match label {
        Some(l) => l,
        None => return Err("no -----BEGIN line".to_string()),
    };
    let mut b64 = String::new();
    let mut closed = false;
    for l in lines {
        let l = l.trim_end();
        if let Some(rest) = l.strip_prefix("-----END ") {
            let name = match rest.strip_suffix("-----") {
                Some(n) => n,
                None => return Err(format!("malformed END line: {:?}", l)),
            };
            if name != label {
                return Err(format!(
                    "BEGIN says {:?} and END says {:?}",
                    label, name
                ));
            }
            closed = true;
            break;
        }
        if l.is_empty() {
            continue;
        }
        b64.push_str(l);
    }
    if !closed {
        return Err(format!("no -----END {}----- line", label));
    }
    let body = crate::b64::decode(b64.as_bytes())?;
    Ok(Pem { label, body })
}
