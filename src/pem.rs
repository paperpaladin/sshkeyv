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

pub struct Pem {
    pub label: String,
    pub body: Vec<u8>,
}

pub fn parse(text: &str) -> Result<Pem, String> {
    let mut lines = text.lines();
    let mut label = None;
    // Skip anything before the BEGIN line: ssh-keygen tolerates leading
    // whitespace and so does every PEM reader in the wild.
    for l in lines.by_ref() {
        let l = l.trim();
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
        let l = l.trim();
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
