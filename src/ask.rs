// The two questions this program exists to answer.
//
// `valid` is "is this certificate good now, and for how long", and
// `authorises` is "does it let NAME in". Both print one line per file and
// both exit 4 when the answer is no, which is a different status from a
// parse refusal (1) and from a signature that did not verify (3). The
// three are separate because a caller that cannot tell them apart will
// treat a corrupt file as an expired one.
//
// Neither command checks the CA signature. That is `verify`, and the
// README says plainly that a certificate can be reported valid here and
// be a forgery; the commands are separate because the questions are, and
// because "it is in its window but nobody can tell who signed it" is a
// thing worth being able to say.

use crate::cert::{Cert, TYPE_HOST};
use crate::time;

/// Returns (line, ok).
pub fn valid(path: &str, c: &Cert, at: u64) -> (String, bool) {
    let a = c.valid_after;
    let b = c.valid_before;
    if a > b {
        // An empty window. ssh-keygen -L prints the two dates and leaves
        // the reader to notice, which nobody does.
        return (
            format!(
                "{}: NEVER valid: the window starts {} and ends {}, which \
                 is earlier",
                path,
                time::format(a).unwrap_or_else(|| a.to_string()),
                time::format(b).unwrap_or_else(|| b.to_string())
            ),
            false,
        );
    }
    if at < a {
        let s = match time::format(a) {
            Some(s) => s,
            None => a.to_string(),
        };
        return (
            format!(
                "{}: not yet valid, starts {}, in {}",
                path,
                s,
                time::duration(a - at)
            ),
            false,
        );
    }
    // The window is [valid_after, valid_before]: OpenSSH treats both ends
    // as inclusive, so a certificate is still good in the second named by
    // valid_before.
    if at > b {
        let s = match time::format(b) {
            Some(s) => s,
            None => b.to_string(),
        };
        return (
            format!(
                "{}: expired {}, {} ago",
                path,
                s,
                time::duration(at - b)
            ),
            false,
        );
    }
    if b == time::FOREVER {
        return (format!("{}: valid, no expiry", path), true);
    }
    let s = match time::format(b) {
        Some(s) => s,
        None => b.to_string(),
    };
    (
        format!(
            "{}: valid, expires {}, in {}",
            path,
            s,
            time::duration(b - at)
        ),
        true,
    )
}

/// Whether a name contains a character that would be a wildcard to a
/// consumer that pattern-matches. Reported, never acted on: see below.
fn has_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('!')
}

// shortcut: a host certificate's principals are compared exactly rather
// than as patterns. The ceiling is a deployment that issues host
// certificates with a wildcard in the principal list: sshkeyv will say
// such a certificate does not authorise web1.example.com when the
// consumer might think it does. The upgrade is OpenSSH's match_pattern,
// and the reason it is not here is that there is no sshd on this machine
// to measure the real rule against. Until then the wildcard is reported.
/// Returns (line, ok).
///
/// The comparison is an exact string match. OpenSSH's own matching of a
/// host certificate's principals against a hostname is not reproduced
/// here, because there is no sshd on this machine to measure it against
/// and guessing at it would be worse than saying so. What sshkeyv does
/// instead is report when a principal holds a character a
/// pattern-matching consumer would treat as a wildcard, because a
/// certificate whose effect depends on that is a thing a deployment
/// should know it has.
pub fn authorises(path: &str, c: &Cert, name: &str) -> (String, bool) {
    let what = if c.cert_type == TYPE_HOST {
        "host"
    } else {
        "user"
    };
    if c.principals.is_empty() {
        return (
            format!(
                "{}: {} is authorised: this {} certificate lists no \
                 principals, which authorises every {}",
                path, name, what, what
            ),
            true,
        );
    }
    let globs: Vec<&&str> = c.principals.iter().filter(|p| has_glob(p)).collect();
    let note = if globs.is_empty() {
        String::new()
    } else {
        format!(
            "; note {} of the principals hold a wildcard character ({}), \
             and sshkeyv compares exactly",
            globs.len(),
            globs
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    match c.principals.iter().position(|p| *p == name) {
        Some(i) => (
            format!(
                "{}: {} is authorised: principal {} of {} in this {} \
                 certificate{}",
                path,
                name,
                i,
                c.principals.len(),
                what,
                note
            ),
            true,
        ),
        None => (
            format!(
                "{}: {} is NOT authorised: this {} certificate lists {}{}",
                path,
                name,
                what,
                c.principals.join(" "),
                note
            ),
            false,
        ),
    }
}
