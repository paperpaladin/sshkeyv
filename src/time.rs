// Formatting a certificate validity time.
//
// ssh-keygen prints these in LOCAL time, using localtime(3). sshkeyv
// prints UTC, which is a deliberate difference and is stated in the
// README: reading /etc/localtime means implementing the TZif format and a
// timezone database, which is a different project. The suite runs the
// oracle with TZ=UTC0 so the comparison is still byte for byte.
//
// The sentinels are the part that matters more than the arithmetic. A
// certificate with valid_after 0 and valid_before 2^64-1 is valid forever,
// and ssh-keygen has three special print forms for the combinations.

/// Days since 1970-01-01 to a calendar date. Howard Hinnant's
/// civil_from_days, which is exact for the whole range of i64 days and has
/// no table and no leap-year special cases.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The ISO form ssh-keygen prints: YYYY-MM-DDTHH:MM:SS, no zone suffix.
/// Returns None for a value that cannot be a time: anything above
/// i64::MAX seconds. ssh-keygen casts such a value into a time_t and
/// prints whatever localtime makes of it, which is not something to copy.
pub fn format(t: u64) -> Option<String> {
    if t > i64::MAX as u64 {
        return None;
    }
    let t = t as i64;
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y,
        m,
        d,
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    ))
}

pub const FOREVER: u64 = u64::MAX;

/// The "Valid:" line's text, in ssh-keygen's four forms.
pub fn validity(after: u64, before: u64) -> String {
    match (after, before) {
        (0, FOREVER) => "forever".to_string(),
        (0, b) => match format(b) {
            Some(s) => format!("before {}", s),
            None => format!("before (unrepresentable: {})", b),
        },
        (a, FOREVER) => match format(a) {
            Some(s) => format!("after {}", s),
            None => format!("after (unrepresentable: {})", a),
        },
        (a, b) => match (format(a), format(b)) {
            (Some(x), Some(y)) => format!("from {} to {}", x, y),
            _ => format!("from {} to {} (unrepresentable)", a, b),
        },
    }
}
