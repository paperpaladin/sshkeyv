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

/// Seconds since the epoch, from the system clock.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse an --at argument: either an integer of seconds since the epoch,
/// or YYYY-MM-DDTHH:MM:SS read as UTC. The ISO form is accepted because it
/// is what ssh-keygen prints, so a window read off a -L block can be
/// pasted straight back in.
pub fn parse(s: &str) -> Result<u64, String> {
    if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
        return s.parse::<u64>().map_err(|e| format!("--at {}: {}", s, e));
    }
    let b = s.as_bytes();
    if b.len() != 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T'
        || b[13] != b':' || b[16] != b':'
    {
        return Err(format!(
            "--at {}: want seconds since the epoch or YYYY-MM-DDTHH:MM:SS",
            s
        ));
    }
    let num = |a: usize, z: usize| -> Result<i64, String> {
        s[a..z]
            .parse::<i64>()
            .map_err(|e| format!("--at {}: {}", s, e))
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59
        || sec > 60
    {
        return Err(format!("--at {}: field out of range", s));
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let t = days * 86400 + h * 3600 + mi * 60 + sec;
    if t < 0 {
        return Err(format!("--at {}: before the epoch", s));
    }
    Ok(t as u64)
}

/// The inverse of civil_from_days, same source.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// A duration as ssh-keygen does not print it: this is sshkeyv's own, and
/// the README says so. Days, hours, minutes, seconds, largest two units.
pub fn duration(mut s: u64) -> String {
    let d = s / 86400;
    s %= 86400;
    let h = s / 3600;
    s %= 3600;
    let m = s / 60;
    s %= 60;
    if d > 0 {
        format!("{}d{}h", d, h)
    } else if h > 0 {
        format!("{}h{}m", h, m)
    } else if m > 0 {
        format!("{}m{}s", m, s)
    } else {
        format!("{}s", s)
    }
}
