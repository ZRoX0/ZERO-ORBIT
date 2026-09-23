// shield.rs — ZERO-ORBIT safety layer.
//
// Usage:
//   shield check --target <host-or-url>
//   (scope lines are read from stdin, one per line)
//
// Exit codes:
//   0 = allowed
//   1 = blocked
//   2 = bad usage
//
// Also provides:
//   shield validate-url   → reads URL from stdin, normalizes + prints
//   shield rate --rps N   → reads timestamps from stdin, reports violations

use std::env;
use std::io::{self, Read, Write};
use std::process::exit;
use std::time::{Duration, Instant};

// ---------- Scope matching ----------

fn host_from_target(t: &str) -> String {
    let mut s = t.trim().to_string();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    // cut at first '/' or ':' 
    let cut = s.find(|c| c == '/' || c == ':').unwrap_or(s.len());
    s.truncate(cut);
    s.to_lowercase()
}

fn scope_allows(host: &str, scope: &[String]) -> bool {
    let h = host.to_lowercase();
    for raw in scope {
        let e = raw.trim().to_lowercase();
        if e.is_empty() || e.starts_with('#') {
            continue;
        }
        if let Some(suffix) = e.strip_prefix("*.") {
            if h == suffix || h.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        } else if e == h {
            return true;
        }
    }
    false
}

// ---------- Input validation ----------

fn validate_target(t: &str) -> Result<String, String> {
    if t.is_empty() {
        return Err("empty target".into());
    }
    if t.len() > 253 {
        return Err("target too long".into());
    }
    // Reject obvious dangerous characters
    for c in t.chars() {
        if c.is_control() {
            return Err(format!("control character in target: {:?}", c));
        }
    }
    // Basic hostname / URL sanity
    let host = host_from_target(t);
    if host.is_empty() {
        return Err("empty host".into());
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err("empty label in host".into());
        }
        for c in label.chars() {
            if !(c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(format!("invalid character in host: {}", c));
            }
        }
    }
    Ok(host)
}

// ---------- Subcommands ----------

fn cmd_check(target: &str) -> i32 {
    let host = match validate_target(target) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("shield: invalid target: {}", e);
            return 1;
        }
    };

    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        eprintln!("shield: failed to read scope");
        return 1;
    }
    let scope: Vec<String> = buf.lines().map(|s| s.to_string()).collect();

    if scope_allows(&host, &scope) {
        // Output a machine-readable OK
        println!("{{\"allowed\":true,\"host\":\"{}\"}}", host);
        0
    } else {
        eprintln!("shield: target '{}' is NOT in scope", host);
        println!("{{\"allowed\":false,\"host\":\"{}\"}}", host);
        1
    }
}

fn cmd_validate_url() -> i32 {
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        return 2;
    }
    let url = buf.trim();
    match validate_target(url) {
        Ok(h) => {
            println!("{{\"valid\":true,\"host\":\"{}\"}}", h);
            0
        }
        Err(e) => {
            println!("{{\"valid\":false,\"error\":\"{}\"}}", e);
            1
        }
    }
}

fn cmd_rate(rps: u64) -> i32 {
    // Read timestamps (milliseconds since epoch) one per line from stdin.
    // Report if the input burst exceeded the RPS budget.
    if rps == 0 {
        eprintln!("shield: rps must be > 0");
        return 2;
    }
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        return 2;
    }
    let mut ts: Vec<u128> = buf
        .lines()
        .filter_map(|l| l.trim().parse::<u128>().ok())
        .collect();
    ts.sort_unstable();
    if ts.len() < 2 {
        println!("{{\"violations\":0,\"observed_rps\":0.0}}");
        return 0;
    }

    let window_ms: u128 = 1000;
    let mut violations = 0u64;
    let mut i = 0usize;
    for j in 0..ts.len() {
        while ts[j].saturating_sub(ts[i]) > window_ms {
            i += 1;
        }
        let count = (j - i + 1) as u64;
        if count > rps {
            violations += 1;
        }
    }
    let span_ms = ts.last().unwrap().saturating_sub(ts[0]).max(1);
    let observed = (ts.len() as f64) * 1000.0 / (span_ms as f64);
    println!(
        "{{\"violations\":{},\"observed_rps\":{:.3}}}",
        violations, observed
    );
    0
}

// ---------- Main ----------

fn usage() {
    let _ = writeln!(
        io::stderr(),
        "shield — ZERO-ORBIT safety layer\n\
         \n\
         Usage:\n\
           shield check --target <host-or-url>     (scope lines on stdin)\n\
           shield validate-url                     (url on stdin)\n\
           shield rate --rps <N>                   (timestamps on stdin)\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        exit(2);
    }

    let code = match args[1].as_str() {
        "check" => {
            let mut target = String::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--target" if i + 1 < args.len() => {
                        target = args[i + 1].clone();
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            if target.is_empty() {
                usage();
                exit(2);
            }
            cmd_check(&target)
        }
        "validate-url" => cmd_validate_url(),
        "rate" => {
            let mut rps = 0u64;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--rps" if i + 1 < args.len() => {
                        rps = args[i + 1].parse().unwrap_or(0);
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            cmd_rate(rps)
        }
        "-h" | "--help" => {
            usage();
            0
        }
        _ => {
            usage();
            2
        }
    };

    exit(code);
}