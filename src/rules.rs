//! Rule list parsing shared by the engine binary and the integration tests.

use crate::validation::validate_domain;
use std::collections::HashMap;
use std::io::BufRead;

pub const HOSTS_BEGIN_MARKER: &str = "# --- BEGIN OMABLOCK MANAGED RULES ---";
pub const HOSTS_END_MARKER: &str = "# --- END OMABLOCK MANAGED RULES ---";

/// Endpoints that sign-in, account switching and Google's web consoles (Play Console,
/// Firebase, Cloud) need to save changes. Aggressive upstream lists include some of them
/// as telemetry, which makes those consoles fail silently, so they are never written to
/// /etc/hosts whatever the lists say. An explicit user blacklist entry still wins.
pub const ESSENTIAL_DOMAINS: &[&str] = &[
    "accounts.google.com",
    "apis.google.com",
    "ogs.google.com",
    "play.google.com",
    "www.google.com",
    "ogads-pa.clients6.google.com",
    "ogads-pa.googleapis.com",
    "peoplestackwebexperiments-pa.clients6.google.com",
    "playconsole-pa.clients6.google.com",
    "playconsole-pa.googleapis.com",
    "play-fe.googleapis.com",
    "androidpublisher.googleapis.com",
    "content.googleapis.com",
    "www.googleapis.com",
    "oauth2.googleapis.com",
    "firebase.googleapis.com",
    "firebaseinstallations.googleapis.com",
    "firebaseremoteconfig.googleapis.com",
    "console.firebase.google.com",
    "console.cloud.google.com",
    "www.gstatic.com",
    "ssl.gstatic.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
];

pub fn is_essential_domain(domain: &str) -> bool {
    ESSENTIAL_DOMAINS.contains(&domain)
}

/// Merges `category domain` (or bare `domain`, filed under ads) lines into `all_rules`.
/// Comments, blanks and entries that fail `validate_domain` are skipped, so a tampered
/// cache cannot smuggle hosts-file syntax into the generated block. Returns how many
/// entries were rejected.
pub fn parse_rules_content(content: &str, all_rules: &mut HashMap<String, String>) -> usize {
    let mut rejected = 0;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (cat, raw_domain) = match parts.as_slice() {
            [domain] => ("ads".to_string(), *domain),
            [cat, domain, ..] => (cat.to_lowercase(), *domain),
            [] => continue,
        };
        match validate_domain(raw_domain) {
            Ok(domain) => {
                all_rules.insert(domain, cat);
            }
            Err(_) => rejected += 1,
        }
    }
    rejected
}

/// Number of IPv4 sinkhole entries inside the OmaBlock block of a hosts file.
/// Counts what is actually enforced (categories, level, whitelist and blacklist already
/// applied), unlike the size of the loaded rule set. The `::` DoH lines duplicate
/// an IPv4 entry and are not counted twice.
pub fn count_managed_hosts_rules<R: BufRead>(reader: R) -> usize {
    let mut inside_block = false;
    let mut count = 0;
    // Split on raw bytes: the helper preserves non-UTF-8 bytes in /etc/hosts, and
    // `lines()` would stop at the first such line before reaching the block.
    for line in reader.split(b'\n').map_while(Result::ok) {
        let line = String::from_utf8_lossy(&line);
        let trimmed = line.trim();
        if trimmed.contains(HOSTS_BEGIN_MARKER) {
            inside_block = true;
            continue;
        }
        if trimmed.contains(HOSTS_END_MARKER) {
            break;
        }
        if inside_block && trimmed.starts_with("0.0.0.0 ") {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn essential_domains_are_valid_and_normalised() {
        for d in ESSENTIAL_DOMAINS {
            assert_eq!(validate_domain(d).as_deref(), Ok(*d), "{d}");
        }
        assert!(is_essential_domain("play.google.com"));
        assert!(!is_essential_domain("ads.google.com"));
    }
}
