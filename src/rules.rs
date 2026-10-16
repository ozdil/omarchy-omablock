//! Rule list parsing shared by the engine binary and the integration tests.

use crate::validation::validate_domain;
use std::collections::HashMap;
use std::io::BufRead;

pub const HOSTS_BEGIN_MARKER: &str = "# --- BEGIN OMABLOCK MANAGED RULES ---";
pub const HOSTS_END_MARKER: &str = "# --- END OMABLOCK MANAGED RULES ---";

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
    for line in reader.lines().map_while(Result::ok) {
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
