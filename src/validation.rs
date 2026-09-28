/// Validates that a string is a legitimate RFC 1035 domain name without shell/hosts injection
pub fn validate_domain(raw: &str) -> Result<String, String> {
    let s = raw.trim().trim_end_matches('.').to_lowercase();
    if s.is_empty() {
        return Err("Domain cannot be empty".to_string());
    }
    if s.len() > 253 {
        return Err("Domain exceeds maximum length of 253 characters".to_string());
    }

    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return Err("Domain must contain at least one dot separating label and TLD".to_string());
    }

    let last_label = labels[labels.len() - 1];
    if matches!(last_label, "local" | "localhost" | "lan" | "internal" | "arpa" | "test" | "invalid") {
        return Err(format!("Domain belongs to reserved local/internal TLD: .{}", last_label));
    }

    let reserved_names = [
        "localhost",
        "broadcasthost",
        "local",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
        "255.255.255.255",
    ];
    if reserved_names.contains(&s.as_str()) {
        return Err(format!("Domain is a reserved system hostname: {}", s));
    }

    for label in &labels {
        if label.is_empty() {
            return Err("Domain contains empty label (e.g. consecutive dots)".to_string());
        }
        if label.len() > 63 {
            return Err("Domain label exceeds 63 characters".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain label cannot start or end with a hyphen".to_string());
        }
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
                return Err(format!("Domain contains invalid character: '{}'", ch));
            }
        }
    }

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_domains() {
        assert!(validate_domain("google.com").is_ok());
        assert!(validate_domain("sub.domain.co.uk").is_ok());
        assert!(validate_domain("adservice.google.com.").is_ok());
    }

    #[test]
    fn test_invalid_domains() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("localhost").is_err());
        assert!(validate_domain("malicious;rm -rf /").is_err());
        assert!(validate_domain("double..dots.com").is_err());
        assert!(validate_domain("-start-hyphen.com").is_err());
    }
}
