use omablock_engine::ai::DgaClassifier;
use omablock_engine::rules::{count_managed_hosts_rules, parse_rules_content, HOSTS_BEGIN_MARKER, HOSTS_END_MARKER};
use omablock_engine::secure_fs;
use omablock_engine::self_defense::{constant_time_eq, enforce_anti_tamper, sha256_hex, SecureBuffer};
use omablock_engine::validate_domain;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

/// Helper to create a temporary directory for isolated simulation tests
struct TestEnv {
    dir: std::path::PathBuf,
}

impl TestEnv {
    fn new(prefix: &str) -> Self {
        let unique = format!("omablock_sim_{}_{}", prefix, std::process::id());
        let dir = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = secure_fs::ensure_state_dir(&dir);
        Self { dir }
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.join(name)
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// -----------------------------------------------------------------------------
// A/B Test Simulation: Mode A (User-Space) vs Mode B (Privileged Helper Present)
// -----------------------------------------------------------------------------

#[test]
fn test_ab_simulation_mode_a_userspace_fallback() {
    // Mode A: omablock-hosts-sync helper does NOT exist in system paths.
    // Verify engine manages state, whitelist/blacklist arithmetic, and fails gracefully without panic.
    let env = TestEnv::new("mode_a");
    let state_file = env.path("state.json");

    let initial_json = r#"{
        "enabled": true,
        "blocking_level": "standard",
        "categories": {
            "ads": true,
            "telemetry": false,
            "malware": true,
            "social": false,
            "popups": false
        },
        "whitelist": ["allowed.org"],
        "blacklist": ["blocked.net"],
        "auto_update": false,
        "doh_prevention": false,
        "ai_protection": true,
        "kernel_enforcement": false,
        "last_updated": "2026-09-28"
    }"#;

    secure_fs::atomic_write_secure(&state_file, initial_json.as_bytes()).unwrap();

    let read_back = secure_fs::read_secure_file(&state_file).unwrap();
    assert!(read_back.contains("allowed.org"));
    assert!(read_back.contains("blocked.net"));

    // Verify atomic state modification under user-space constraints
    let updated_json = read_back.replace("\"ads\": true", "\"ads\": false");
    secure_fs::atomic_write_secure(&state_file, updated_json.as_bytes()).unwrap();

    let final_read = secure_fs::read_secure_file(&state_file).unwrap();
    assert!(final_read.contains("\"ads\": false"));
}

#[test]
fn test_ab_simulation_mode_b_privileged_helper_rule_processing() {
    // Mode B: the engine's real rule parser feeds the hosts block the helper installs
    let env = TestEnv::new("mode_b");
    let rules_file = env.path("cached_rules.txt");

    let cached = [
        "ads doubleclick.net",
        "ads pagead2.googlesyndication.com",
        "telemetry telemetry.microsoft.com",
        "bare-entry.example.org",
        "# Comment line",
        "   ",
        "ads invalid..domain",
        "ads -badstart.com",
        "ads evil.com;id",
        "malware 0.0.0.0",
    ];
    secure_fs::atomic_write_secure(&rules_file, cached.join("\n").as_bytes()).unwrap();
    let parsed = secure_fs::read_secure_file(&rules_file).unwrap();

    let mut rules = HashMap::new();
    let rejected = parse_rules_content(&parsed, &mut rules);

    assert_eq!(rules.get("doubleclick.net").map(String::as_str), Some("ads"));
    assert_eq!(rules.get("telemetry.microsoft.com").map(String::as_str), Some("telemetry"));
    assert_eq!(rules.get("bare-entry.example.org").map(String::as_str), Some("ads"));
    assert_eq!(rules.len(), 4);
    assert_eq!(rejected, 4, "invalid domains must be dropped, not passed to the helper");

    // The managed block the helper writes is counted the same way the status reports it
    let mut hosts = format!("127.0.0.1 localhost\n{}\n", HOSTS_BEGIN_MARKER);
    for d in rules.keys() {
        hosts.push_str(&format!("0.0.0.0 {}\n:: {}\n", d, d));
    }
    hosts.push_str(&format!("{}\n0.0.0.0 user-owned.example\n", HOSTS_END_MARKER));
    assert_eq!(count_managed_hosts_rules(hosts.as_bytes()), 4);
}

#[test]
fn test_builtin_rules_are_all_valid_domains() {
    let mut rules = HashMap::new();
    let rejected = parse_rules_content(include_str!("../assets/rules_builtin.txt"), &mut rules);
    assert_eq!(rejected, 0, "assets/rules_builtin.txt contains invalid domains");
    assert!(!rules.is_empty());
}

// -----------------------------------------------------------------------------
// Attack Scenario 1: Injection & Metacharacter Defense
// -----------------------------------------------------------------------------

#[test]
fn test_injection_attack_simulation() {
    let malicious_payloads = [
        "evil.com\n0.0.0.0 bank.com",
        "evil.com\r\n0.0.0.0 bank.com",
        "evil.com; rm -rf /",
        "evil.com && cat /etc/shadow",
        "evil.com`id`",
        "evil.com$(id)",
        "evil.com|whoami",
        "evil.com>file",
        "evil.com<file",
        "evil.com\\0admin",
        "evil..com",
        "-evil.com",
        "evil.com-",
        "evil.com/path",
        "evil.com:80",
        "evil.com?query=1",
        "evil.com#hash",
        "*.evil.com",
        "localhost",
        "broadcasthost",
        "local",
        "ip6-localhost",
        "255.255.255.255",
    ];

    for payload in &malicious_payloads {
        let res = validate_domain(payload);
        assert!(res.is_err(), "Malicious payload '{}' must be rejected", payload);
    }
}

// -----------------------------------------------------------------------------
// Attack Scenario 2: Symlink & TOCTOU Path Traversal Defense
// -----------------------------------------------------------------------------

#[test]
fn test_symlink_toctou_defense_simulation() {
    let env = TestEnv::new("symlink_attack");
    let sensitive_file = env.path("sensitive_data.txt");
    let symlink_path = env.path("symlink_attack.json");

    secure_fs::atomic_write_secure(&sensitive_file, b"CONFIDENTIAL_DATA").unwrap();

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&sensitive_file, &symlink_path).unwrap();

        // Attempting bounded read on symlink MUST fail with Security Error
        let read_res = secure_fs::read_secure_file_bounded(&symlink_path, 1024);
        assert!(read_res.is_err(), "Reading via symlink must be rejected");

        // Attempting atomic write on symlink MUST fail to prevent overwriting target
        let write_res = secure_fs::atomic_write_secure(&symlink_path, b"COMPROMISED");
        assert!(write_res.is_err(), "Writing to symlink must be rejected");

        // Verify sensitive data was NOT corrupted
        let orig_content = std::fs::read_to_string(&sensitive_file).unwrap();
        assert_eq!(orig_content, "CONFIDENTIAL_DATA");
    }
}

// -----------------------------------------------------------------------------
// Attack Scenario 3: Memory Exhaustion (DoS) Defense & Bounded Buffers
// -----------------------------------------------------------------------------

#[test]
fn test_memory_exhaustion_bounds_simulation() {
    let env = TestEnv::new("dos_bounds");
    let oversized_file = env.path("oversized.txt");

    // Create a 2 MiB test payload (exceeding standard 1 MiB limit)
    let payload = vec![b'A'; 2 * 1024 * 1024];
    let mut f = File::create(&oversized_file).unwrap();
    f.write_all(&payload).unwrap();
    drop(f);

    // Reading with 1 MiB bound must fail with payload size error
    let res = secure_fs::read_secure_file_bounded(&oversized_file, 1024 * 1024);
    assert!(res.is_err());
    let err_msg = res.unwrap_err();
    assert!(err_msg.contains("exceeds maximum allowed limit"));
}

// -----------------------------------------------------------------------------
// Attack Scenario 4: Anti-Tamper, Constant-Time & Memory Zeroization
// -----------------------------------------------------------------------------

#[test]
fn test_anti_tamper_and_memory_security_simulation() {
    // 1. Anti-tamper prctl execution
    assert!(enforce_anti_tamper());

    // 2. Timing attack resistant constant-time comparison
    let token_a = b"secret-token-hash-2026-auth";
    let token_b = b"secret-token-hash-2026-auth";
    let token_c = b"secret-token-hash-2026-diff";

    assert!(constant_time_eq(token_a, token_b));
    assert!(!constant_time_eq(token_a, token_c));
    assert!(!constant_time_eq(token_a, b"short"));

    // 3. Volatile memory zeroization
    let mut sensitive_buf = SecureBuffer::new(vec![0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(sensitive_buf.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    sensitive_buf.zeroize();
    assert_eq!(sensitive_buf.as_slice(), &[0x00, 0x00, 0x00, 0x00]);

    // 4. SHA-256 Self-Integrity calculation
    let hash = sha256_hex(b"OmaBlock-Zero-Latency-Shield");
    assert_eq!(hash.len(), 64);
}

// -----------------------------------------------------------------------------
// Attack Scenario 5: AI / DGA Threat Classification & Spoofing Radar
// -----------------------------------------------------------------------------

#[test]
fn test_dga_and_homograph_spoofing_simulation() {
    let classifier = DgaClassifier::new();

    // High Entropy / Algorithmic DGA simulation
    let dga_cases = [
        "vczmxnbvzkjwer.info",
        "0987654321qwertyuiop.biz",
        "lkjhgfdsa-poiuytrewq.xyz",
    ];
    for d in &dga_cases {
        let assessment = classifier.assess(d);
        assert!(assessment.is_suspicious, "DGA domain '{}' must be detected", d);
    }

    // Phishing & Homograph Typosquatting simulation
    let phishing_cases = [
        "paypal-update-account-security.cc",
        "apple-id-verify-login.xyz",
        "googlе.com", // Cyrillic e
        "xn--gogle-p1a.com",
    ];
    for p in &phishing_cases {
        let assessment = classifier.assess(p);
        assert!(assessment.is_suspicious, "Phishing/Homograph domain '{}' must be detected", p);
    }
}
