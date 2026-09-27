use omablock_engine::ai::{AiClassification, DgaClassifier};
use omablock_engine::kernel::KernelNetfilter;
use std::net::IpAddr;

#[test]
fn test_shannon_entropy_calculation() {
    // Single character or repeated: entropy should be 0.0
    let ent_zero = DgaClassifier::shannon_entropy("aaaaaaa");
    assert_eq!(ent_zero, 0.0);

    // Highly diverse string: entropy should be high (> 3.5)
    let ent_high = DgaClassifier::shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789");
    assert!(ent_high > 4.5);

    // Typical English word domain: entropy should be around 2.0 - 3.2
    let ent_word = DgaClassifier::shannon_entropy("google");
    assert!(ent_word < 3.2);
}

#[test]
fn test_dga_classifier_clean_domains() {
    let classifier = DgaClassifier::new();

    let clean_domains = [
        "google.com",
        "github.com",
        "archlinux.org",
        "wikipedia.org",
        "omarchy.org",
    ];

    for domain in &clean_domains {
        let res = classifier.assess(domain);
        assert!(
            !res.is_suspicious,
            "Clean domain '{}' should not be flagged as suspicious (score: {})",
            domain, res.risk_score
        );
        assert_eq!(res.classification, AiClassification::Clean);
    }
}

#[test]
fn test_dga_classifier_algorithmic_dga() {
    let classifier = DgaClassifier::new();

    let dga_domains = [
        "xkjqwpznvmcrtybg.xyz",
        "asdfghjklqwerty.top",
        "zxcvbnmasdfghjk123.biz",
        "qwertyuiopasdfgh.click",
    ];

    for domain in &dga_domains {
        let res = classifier.assess(domain);
        assert!(
            res.is_suspicious,
            "DGA domain '{}' should be flagged as suspicious (score: {})",
            domain, res.risk_score
        );
        assert!(
            res.classification == AiClassification::SuspiciousDga
                || res.classification == AiClassification::HighEntropyMalware
        );
    }
}

#[test]
fn test_dga_classifier_typosquatting_and_phishing() {
    let classifier = DgaClassifier::new();

    let phishing_domains = [
        "g00gle.com",
        "paypa1.com",
        "paypal-verify-login.xyz",
        "github-security-auth.top",
    ];

    for domain in &phishing_domains {
        let res = classifier.assess(domain);
        assert!(
            res.is_suspicious,
            "Phishing domain '{}' should be flagged as suspicious (score: {})",
            domain, res.risk_score
        );
        assert_eq!(res.classification, AiClassification::PhishingTyposquat);
    }
}

#[test]
fn test_dga_classifier_tracker_heuristics() {
    let classifier = DgaClassifier::new();

    let tracker_domains = [
        "telemetry.badservice.xyz",
        "adserver-traffic.click",
        "tracking-pixel.adnetwork.top",
    ];

    for domain in &tracker_domains {
        let res = classifier.assess(domain);
        assert!(
            res.is_suspicious,
            "Tracker domain '{}' should be flagged as suspicious (score: {})",
            domain, res.risk_score
        );
    }
}

#[test]
fn test_kernel_netfilter_ruleset_generation() {
    let test_ips: Vec<IpAddr> = vec![
        "1.1.1.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
    ];

    let ruleset = KernelNetfilter::generate_ruleset(&test_ips);

    assert!(ruleset.contains("table inet omablock"));
    assert!(ruleset.contains("set bad_ipv4"));
    assert!(ruleset.contains("set bad_ipv6"));
    assert!(ruleset.contains("1.1.1.1"));
    assert!(ruleset.contains("8.8.8.8"));
    assert!(ruleset.contains("2606:4700:4700::1111"));
    assert!(ruleset.contains("chain output"));
    assert!(ruleset.contains("reject with icmp type admin-prohibited"));
}
