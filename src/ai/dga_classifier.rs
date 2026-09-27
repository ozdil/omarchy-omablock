use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiClassification {
    Clean,
    SuspiciousDga,
    PhishingTyposquat,
    TrackerHeuristic,
    HighEntropyMalware,
}

impl AiClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::SuspiciousDga => "suspicious_dga",
            Self::PhishingTyposquat => "phishing_typosquat",
            Self::TrackerHeuristic => "tracker_heuristic",
            Self::HighEntropyMalware => "high_entropy_malware",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Clean => "Temiz (Clean)",
            Self::SuspiciousDga => "DGA Algoritmasi (Algorithmic Domain)",
            Self::PhishingTyposquat => "Phishing / Typosquatting",
            Self::TrackerHeuristic => "Reklam / Takipci CDN Sezgisi",
            Self::HighEntropyMalware => "Yuksek Entropili Zararli Alan Adi",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AiRiskAssessment {
    pub domain: String,
    pub risk_score: f64,
    pub is_suspicious: bool,
    pub classification: AiClassification,
    pub entropy: f64,
    pub consonant_vowel_ratio: f64,
    pub max_consonant_run: usize,
    pub reasons: Vec<String>,
}

/// Standalone in-memory specialized AI / Heuristic DGA & Phishing Classifier for OmaBlock
pub struct DgaClassifier {
    known_targets: &'static [&'static str],
    tracker_keywords: &'static [&'static str],
    suspicious_tlds: &'static [&'static str],
}

impl Default for DgaClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DgaClassifier {
    pub fn new() -> Self {
        Self {
            known_targets: &[
                "google", "gmail", "youtube", "github", "microsoft", "apple", "amazon",
                "paypal", "netflix", "cloudflare", "facebook", "instagram", "twitter",
                "binance", "coinbase", "telegram", "discord", "dropbox", "yahoo",
            ],
            tracker_keywords: &[
                "telemetry", "analytics", "adserver", "ads", "track", "tracking",
                "metrics", "pixel", "beacon", "counter", "stat", "stats", "logger",
                "affiliate", "click", "pop", "traffic", "collector", "syndication",
            ],
            suspicious_tlds: &[
                "top", "xyz", "buzz", "click", "fit", "rest", "cam", "bid", "men",
                "work", "date", "racing", "cf", "ga", "gq", "ml", "tk",
            ],
        }
    }

    /// Computes Shannon entropy of string slice: H = -sum(p * log2(p))
    pub fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        let total = s.chars().count() as f64;

        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let mut entropy = 0.0;
        for &count in freq.values() {
            let p = (count as f64) / total;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Calculates consonant vs vowel ratio and maximum consecutive consonant run
    pub fn analyze_phonetics(s: &str) -> (f64, usize) {
        let vowels = ['a', 'e', 'i', 'o', 'u', 'y'];
        let mut vowel_count = 0usize;
        let mut consonant_count = 0usize;
        let mut current_consonant_run = 0usize;
        let mut max_consonant_run = 0usize;

        for c in s.chars().filter(|c| c.is_alphabetic()) {
            let lower = c.to_ascii_lowercase();
            if vowels.contains(&lower) {
                vowel_count += 1;
                current_consonant_run = 0;
            } else {
                consonant_count += 1;
                current_consonant_run += 1;
                if current_consonant_run > max_consonant_run {
                    max_consonant_run = current_consonant_run;
                }
            }
        }

        let total = vowel_count + consonant_count;
        let ratio = if total > 0 {
            (consonant_count as f64) / (total as f64)
        } else {
            0.0
        };

        (ratio, max_consonant_run)
    }

    /// Detects IDN Homograph attacks (Punycode 'xn--' prefix or mixed Cyrillic/Latin scripts)
    pub fn detect_idn_homograph(domain: &str) -> bool {
        if domain.contains("xn--") {
            return true;
        }
        let has_cyrillic = domain.chars().any(|c| {
            let u = c as u32;
            u >= 0x0400 && u <= 0x04FF
        });
        let has_latin = domain.chars().any(|c| c.is_ascii_alphabetic());
        
        has_cyrillic && has_latin
    }

    /// Computes classic Levenshtein distance without heap allocations if small
    pub fn levenshtein(a: &str, b: &str) -> usize {
        let b_len = b.chars().count();
        let mut prev = (0..=b_len).collect::<Vec<usize>>();
        let mut curr = vec![0; b_len + 1];

        for (i, ca) in a.chars().enumerate() {
            curr[0] = i + 1;
            for (j, cb) in b.chars().enumerate() {
                let cost = if ca == cb { 0 } else { 1 };
                curr[j + 1] = std::cmp::min(
                    prev[j + 1] + 1,
                    std::cmp::min(curr[j] + 1, prev[j] + cost),
                );
            }
            prev.copy_from_slice(&curr);
        }

        prev[b_len]
    }

    /// Evaluates domain string and produces an explainable local AI risk assessment
    pub fn assess(&self, raw_domain: &str) -> AiRiskAssessment {
        let domain = raw_domain.trim().to_ascii_lowercase();
        let mut reasons = Vec::new();
        let mut risk_score = 0.0f64;

        if domain.is_empty() {
            return AiRiskAssessment {
                domain,
                risk_score: 0.0,
                is_suspicious: false,
                classification: AiClassification::Clean,
                entropy: 0.0,
                consonant_vowel_ratio: 0.0,
                max_consonant_run: 0,
                reasons: vec!["Bos alan adi".to_string()],
            };
        }

        let parts: Vec<&str> = domain.split('.').collect();
        let main_label = if parts.len() >= 2 {
            parts[parts.len() - 2]
        } else {
            &domain
        };
        let tld = parts.last().copied().unwrap_or("");

        // 1. Entropy Analysis
        let entropy = Self::shannon_entropy(main_label);
        if entropy > 3.9 && main_label.len() >= 8 {
            risk_score += 0.45;
            reasons.push(format!("Asiri yuksek entropi ({:.2} bits/char): rastgele DGA veya makine uretimi deseni", entropy));
        } else if entropy > 3.4 && main_label.len() >= 10 {
            risk_score += 0.25;
            reasons.push(format!("Yuksek entropi seviyesi ({:.2} bits/char)", entropy));
        }

        // 2. Phonetics & Consonant Cluster Analysis
        let (consonant_ratio, max_consonant_run) = Self::analyze_phonetics(main_label);
        if max_consonant_run >= 5 {
            risk_score += 0.35;
            reasons.push(format!("Ard arda {} unsuz harf yigilmasi (anlamsiz sozcuk / DGA belirtisi)", max_consonant_run));
        }
        if consonant_ratio > 0.85 && main_label.len() >= 6 {
            risk_score += 0.25;
            reasons.push(format!("Dogal dilden uzak unsuz harf orani (%{:.0})", consonant_ratio * 100.0));
        }

        // 3. Digit Ratio Analysis
        let digit_count = main_label.chars().filter(|c| c.is_ascii_digit()).count();
        if digit_count >= 4 && (digit_count as f64) / (main_label.len() as f64) > 0.35 {
            risk_score += 0.30;
            reasons.push(format!("Alan adi ana etiketinde yogun sayisal karakter kullanimi ({}/{})", digit_count, main_label.len()));
        }

        // 4. Typosquatting & Phishing Detection with Leetspeak Normalization
        let mut typosquat_found = false;
        
        if Self::detect_idn_homograph(&domain) {
            risk_score += 0.95;
            reasons.push("Kritik Uyari: IDN Homograph / Punycode (Karisik Alfabe) Spoofing Tespiti".to_string());
            typosquat_found = true;
        }

        let leet_normalized: String = main_label.chars().map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '@' => 'a',
            _ => c,
        }).collect();

        for &target in self.known_targets {
            if main_label == target {
                continue;
            }
            if leet_normalized == target {
                risk_score += 0.75;
                reasons.push(format!("'{}' markasina yonelik l33tspeak karakter degisimiyle gizlenmis phishing tespiti", target));
                typosquat_found = true;
                break;
            }
            if (main_label.contains(target) || leet_normalized.contains(target)) && main_label.len() > target.len() + 2 {
                risk_score += 0.50;
                reasons.push(format!("Guvenilir marka adini ('{}') iceren sahte tuzak kombinasyonu", target));
                typosquat_found = true;
                break;
            }
            let dist = Self::levenshtein(main_label, target);
            let leet_dist = Self::levenshtein(&leet_normalized, target);
            let min_dist = std::cmp::min(dist, leet_dist);
            if min_dist == 1 && main_label.len() >= 4 {
                risk_score += 0.60;
                reasons.push(format!("'{}' markasina yonelik 1 harf mesafeli hedefli typosquatting / phishing taklidi", target));
                typosquat_found = true;
                break;
            }
        }

        // 5. Ad/Tracker/Telemetry Keyword Heuristics (exclude TLD)
        let mut tracker_found = false;
        let non_tld_parts = if parts.len() > 1 {
            &parts[..parts.len() - 1]
        } else {
            &parts[..]
        };
        for part in non_tld_parts {
            for &kw in self.tracker_keywords {
                if part == &kw || part.starts_with(&format!("{}-", kw)) || part.ends_with(&format!("-{}", kw)) {
                    risk_score += 0.50;
                    reasons.push(format!("Reklam veya telemetri altyapi anahtar kelimesi tespit edildi: '{}'", kw));
                    tracker_found = true;
                    break;
                }
            }
        }

        // 6. Suspicious TLD Scoring
        if self.suspicious_tlds.contains(&tld) {
            risk_score += 0.20;
            reasons.push(format!("Kotuye kullanim orani yuksek TLD uzantisi: '.{}'", tld));
        }

        // 7. Excessive Subdomain Tree Depth
        if parts.len() >= 5 {
            risk_score += 0.20;
            reasons.push(format!("Supheli alt alan adi derinligi ({} kademe)", parts.len()));
        }

        // Clamp risk score to 1.0
        let final_score = risk_score.min(1.0);
        let is_suspicious = final_score >= 0.55;

        let classification = if !is_suspicious {
            AiClassification::Clean
        } else if typosquat_found {
            AiClassification::PhishingTyposquat
        } else if tracker_found {
            AiClassification::TrackerHeuristic
        } else if entropy > 3.2 || max_consonant_run >= 4 || consonant_ratio > 0.70 {
            AiClassification::SuspiciousDga
        } else {
            AiClassification::HighEntropyMalware
        };

        if reasons.is_empty() {
            reasons.push("Normal sozluk uyumu ve dengeli harf entropisi".to_string());
        }

        AiRiskAssessment {
            domain,
            risk_score: (final_score * 100.0).round() / 100.0,
            is_suspicious,
            classification,
            entropy: (entropy * 100.0).round() / 100.0,
            consonant_vowel_ratio: (consonant_ratio * 100.0).round() / 100.0,
            max_consonant_run,
            reasons,
        }
    }
}
