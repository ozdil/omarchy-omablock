use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

const BUILTIN_RULES: &str = include_str!("../assets/rules_builtin.txt");

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CategoriesConfig {
    pub ads: bool,
    pub telemetry: bool,
    pub malware: bool,
    pub social: bool,
}

impl Default for CategoriesConfig {
    fn default() -> Self {
        Self {
            ads: true,
            telemetry: true,
            malware: true,
            social: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestDetail {
    pub domain: String,
    pub expected_blocked: bool,
    pub actual_blocked: bool,
    pub resolved_ip: String,
    pub latency_ms: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestSummary {
    pub success: bool,
    pub message: String,
    pub avg_latency_ms: f64,
    pub blocked_tested: usize,
    pub allowed_tested: usize,
    pub timestamp: String,
    pub details: Vec<TestDetail>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OmaBlockConfig {
    pub enabled: bool,
    pub categories: CategoriesConfig,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub last_updated: Option<String>,
    pub last_test: Option<TestSummary>,
}

impl Default for OmaBlockConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            categories: CategoriesConfig::default(),
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            last_updated: Some("Built-in Curated v1.0".to_string()),
            last_test: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusOutput {
    pub enabled: bool,
    pub active_rules: usize,
    pub total_rules: usize,
    pub categories: CategoriesConfig,
    pub category_counts: HashMap<String, usize>,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub last_updated: String,
    pub last_test: Option<TestSummary>,
    pub system_hosts_active: bool,
}

fn get_state_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ozdil".to_string());
    PathBuf::from(home).join(".local/state/omarchy/omablock")
}

fn get_config_path() -> PathBuf {
    get_state_dir().join("config.json")
}

fn get_cached_rules_path() -> PathBuf {
    get_state_dir().join("rules_cached.txt")
}

fn get_active_hosts_path() -> PathBuf {
    get_state_dir().join("active_hosts.txt")
}

fn load_config() -> OmaBlockConfig {
    let path = get_config_path();
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<OmaBlockConfig>(&data) {
                return cfg;
            }
        }
    }
    let default_cfg = OmaBlockConfig::default();
    save_config(&default_cfg);
    default_cfg
}

fn save_config(cfg: &OmaBlockConfig) {
    let dir = get_state_dir();
    let _ = fs::create_dir_all(&dir);
    let path = get_config_path();
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        let _ = fs::write(path, json);
    }
}

fn send_notification(summary: &str, body: &str) {
    let _ = Command::new("notify-send")
        .args(["-a", "OmaBlock", summary, body])
        .output();
}

struct ParsedRules {
    pub all_rules: HashMap<String, String>, // domain -> category
    pub category_counts: HashMap<String, usize>,
}

fn parse_rules_content(content: &str, all_rules: &mut HashMap<String, String>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let cat = parts[0].to_lowercase();
            let domain = parts[1].to_lowercase();
            all_rules.insert(domain, cat);
        } else if parts.len() == 1 {
            let domain = parts[0].to_lowercase();
            all_rules.insert(domain, "ads".to_string());
        }
    }
}

fn load_all_rules() -> ParsedRules {
    let mut all_rules = HashMap::new();
    let mut category_counts = HashMap::new();
    category_counts.insert("ads".to_string(), 0);
    category_counts.insert("telemetry".to_string(), 0);
    category_counts.insert("malware".to_string(), 0);
    category_counts.insert("social".to_string(), 0);

    // 1. Always load curated builtin rules FIRST (ensures telemetry and ad sinks exist)
    parse_rules_content(BUILTIN_RULES, &mut all_rules);

    // 2. Overlay cached upstream rules if available
    let cached_path = get_cached_rules_path();
    if cached_path.exists() {
        if let Ok(content) = fs::read_to_string(&cached_path) {
            parse_rules_content(&content, &mut all_rules);
        }
    }

    for cat in all_rules.values() {
        if let Some(c) = category_counts.get_mut(cat) {
            *c += 1;
        }
    }

    ParsedRules {
        all_rules,
        category_counts,
    }
}

fn is_system_hosts_active() -> bool {
    let hosts_path = "/etc/hosts";
    if let Ok(content) = fs::read_to_string(hosts_path) {
        content.contains("# --- BEGIN OMABLOCK MANAGED RULES ---")
    } else {
        false
    }
}

fn sync_system_hosts(cfg: &OmaBlockConfig, rules: &ParsedRules) -> usize {
    if !cfg.enabled {
        let _ = Command::new("sudo")
            .args(["/usr/local/bin/omablock-hosts-sync", "--clear"])
            .output();
        return 0;
    }

    let whitelist_set: HashSet<String> = cfg.whitelist.iter().map(|d| d.to_lowercase()).collect();
    let mut active_domains: HashSet<String> = HashSet::new();

    for (domain, cat) in &rules.all_rules {
        let is_cat_enabled = match cat.as_str() {
            "ads" => cfg.categories.ads,
            "telemetry" => cfg.categories.telemetry,
            "malware" => cfg.categories.malware,
            "social" => cfg.categories.social,
            _ => true,
        };

        if is_cat_enabled {
            // Check whitelist
            let mut whitelisted = whitelist_set.contains(domain);
            if !whitelisted {
                for wl in &whitelist_set {
                    if domain.ends_with(&format!(".{}", wl)) {
                        whitelisted = true;
                        break;
                    }
                }
            }
            if !whitelisted {
                active_domains.insert(domain.clone());
            }
        }
    }

    // Add blacklist
    for bl in &cfg.blacklist {
        active_domains.insert(bl.to_lowercase());
    }

    let active_path = get_active_hosts_path();
    let _ = fs::create_dir_all(get_state_dir());
    if let Ok(mut f) = File::create(&active_path) {
        for d in &active_domains {
            let _ = writeln!(f, "0.0.0.0 {}", d);
        }
    }

    let _ = Command::new("sudo")
        .args([
            "/usr/local/bin/omablock-hosts-sync",
            "--apply",
            active_path.to_str().unwrap(),
        ])
        .output();

    active_domains.len()
}

fn run_verification_test(cfg: &mut OmaBlockConfig, rules: &ParsedRules) -> TestSummary {
    if cfg.enabled {
        let _ = sync_system_hosts(cfg, rules);
        let _ = Command::new("sudo").args(["resolvectl", "flush-caches"]).output();
    }

    let test_domains = vec![
        ("doubleclick.net", cfg.categories.ads),
        ("pagead2.googlesyndication.com", cfg.categories.ads),
        ("telemetry.microsoft.com", cfg.categories.telemetry),
        ("google-analytics.com", cfg.categories.telemetry),
        ("archlinux.org", false),
    ];

    let mut details = Vec::new();
    let mut total_latency = 0.0;
    let mut all_passed = true;
    let mut blocked_count = 0;
    let mut allowed_count = 0;

    for (domain, should_block) in test_domains {
        let start = Instant::now();
        let target = format!("{}:80", domain);
        let mut is_blocked = false;
        let mut resolved_ip = "UNRESOLVED".to_string();

        if let Ok(mut addrs) = target.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                resolved_ip = addr.ip().to_string();
                if resolved_ip == "0.0.0.0" || resolved_ip == "127.0.0.1" {
                    is_blocked = true;
                }
            }
        }

        let elapsed_ms = (start.elapsed().as_nanos() as f64) / 1_000_000.0;
        total_latency += elapsed_ms;

        let pass = if should_block {
            if cfg.enabled {
                is_blocked
            } else {
                !is_blocked
            }
        } else {
            !is_blocked
        };

        if !pass {
            all_passed = false;
        }

        if is_blocked {
            blocked_count += 1;
        } else {
            allowed_count += 1;
        }

        details.push(TestDetail {
            domain: domain.to_string(),
            expected_blocked: should_block && cfg.enabled,
            actual_blocked: is_blocked,
            resolved_ip,
            latency_ms: (elapsed_ms * 100.0).round() / 100.0,
        });
    }

    let avg_latency = if !details.is_empty() {
        (total_latency / details.len() as f64 * 100.0).round() / 100.0
    } else {
        0.0
    };

    let summary_msg = if cfg.enabled {
        if all_passed {
            format!(
                "Protection Verified: {}/4 ad & tracker domains blocked (avg {}ms)",
                blocked_count, avg_latency
            )
        } else {
            "Partial: Some domains were not blocked by sinkhole".to_string()
        }
    } else {
        "Shield Disabled: All queries allowed".to_string()
    };

    let now_str = Command::new("date")
        .args(["+%Y-%m-%d %H:%M"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Now".to_string());

    let summary = TestSummary {
        success: all_passed,
        message: summary_msg,
        avg_latency_ms: avg_latency,
        blocked_tested: blocked_count,
        allowed_tested: allowed_count,
        timestamp: now_str,
        details,
    };

    cfg.last_test = Some(summary.clone());
    save_config(cfg);
    summary
}

fn update_blocklists_online(cfg: &mut OmaBlockConfig, rules: &mut ParsedRules) -> bool {
    let cached_path = get_cached_rules_path();
    let temp_download = get_state_dir().join("download_hosts.tmp");

    let urls = vec![
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://v.firebog.net/hosts/Easyprivacy.txt",
    ];

    let mut new_domains = HashMap::new();

    for url in urls {
        let status = Command::new("curl")
            .args(["-sSL", "--max-time", "15", url, "-o", temp_download.to_str().unwrap()])
            .status();

        if let Ok(st) = status {
            if st.success() {
                if let Ok(f) = File::open(&temp_download) {
                    let reader = BufReader::new(f);
                    for line in reader.lines().map_while(Result::ok) {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        let (domain, cat) = if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                            (parts[1].to_lowercase(), "ads")
                        } else if parts.len() == 1 {
                            (parts[0].to_lowercase(), "telemetry")
                        } else {
                            continue;
                        };

                        if domain != "0.0.0.0" && domain != "localhost" && !domain.is_empty() {
                            new_domains.insert(domain, cat.to_string());
                        }
                    }
                }
            }
        }
        let _ = fs::remove_file(&temp_download);
    }

    if new_domains.len() > 1000 {
        if let Ok(mut out) = File::create(&cached_path) {
            for (d, c) in &new_domains {
                let _ = writeln!(out, "{} {}", c, d);
            }
        }

        let now_str = Command::new("date")
            .args(["+%Y-%m-%d %H:%M"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Recently".to_string());

        cfg.last_updated = Some(now_str);
        save_config(cfg);

        *rules = load_all_rules();
        if cfg.enabled {
            sync_system_hosts(cfg, rules);
        }
        send_notification(
            "OmaBlock Updated",
            &format!("Loaded {} domains from upstream blocklists", new_domains.len()),
        );
        true
    } else {
        send_notification("OmaBlock Update", "Failed to reach blocklist servers");
        false
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = load_config();
    let mut rules = load_all_rules();

    if args.len() < 2 || args[1] == "--status" || args[1] == "--json" {
        let system_active = is_system_hosts_active();
        let active_count = if cfg.enabled && system_active {
            rules.all_rules.len()
        } else {
            0
        };

        let output = StatusOutput {
            enabled: cfg.enabled,
            active_rules: active_count,
            total_rules: rules.all_rules.len(),
            categories: cfg.categories.clone(),
            category_counts: rules.category_counts.clone(),
            whitelist: cfg.whitelist.clone(),
            blacklist: cfg.blacklist.clone(),
            last_updated: cfg.last_updated.unwrap_or_else(|| "Curated v1.0".to_string()),
            last_test: cfg.last_test.clone(),
            system_hosts_active: system_active,
        };

        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }

    match args[1].as_str() {
        "--enable" => {
            cfg.enabled = true;
            save_config(&cfg);
            let count = sync_system_hosts(&cfg, &rules);
            send_notification(
                "OmaBlock Shield: ACTIVE",
                &format!("Kernel sinkhole active with {} rules", count),
            );
            println!("OmaBlock enabled: {} rules active.", count);
        }
        "--disable" => {
            cfg.enabled = false;
            save_config(&cfg);
            sync_system_hosts(&cfg, &rules);
            send_notification(
                "OmaBlock Shield: DISABLED",
                "System DNS restored without filtering",
            );
            println!("OmaBlock disabled.");
        }
        "--toggle" => {
            cfg.enabled = !cfg.enabled;
            save_config(&cfg);
            let count = sync_system_hosts(&cfg, &rules);
            if cfg.enabled {
                send_notification(
                    "OmaBlock Shield: ACTIVE",
                    &format!("Protection active ({} rules)", count),
                );
            } else {
                send_notification("OmaBlock Shield: DISABLED", "AdBlocker disabled");
            }
            println!("Toggled OmaBlock to: {}", cfg.enabled);
        }
        "--toggle-category" => {
            if args.len() > 2 {
                let cat = args[2].to_lowercase();
                match cat.as_str() {
                    "ads" => cfg.categories.ads = !cfg.categories.ads,
                    "telemetry" => cfg.categories.telemetry = !cfg.categories.telemetry,
                    "malware" => cfg.categories.malware = !cfg.categories.malware,
                    "social" => cfg.categories.social = !cfg.categories.social,
                    _ => eprintln!("Unknown category: {}", cat),
                }
                save_config(&cfg);
                if cfg.enabled {
                    sync_system_hosts(&cfg, &rules);
                }
                println!("Category '{}' toggled.", cat);
            }
        }
        "--whitelist-add" => {
            if args.len() > 2 {
                let domain = args[2].to_lowercase().trim().to_string();
                if !cfg.whitelist.contains(&domain) {
                    cfg.whitelist.push(domain.clone());
                    save_config(&cfg);
                    if cfg.enabled {
                        sync_system_hosts(&cfg, &rules);
                    }
                    println!("Domain '{}' added to whitelist.", domain);
                }
            }
        }
        "--whitelist-remove" => {
            if args.len() > 2 {
                let domain = args[2].to_lowercase().trim().to_string();
                cfg.whitelist.retain(|d| d != &domain);
                save_config(&cfg);
                if cfg.enabled {
                    sync_system_hosts(&cfg, &rules);
                }
                println!("Domain '{}' removed from whitelist.", domain);
            }
        }
        "--blacklist-add" => {
            if args.len() > 2 {
                let domain = args[2].to_lowercase().trim().to_string();
                if !cfg.blacklist.contains(&domain) {
                    cfg.blacklist.push(domain.clone());
                    save_config(&cfg);
                    if cfg.enabled {
                        sync_system_hosts(&cfg, &rules);
                    }
                    println!("Domain '{}' added to custom blacklist.", domain);
                }
            }
        }
        "--blacklist-remove" => {
            if args.len() > 2 {
                let domain = args[2].to_lowercase().trim().to_string();
                cfg.blacklist.retain(|d| d != &domain);
                save_config(&cfg);
                if cfg.enabled {
                    sync_system_hosts(&cfg, &rules);
                }
                println!("Domain '{}' removed from custom blacklist.", domain);
            }
        }
        "--test" => {
            let res = run_verification_test(&mut cfg, &rules);
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        }
        "--update" => {
            let ok = update_blocklists_online(&mut cfg, &mut rules);
            println!("Update finished. Success: {}", ok);
        }
        "--flush" => {
            let _ = Command::new("sudo").args(["resolvectl", "flush-caches"]).output();
            println!("Flushed system DNS caches.");
        }
        "--sync" => {
            let count = sync_system_hosts(&cfg, &rules);
            println!("Synced {} rules to /etc/hosts.", count);
        }
        _ => {
            eprintln!("Usage: omablock-engine [--status|--enable|--disable|--toggle|--toggle-category <cat>|--whitelist-add <d>|--whitelist-remove <d>|--blacklist-add <d>|--blacklist-remove <d>|--test|--update|--flush]");
        }
    }
}
