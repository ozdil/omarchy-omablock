mod secure_fs;
mod subproc;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BUILTIN_RULES: &str = include_str!("../assets/rules_builtin.txt");

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockingLevel {
    Standard,
    #[default]
    Aggressive,
    Ultimate,
}

impl std::str::FromStr for BlockingLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "standard" | "std" | "standart" => Ok(Self::Standard),
            "aggressive" | "gelismis" | "advanced" => Ok(Self::Aggressive),
            "ultimate" | "maksimum" | "max" | "popup" | "anti-popup" | "no-popup" => Ok(Self::Ultimate),
            _ => Err(()),
        }
    }
}

impl BlockingLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Aggressive => "aggressive",
            Self::Ultimate => "ultimate",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        <Self as std::str::FromStr>::from_str(s).ok()
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Aggressive => "Aggressive",
            Self::Ultimate => "Ultimate (Anti-Popup)",
        }
    }
}

const BUILTIN_POPUP_RULES: &[&str] = &[
    "popads.net",
    "popcash.net",
    "propellerads.com",
    "adcash.com",
    "clickadu.com",
    "hilltopads.net",
    "adsterra.com",
    "exoclick.com",
    "trafficjunky.com",
    "juicyads.com",
    "tsyndicate.com",
    "twinred.com",
    "realsrv.com",
    "wigetmedia.com",
    "adtrue.com",
    "adtng.com",
    "directrev.com",
    "popunder.net",
    "ero-advertising.com",
    "adxpansion.com",
    "adxprts.com",
    "plugrush.com",
    "trafficstars.com",
    "bidvertiser.com",
    "yllix.com",
    "coinzilla.com",
    "a-ads.com",
    "clicksor.com",
    "infolinks.com",
    "chitika.com",
    "clickaine.com",
    "ad-maven.com",
    "pushwoosh.com",
    "onesignal.com",
    "pushalert.co",
    "notix.co",
    "izooto.com",
    "webpushs.com",
    "truepush.com",
    "pushassist.com",
    "richpush.com",
    "evadav.com",
    "rollerads.com",
    "mondiad.com",
    "clickadilla.com",
    "daopush.com",
    "pushground.com",
    "clickunder.ru",
    "popunder.ru",
    "trafficfactory.biz",
    "adrun.com",
    "hubtraffic.com",
    "tubecorporate.com",
    "exosrv.com",
    "exdynsrv.com",
    "rtmark.net",
    "serving-sys.com",
    "zedo.com",
    "adnxs.com",
    "adpushup.com",
    "adrecovery.com",
    "adblade.com",
    "content.ad",
    "revcontent.com",
    "taboola.com",
    "outbrain.com",
    "mgid.com",
    "adkeeper.com",
    "marketgid.com",
    "kadam.net",
    "teasernet.com",
    "bodyclick.net",
    "novadnet.com",
    "adkernel.com",
    "smartadserver.com",
    "openx.net",
    "rubiconproject.com",
    "pubmatic.com",
    "casalemedia.com",
    "exponential.com",
    "conversantmedia.com",
    "sovrn.com",
    "yieldmo.com",
    "sharethrough.com",
    "triplelift.com",
    "gumgum.com",
    "inmobi.com",
    "smaato.net",
    "flurry.com",
    "chartboost.com",
    "vungle.com",
    "applovin.com",
    "ironsrc.com",
    "fyber.com",
    "adcolony.com",
    "tapjoy.com",
    "hyprmx.com",
    "mintegral.com",
    "pangle.io",
    "leadbolt.com",
    "startapp.com",
    "mobvista.com",
    "adfalcon.com",
    "smartfocus.com",
    "siftscience.com",
    "hotjar.com",
    "crazyegg.com",
    "mouseflow.com",
    "fullstory.com",
    "luckyorange.com",
    "inspectlet.com",
    "sessioncam.com",
    "clicktale.net",
    "clarity.ms",
    "pushwelcome.com",
    "pushmaster.info",
    "propush.me",
    "pushmonetization.com",
    "adoperator.com",
    "targeleon.com",
    "clickunder.org",
    "popmyads.com",
    "popvertising.com",
    "propeller-tracking.com",
    "onclickbright.com",
    "onclickperformance.com",
    "onclickalgo.com",
    "onclickpredictiv.com",
    "onclickmega.com",
    "onclicksuper.com",
    "adsterra.net",
    "adsterratools.com",
    "atdmt.com",
    "adform.net",
    "admob.com",
    "adition.com",
    "advertising.com",
    "yandexadexchange.net",
    "an.yandex.ru",
    "offerforge.com",
    "tradedoubler.com",
    "zanox.com",
    "cj.com",
    "linkshare.com",
    "shareasale.com",
    "adtarget.me",
    "adgear.com",
    "adtech.de",
    "yieldlove.com",
    "adscale.de",
    "yieldmanager.com",
    "adtechus.com",
    "admeta.com",
    "adshuffle.com",
    "contextweb.com",
    "dotomi.com",
    "specificclick.net",
    "interclick.com",
    "mediaplex.com",
    "valueclick.com",
    "fastclick.net",
    "burstnet.com",
    "tribalfusion.com",
    "chitika.net",
    "bidvertiser.net",
    "adknowledge.com",
    "revenuehits.com",
    "infolinks.net",
    "buysellads.com",
    "directleads.com",
    "linkbucks.com",
    "adf.ly",
    "shorte.st",
    "ouo.io",
    "linkvertise.com",
    "bc.vc",
    "tinyium.com",
    "q.gs",
    "j.gs",
    "yenimedya.com.tr",
    "www.yenimedya.com.tr",
    "adsby.io",
    "cdn.adsby.io",
    "membrana.media",
    "cdn.membrana.media",
    "idealmedia.io",
    "jsc.idealmedia.io",
    "gemius.pl",
    "hit.gemius.pl",
    "virgul.com",
    "ad.virgul.com",
    "medyanet.net",
    "ad.medyanet.net",
];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CategoriesConfig {
    pub ads: bool,
    pub telemetry: bool,
    pub malware: bool,
    pub social: bool,
    #[serde(default = "default_true")]
    pub popups: bool,
}

impl Default for CategoriesConfig {
    fn default() -> Self {
        Self {
            ads: true,
            telemetry: true,
            malware: true,
            social: false,
            popups: true,
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
    #[serde(default)]
    pub blocking_level: BlockingLevel,
    pub categories: CategoriesConfig,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub last_updated: Option<String>,
    pub last_test: Option<TestSummary>,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default)]
    pub paused_until: Option<u64>,
    #[serde(default = "default_true")]
    pub doh_prevention: bool,
}

impl Default for OmaBlockConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocking_level: BlockingLevel::Aggressive,
            categories: CategoriesConfig::default(),
            whitelist: Vec::new(),
            blacklist: Vec::new(),
            last_updated: Some("Built-in Curated v1.0".to_string()),
            last_test: None,
            auto_update: false,
            paused_until: None,
            doh_prevention: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatusOutput {
    pub enabled: bool,
    pub blocking_level: String,
    pub active_rules: usize,
    pub total_rules: usize,
    pub categories: CategoriesConfig,
    pub category_counts: HashMap<String, usize>,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub last_updated: String,
    pub last_test: Option<TestSummary>,
    pub system_hosts_active: bool,
    pub auto_update: bool,
    pub paused_until: Option<u64>,
    pub pause_remaining_secs: Option<u64>,
    pub doh_prevention: bool,
}

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

/// Generates a local timestamp string in pure Rust using POSIX localtime_r
pub fn get_current_timestamp() -> String {
    #[cfg(unix)]
    {
        // SAFETY: time() and localtime_r() are standard POSIX libc calls.
        unsafe {
            let mut t: libc::time_t = 0;
            libc::time(&mut t);
            let mut tm: libc::tm = std::mem::zeroed();
            if !libc::localtime_r(&t, &mut tm).is_null() {
                return format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}",
                    tm.tm_year + 1900,
                    tm.tm_mon + 1,
                    tm.tm_mday,
                    tm.tm_hour,
                    tm.tm_min
                );
            }
        }
    }
    "Recently".to_string()
}

pub fn get_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn check_pause_expiry(cfg: &mut OmaBlockConfig, rules: &ParsedRules) -> bool {
    if let Some(until) = cfg.paused_until {
        let now = get_now_unix();
        if now >= until {
            cfg.paused_until = None;
            cfg.enabled = true;
            save_config(cfg);
            let count = sync_system_hosts(cfg, rules);
            send_notification(
                "OmaBlock Shield: REACTIVATED",
                &format!("Pause period ended. {} rules restored.", count),
            );
            return true;
        }
    }
    false
}

fn get_state_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ozdil".to_string());
    let dir = PathBuf::from(home).join(".local/state/omarchy/omablock");
    let _ = secure_fs::ensure_state_dir(&dir);
    dir
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
        if let Ok(data) = secure_fs::read_secure_file(&path) {
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
    let path = get_config_path();
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        if let Err(e) = secure_fs::atomic_write_secure(&path, json.as_bytes()) {
            eprintln!("Warning: Failed to save config securely: {}", e);
        }
    }
}

fn send_notification(summary: &str, body: &str) {
    let env_keys = [
        "DBUS_SESSION_BUS_ADDRESS",
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "XDG_RUNTIME_DIR",
    ];
    let mut extra_envs = Vec::new();
    let values: Vec<Option<String>> = env_keys.iter().map(|k| std::env::var(k).ok()).collect();
    for (i, v_opt) in values.iter().enumerate() {
        if let Some(v) = v_opt {
            extra_envs.push((env_keys[i], v.as_str()));
        }
    }

    let deadline = Instant::now() + Duration::from_millis(1500);
    let _ = subproc::run_cmd_bounded(
        "notify-send",
        &["-a", "OmaBlock", summary, body],
        &extra_envs,
        deadline,
        4096,
    );
}

fn flush_dns_cache() {
    let deadline = Instant::now() + Duration::from_secs(3);
    let res = subproc::run_cmd_bounded(
        "resolvectl",
        &["flush-caches"],
        &[],
        deadline,
        4096,
    );
    if res.is_none() {
        let deadline2 = Instant::now() + Duration::from_secs(3);
        let _ = subproc::run_cmd_bounded(
            "sudo",
            &["-n", "resolvectl", "flush-caches"],
            &[],
            deadline2,
            4096,
        );
    }
}

pub struct ParsedRules {
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
    let mut category_counts: HashMap<String, usize> = HashMap::new();
    category_counts.insert("ads".to_string(), 0);
    category_counts.insert("telemetry".to_string(), 0);
    category_counts.insert("malware".to_string(), 0);
    category_counts.insert("social".to_string(), 0);
    category_counts.insert("popups".to_string(), 0);

    // 1. Always load curated builtin rules FIRST (ensures telemetry and ad sinks exist)
    parse_rules_content(BUILTIN_RULES, &mut all_rules);

    // 2. Load dedicated built-in popup and redirect shield rules
    for domain in BUILTIN_POPUP_RULES {
        if let Ok(valid) = validate_domain(domain) {
            all_rules.insert(valid, "popups".to_string());
        }
    }

    // 3. Overlay cached upstream rules if available (bounded to 32 MiB)
    let cached_path = get_cached_rules_path();
    if cached_path.exists() {
        if let Ok(content) = secure_fs::read_secure_file_bounded(&cached_path, 32 * 1024 * 1024) {
            parse_rules_content(&content, &mut all_rules);
        }
    }

    for cat in all_rules.values() {
        if let Some(c) = category_counts.get_mut(cat) {
            *c = (*c).saturating_add(1);
        }
    }

    ParsedRules {
        all_rules,
        category_counts,
    }
}

fn is_system_hosts_active() -> bool {
    let hosts_path = "/etc/hosts";
    if let Ok(file) = File::open(hosts_path) {
        let reader = BufReader::new(file);
        return is_system_hosts_active_from_reader(reader);
    }
    false
}

pub fn is_system_hosts_active_from_reader<R: BufRead>(reader: R) -> bool {
    for line in reader.lines().map_while(Result::ok) {
        if line.contains("# --- BEGIN OMABLOCK MANAGED RULES ---") {
            return true;
        }
    }
    false
}

fn sync_system_hosts(cfg: &OmaBlockConfig, rules: &ParsedRules) -> usize {
    if !cfg.enabled {
        let deadline = Instant::now() + Duration::from_secs(5);
        let _ = subproc::run_cmd_bounded(
            "sudo",
            &["-n", "/usr/local/bin/omablock-hosts-sync", "--clear"],
            &[],
            deadline,
            16384,
        );
        return 0;
    }

    let whitelist_set: HashSet<String> = cfg.whitelist.iter().map(|d| d.to_lowercase()).collect();
    // Optimization: precompute suffix patterns once to avoid format! per rule iteration
    let wl_suffixes: Vec<String> = whitelist_set.iter().map(|w| format!(".{}", w)).collect();
    let mut active_domains: HashSet<String> = HashSet::new();

    for (domain, cat) in &rules.all_rules {
        let is_cat_enabled = match cfg.blocking_level {
            BlockingLevel::Standard => match cat.as_str() {
                "ads" => cfg.categories.ads,
                "malware" => cfg.categories.malware,
                _ => false,
            },
            BlockingLevel::Aggressive => match cat.as_str() {
                "ads" => cfg.categories.ads,
                "telemetry" => cfg.categories.telemetry,
                "malware" => cfg.categories.malware,
                "social" => cfg.categories.social,
                "popups" => cfg.categories.popups,
                _ => true,
            },
            BlockingLevel::Ultimate => {
                // In Ultimate level, all categories and aggressive pop-ups are strictly enforced
                true
            }
        };

        if is_cat_enabled {
            let mut whitelisted = whitelist_set.contains(domain);
            if !whitelisted {
                for suffix in &wl_suffixes {
                    if domain.ends_with(suffix) {
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

    // DoH Bypass Prevention: Block encrypted DNS endpoints and canary domains to ensure browsers honor system sinkhole rules
    if cfg.doh_prevention || cfg.blocking_level == BlockingLevel::Ultimate {
        let doh_domains = [
            "use-application-dns.net", // Firefox Canary
            "dns.google",
            "dns.google.com",
            "cloudflare-dns.com",
            "chrome.cloudflare-dns.com",
            "mozilla.cloudflare-dns.com",
            "1dot1dot1dot1.cloudflare-dns.com",
            "dns.quad9.net",
            "doh.opendns.com",
            "dns.adguard-dns.com",
            "doh.cleanbrowsing.org",
            "dns.nextdns.io",
            "doh.applied-privacy.net",
            "dnsforge.de",
            "doh.mullvad.net",
            "doh.controld.com",
            "dns.alidns.com",
            "doh.pub",
            "dns.sb",
        ];
        for d in &doh_domains {
            active_domains.insert(d.to_string());
        }
    }

    let active_path = get_active_hosts_path();
    let mut buf = Vec::with_capacity(active_domains.len().saturating_mul(32));
    for d in &active_domains {
        let _ = writeln!(buf, "0.0.0.0 {}", d);
    }

    if let Err(e) = secure_fs::atomic_write_secure(&active_path, &buf) {
        eprintln!("Warning: Failed to write active hosts securely: {}", e);
        return 0;
    }

    let path_str = match active_path.to_str() {
        Some(s) => s,
        None => return 0,
    };

    let deadline = Instant::now() + Duration::from_secs(8);
    let res = subproc::run_cmd_bounded(
        "sudo",
        &["-n", "/usr/local/bin/omablock-hosts-sync", "--apply", path_str],
        &[],
        deadline,
        32768,
    );

    if res.is_some() {
        active_domains.len()
    } else {
        eprintln!("Warning: omablock-hosts-sync --apply failed or timed out");
        0
    }
}

fn run_verification_test(cfg: &mut OmaBlockConfig, rules: &ParsedRules) -> TestSummary {
    if cfg.enabled {
        let _ = sync_system_hosts(cfg, rules);
        flush_dns_cache();
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
    let mut blocked_count: usize = 0;
    let mut allowed_count: usize = 0;

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
            blocked_count = blocked_count.saturating_add(1);
        } else {
            allowed_count = allowed_count.saturating_add(1);
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

    let now_str = get_current_timestamp();

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

    let urls: Vec<(&str, &str)> = vec![
        ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt", "popups"),
        ("https://v.firebog.net/hosts/Admiral.txt", "popups"),
        ("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts", "popups"),
        ("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts", "malware"),
        ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt", "ads"),
        ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "ads"),
        ("https://v.firebog.net/hosts/Easyprivacy.txt", "telemetry"),
        ("https://v.firebog.net/hosts/AdguardDNS.txt", "ads"),
    ];

    let mut new_domains = HashMap::new();

    for (url, default_cat) in urls {
        // Ensure no pre-existing file or symlink exists before curl writes to it
        let _ = fs::remove_file(&temp_download);

        let temp_str = match temp_download.to_str() {
            Some(s) => s,
            None => continue,
        };

        let deadline = Instant::now() + Duration::from_secs(20);
        let status = subproc::run_cmd_bounded(
            "curl",
            &["-sSL", "--max-time", "18", url, "-o", temp_str],
            &[],
            deadline,
            4096,
        );

        if status.is_some() {
            if let Ok(f) = File::open(&temp_download) {
                let reader = BufReader::new(f);
                for line in reader.lines().map_while(Result::ok) {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with('/') {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let (domain, cat) = if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                        (parts[1].to_lowercase(), default_cat)
                    } else if parts.len() == 1 {
                        (parts[0].to_lowercase(), default_cat)
                    } else {
                        continue;
                    };

                    if domain != "0.0.0.0" && domain != "localhost" && !domain.is_empty() {
                        if let Ok(valid_d) = validate_domain(&domain) {
                            new_domains.insert(valid_d, cat.to_string());
                        }
                    }
                }
            }
        }
        let _ = fs::remove_file(&temp_download);
    }

    if new_domains.len() > 1000 {
        let mut out_buf = Vec::with_capacity(new_domains.len().saturating_mul(32));
        for (d, c) in &new_domains {
            let _ = writeln!(out_buf, "{} {}", c, d);
        }

        if let Err(e) = secure_fs::atomic_write_secure(&cached_path, &out_buf) {
            eprintln!("Warning: Failed to write cached rules: {}", e);
        }

        let now_str = get_current_timestamp();
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
    let _ = check_pause_expiry(&mut cfg, &rules);

    if args.len() < 2 || args[1] == "--status" || args[1] == "--json" {
        let system_active = is_system_hosts_active();
        let active_count = if cfg.enabled && system_active {
            rules.all_rules.len()
        } else {
            0
        };

        let now = get_now_unix();
        let pause_remaining = cfg.paused_until.and_then(|u| {
            if u > now {
                Some(u - now)
            } else {
                None
            }
        });

        let output = StatusOutput {
            enabled: cfg.enabled,
            blocking_level: cfg.blocking_level.as_str().to_string(),
            active_rules: active_count,
            total_rules: rules.all_rules.len(),
            categories: cfg.categories.clone(),
            category_counts: rules.category_counts.clone(),
            whitelist: cfg.whitelist.clone(),
            blacklist: cfg.blacklist.clone(),
            last_updated: cfg.last_updated.unwrap_or_else(|| "Curated v1.0".to_string()),
            last_test: cfg.last_test.clone(),
            system_hosts_active: system_active,
            auto_update: cfg.auto_update,
            paused_until: cfg.paused_until,
            pause_remaining_secs: pause_remaining,
            doh_prevention: cfg.doh_prevention,
        };

        if let Ok(json) = serde_json::to_string_pretty(&output) {
            println!("{}", json);
        }
        return;
    }

    match args[1].as_str() {
        "--enable" => {
            cfg.enabled = true;
            cfg.paused_until = None;
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
            cfg.paused_until = None;
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
            cfg.paused_until = None;
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
                    "popups" | "popup" => cfg.categories.popups = !cfg.categories.popups,
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
                match validate_domain(&args[2]) {
                    Ok(domain) => {
                        if !cfg.whitelist.contains(&domain) {
                            cfg.whitelist.push(domain.clone());
                            save_config(&cfg);
                            if cfg.enabled {
                                sync_system_hosts(&cfg, &rules);
                            }
                            println!("Domain '{}' added to whitelist.", domain);
                        } else {
                            println!("Domain '{}' already in whitelist.", domain);
                        }
                    }
                    Err(e) => {
                        eprintln!("Invalid domain: {}", e);
                    }
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
                match validate_domain(&args[2]) {
                    Ok(domain) => {
                        if !cfg.blacklist.contains(&domain) {
                            cfg.blacklist.push(domain.clone());
                            save_config(&cfg);
                            if cfg.enabled {
                                sync_system_hosts(&cfg, &rules);
                            }
                            println!("Domain '{}' added to custom blacklist.", domain);
                        } else {
                            println!("Domain '{}' already in custom blacklist.", domain);
                        }
                    }
                    Err(e) => {
                        eprintln!("Invalid domain: {}", e);
                    }
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
            if let Ok(json) = serde_json::to_string_pretty(&res) {
                println!("{}", json);
            }
        }
        "--update" => {
            let ok = update_blocklists_online(&mut cfg, &mut rules);
            println!("Update finished. Success: {}", ok);
        }
        "--flush" => {
            flush_dns_cache();
            println!("Flushed system DNS caches.");
        }
        "--sync" => {
            let count = sync_system_hosts(&cfg, &rules);
            println!("Synced {} rules to /etc/hosts.", count);
        }
        "--toggle-auto-update" => {
            cfg.auto_update = !cfg.auto_update;
            save_config(&cfg);
            println!("Auto-update on startup set to: {}", cfg.auto_update);
        }
        "--set-auto-update" => {
            if args.len() > 2 {
                let val = match args[2].to_lowercase().as_str() {
                    "true" | "1" | "on" => true,
                    "false" | "0" | "off" => false,
                    _ => {
                        eprintln!("Invalid boolean value: {}", args[2]);
                        return;
                    }
                };
                cfg.auto_update = val;
                save_config(&cfg);
                println!("Auto-update on startup set to: {}", cfg.auto_update);
            }
        }
        "--startup" => {
            if cfg.auto_update {
                println!("Auto-update on startup is active. Fetching latest rules...");
                let ok = update_blocklists_online(&mut cfg, &mut rules);
                println!("Startup update finished. Success: {}", ok);
            } else {
                println!("Auto-update on startup is disabled. Skipping.");
            }
        }
        "--pause" => {
            let mins: u64 = if args.len() > 2 {
                args[2].parse().unwrap_or(5)
            } else {
                5
            };
            let now = get_now_unix();
            cfg.paused_until = Some(now.saturating_add(mins.saturating_mul(60)));
            cfg.enabled = false;
            save_config(&cfg);
            sync_system_hosts(&cfg, &rules);
            send_notification(
                "OmaBlock Shield: PAUSED",
                &format!("AdBlocker paused for {} minutes", mins),
            );
            println!("OmaBlock paused for {} minutes.", mins);
        }
        "--resume" => {
            cfg.paused_until = None;
            cfg.enabled = true;
            save_config(&cfg);
            let count = sync_system_hosts(&cfg, &rules);
            send_notification(
                "OmaBlock Shield: ACTIVE",
                &format!("Protection resumed ({} rules active)", count),
            );
            println!("OmaBlock protection resumed.");
        }
        "--toggle-doh-guard" => {
            cfg.doh_prevention = !cfg.doh_prevention;
            save_config(&cfg);
            if cfg.enabled {
                sync_system_hosts(&cfg, &rules);
            }
            println!("Browser DoH bypass prevention set to: {}", cfg.doh_prevention);
        }
        "--set-level" => {
            if args.len() > 2 {
                if let Some(level) = BlockingLevel::from_str(&args[2]) {
                    cfg.blocking_level = level;
                    match level {
                        BlockingLevel::Standard => {
                            cfg.categories.ads = true;
                            cfg.categories.malware = true;
                            cfg.categories.telemetry = false;
                            cfg.categories.social = false;
                            cfg.categories.popups = false;
                        }
                        BlockingLevel::Aggressive => {
                            cfg.categories.ads = true;
                            cfg.categories.malware = true;
                            cfg.categories.telemetry = true;
                            cfg.categories.social = false;
                            cfg.categories.popups = true;
                        }
                        BlockingLevel::Ultimate => {
                            cfg.categories.ads = true;
                            cfg.categories.malware = true;
                            cfg.categories.telemetry = true;
                            cfg.categories.social = true;
                            cfg.categories.popups = true;
                            cfg.doh_prevention = true;
                        }
                    }
                    save_config(&cfg);
                    let count = if cfg.enabled {
                        sync_system_hosts(&cfg, &rules)
                    } else {
                        0
                    };
                    send_notification(
                        "OmaBlock Shield Level Updated",
                        &format!("Shield level set to {} ({} rules active)", level.display_name(), count),
                    );
                    println!("Blocking level set to: {} ({} active rules)", level.as_str(), count);
                } else {
                    eprintln!("Invalid level: '{}'. Choose from: standard, aggressive, ultimate", args[2]);
                }
            } else {
                eprintln!("Usage: omablock-engine --set-level <standard|aggressive|ultimate>");
            }
        }
        "--level" => {
            println!("{}", cfg.blocking_level.as_str());
        }
        _ => {
            eprintln!("Usage: omablock-engine [--status|--enable|--disable|--toggle|--set-level <standard|aggressive|ultimate>|--level|--toggle-category <cat>|--whitelist-add <d>|--whitelist-remove <d>|--blacklist-add <d>|--blacklist-remove <d>|--toggle-auto-update|--set-auto-update <bool>|--pause <mins>|--resume|--toggle-doh-guard|--startup|--test|--update|--flush]");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_validation_valid() {
        assert!(validate_domain("doubleclick.net").is_ok());
        assert!(validate_domain("pagead2.googlesyndication.com").is_ok());
        assert!(validate_domain("sub.domain.example.co.uk").is_ok());
        assert!(validate_domain("my-domain-123.org.").is_ok());
        assert_eq!(validate_domain("EXAMPLE.COM.").unwrap(), "example.com");
    }

    #[test]
    fn test_domain_validation_injection_attacks() {
        // Space injection
        assert!(validate_domain("bad.com 0.0.0.0 evil.com").is_err());
        // Newline injection
        assert!(validate_domain("bad.com\n1.2.3.4 evil.com").is_err());
        // Carriage return
        assert!(validate_domain("bad.com\r\nevil.com").is_err());
        // Shell characters
        assert!(validate_domain("bad.com; rm -rf /").is_err());
        assert!(validate_domain("`id`.evil.com").is_err());
        assert!(validate_domain("$evil.com").is_err());
        // Path traversal / slashes
        assert!(validate_domain("../../etc/shadow").is_err());
        // Null byte
        assert!(validate_domain("test\0.com").is_err());
    }

    #[test]
    fn test_domain_validation_syntax_boundaries() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("   ").is_err());
        assert!(validate_domain(".leadingdot.com").is_err());
        assert!(validate_domain("empty..label.com").is_err());
        assert!(validate_domain("-leadinghyphen.com").is_err());
        assert!(validate_domain("trailinghyphen-.com").is_err());

        let long_label = "a".repeat(64) + ".com";
        assert!(validate_domain(&long_label).is_err());

        let long_domain = "a".repeat(250) + ".com";
        assert!(validate_domain(&long_domain).is_err());

        // Single label domains without dot
        assert!(validate_domain("localhost").is_err());
        assert!(validate_domain("router").is_err());

        // Reserved local / mDNS TLDs
        assert!(validate_domain("nas.local").is_err());
        assert!(validate_domain("gateway.lan").is_err());
        assert!(validate_domain("device.internal").is_err());
        assert!(validate_domain("1.0.0.127.in-addr.arpa").is_err());

        // Reserved system hostnames
        assert!(validate_domain("broadcasthost").is_err());
        assert!(validate_domain("0.0.0.0").is_err());
        assert!(validate_domain("255.255.255.255").is_err());
    }

    #[test]
    fn test_timestamp_pure_rust() {
        let ts = get_current_timestamp();
        assert!(!ts.is_empty());
        assert!(ts.contains('-'));
        assert!(ts.contains(':'));
    }

    #[test]
    fn test_subdomain_whitelist_suffix_matching() {
        let wl = ["google.com".to_string(), "archlinux.org".to_string()];
        let wl_suffixes: Vec<String> = wl.iter().map(|w| format!(".{}", w)).collect();

        let d1 = "mail.google.com";
        let d2 = "evilgoogle.com";
        let d3 = "sub.archlinux.org";

        let matches = |domain: &str| {
            wl.contains(&domain.to_string()) || wl_suffixes.iter().any(|s| domain.ends_with(s))
        };

        assert!(matches(d1));
        assert!(!matches(d2));
        assert!(matches(d3));
    }

    #[test]
    fn test_auto_update_config() {
        let mut cfg = OmaBlockConfig::default();
        assert!(!cfg.auto_update);
        cfg.auto_update = true;
        let json = serde_json::to_string(&cfg).unwrap();
        let loaded: OmaBlockConfig = serde_json::from_str(&json).unwrap();
        assert!(loaded.auto_update);
    }

    #[test]
    fn test_pause_expiry_logic() {
        let mut cfg = OmaBlockConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.paused_until.is_none());

        // Set pause in the future
        let now = get_now_unix();
        cfg.paused_until = Some(now + 300);
        cfg.enabled = false;

        let parsed = ParsedRules {
            all_rules: HashMap::new(),
            category_counts: HashMap::new(),
        };

        // Not yet expired
        assert!(!check_pause_expiry(&mut cfg, &parsed));
        assert!(!cfg.enabled);
        assert!(cfg.paused_until.is_some());

        // Simulate expired
        cfg.paused_until = Some(now.saturating_sub(10));
        assert!(check_pause_expiry(&mut cfg, &parsed));
        assert!(cfg.enabled);
        assert!(cfg.paused_until.is_none());
    }

    #[test]
    fn test_doh_prevention_config() {
        let mut cfg = OmaBlockConfig::default();
        assert!(!cfg.doh_prevention);
        cfg.doh_prevention = true;
        let json = serde_json::to_string(&cfg).unwrap();
        let loaded: OmaBlockConfig = serde_json::from_str(&json).unwrap();
        assert!(loaded.doh_prevention);
    }

    #[test]
    fn test_is_system_hosts_active_reader() {
        let inactive = "127.0.0.1 localhost\n::1 localhost\n";
        assert!(!is_system_hosts_active_from_reader(inactive.as_bytes()));

        let active = "127.0.0.1 localhost\n# --- BEGIN OMABLOCK MANAGED RULES ---\n0.0.0.0 ad.com\n# --- END OMABLOCK MANAGED RULES ---\n";
        assert!(is_system_hosts_active_from_reader(active.as_bytes()));
    }

    #[test]
    fn test_blocking_level_parsing_and_defaults() {
        assert_eq!(BlockingLevel::default(), BlockingLevel::Aggressive);
        assert_eq!(BlockingLevel::from_str("standard"), Some(BlockingLevel::Standard));
        assert_eq!(BlockingLevel::from_str("standart"), Some(BlockingLevel::Standard));
        assert_eq!(BlockingLevel::from_str("aggressive"), Some(BlockingLevel::Aggressive));
        assert_eq!(BlockingLevel::from_str("gelismis"), Some(BlockingLevel::Aggressive));
        assert_eq!(BlockingLevel::from_str("ultimate"), Some(BlockingLevel::Ultimate));
        assert_eq!(BlockingLevel::from_str("maksimum"), Some(BlockingLevel::Ultimate));
        assert_eq!(BlockingLevel::from_str("anti-popup"), Some(BlockingLevel::Ultimate));
        assert_eq!(BlockingLevel::from_str("popup"), Some(BlockingLevel::Ultimate));
        assert_eq!(BlockingLevel::from_str("invalid_xyz"), None);

        let cfg = OmaBlockConfig::default();
        assert_eq!(cfg.blocking_level, BlockingLevel::Aggressive);
        assert!(cfg.categories.popups);

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"blocking_level\":\"aggressive\""));
        let loaded: OmaBlockConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.blocking_level, BlockingLevel::Aggressive);
    }

    #[test]
    fn test_builtin_popup_rules_validation() {
        assert!(!BUILTIN_POPUP_RULES.is_empty());
        for domain in BUILTIN_POPUP_RULES {
            assert!(
                validate_domain(domain).is_ok(),
                "Built-in popup domain failed validation: {}",
                domain
            );
        }
    }
}
