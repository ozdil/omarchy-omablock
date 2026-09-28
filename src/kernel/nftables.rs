use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KernelFilterStatus {
    pub is_supported: bool,
    pub is_active: bool,
    pub table_name: String,
    pub blocked_ports: Vec<u16>,
    pub active_rule_count: usize,
    pub summary: String,
}

/// Linux Netfilter (nftables) kernel-level ruleset manager for OmaBlock
pub struct KernelNetfilter;

impl KernelNetfilter {
    pub const TABLE_NAME: &'static str = "omablock";
    pub const FAMILY: &'static str = "inet";

    /// Checks if nftables CLI tool is available on the system
    pub fn is_nft_available() -> bool {
        let cmd_paths = ["/usr/bin/nft", "/sbin/nft", "/usr/sbin/nft"];
        cmd_paths.iter().any(|p| Path::new(p).is_file())
    }

    /// Checks if omablock kernel table is currently active in the Linux kernel
    pub fn is_active() -> bool {
        if !Self::is_nft_available() {
            return false;
        }

        let deadline = std::time::Instant::now() + Duration::from_millis(600);
        match crate::subproc::run_cmd_bounded(
            "/usr/bin/nft",
            &["list", "table", Self::FAMILY, Self::TABLE_NAME],
            &[],
            deadline,
            64 * 1024,
        ) {
            Some(stdout) => {
                let s = String::from_utf8_lossy(&stdout);
                s.contains("table inet omablock")
            }
            None => false,
        }
    }

    /// Generates safe, declarative nftables ruleset string for OmaBlock kernel enforcement
    pub fn generate_ruleset(blocked_doh_ips: &[IpAddr]) -> String {
        let mut rules = String::new();
        rules.push_str(&format!(
            "table {} {} {{\n",
            Self::FAMILY,
            Self::TABLE_NAME
        ));

        // Define sets for blocked IP addresses
        rules.push_str("    set bad_ipv4 {\n        type ipv4_addr;\n        flags interval;\n");
        let v4_ips: Vec<String> = blocked_doh_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4.to_string()),
                _ => None,
            })
            .collect();
        if !v4_ips.is_empty() {
            rules.push_str(&format!("        elements = {{ {} }}\n", v4_ips.join(", ")));
        }
        rules.push_str("    }\n\n");

        rules.push_str("    set bad_ipv6 {\n        type ipv6_addr;\n        flags interval;\n");
        let v6_ips: Vec<String> = blocked_doh_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6.to_string()),
                _ => None,
            })
            .collect();
        if !v6_ips.is_empty() {
            rules.push_str(&format!("        elements = {{ {} }}\n", v6_ips.join(", ")));
        }
        rules.push_str("    }\n\n");

        // Output filter chain: intercepts outbound packets at kernel network stack
        rules.push_str("    chain output {\n");
        rules.push_str("        type filter hook output priority filter; policy accept;\n\n");
        rules.push_str("        # Restrict drops to encrypted DNS ports (443 DoH, 853 DoT, 53 plaintext) with fast TCP RST\n");
        rules.push_str("        ip daddr @bad_ipv4 tcp dport { 443, 853 } counter reject with tcp reset\n");
        rules.push_str("        ip daddr @bad_ipv4 udp dport { 53, 853 } counter reject with icmp type admin-prohibited\n");
        rules.push_str("        ip6 daddr @bad_ipv6 tcp dport { 443, 853 } counter reject with tcp reset\n");
        rules.push_str("        ip6 daddr @bad_ipv6 udp dport { 53, 853 } counter reject with icmpx type admin-prohibited\n");
        rules.push_str("    }\n");

        rules.push_str("}\n");
        rules
    }

    /// Inspects the current kernel filter status
    pub fn query_status() -> KernelFilterStatus {
        let supported = Self::is_nft_available();
        let active = Self::is_active();

        let mut rule_count = 0;
        if active {
            let deadline = std::time::Instant::now() + Duration::from_millis(600);
            if let Some(stdout) = crate::subproc::run_cmd_bounded(
                "/usr/bin/nft",
                &["list", "table", Self::FAMILY, Self::TABLE_NAME],
                &[],
                deadline,
                64 * 1024,
            ) {
                let s = String::from_utf8_lossy(&stdout);
                rule_count = s.lines().filter(|l| l.contains("reject") || l.contains("elements")).count();
            }
        }

        let summary = if !supported {
            "nftables araci sistemde bulunamadi (kernel destegi pasif)".to_string()
        } else if active {
            format!("Cekirdek Netfilter kalkani aktif ({} kural devrede)", rule_count)
        } else {
            "Cekirdek Netfilter kalkani pasif (istege bagli aktif edilebilir)".to_string()
        };

        KernelFilterStatus {
            is_supported: supported,
            is_active: active,
            table_name: Self::TABLE_NAME.to_string(),
            blocked_ports: vec![53, 853],
            active_rule_count: rule_count,
            summary,
        }
    }

    /// Generates rules for double-sided strict egress lockdown (panic blackout)
    fn generate_blackout_ruleset() -> String {
        let mut rules = String::new();
        rules.push_str(&format!("table {} {} {{\n", Self::FAMILY, Self::TABLE_NAME));
        rules.push_str("    chain output {\n");
        rules.push_str("        type filter hook output priority filter; policy accept;\n\n");
        rules.push_str("        # Double-sided strict egress lockdown (Panic Blackout)\n");
        rules.push_str("        # Reject non-loopback DNS (53, 853) traffic globally\n");
        rules.push_str("        iifname != \"lo\" tcp dport { 53, 853 } counter reject with tcp reset\n");
        rules.push_str("        iifname != \"lo\" udp dport { 53, 853 } counter reject with icmp type admin-prohibited\n");
        rules.push_str("        iifname != \"lo\" udp dport { 53, 853 } counter reject with icmpx type admin-prohibited\n");
        rules.push_str("    }\n");
        rules.push_str("}\n");
        rules
    }

    pub fn apply_network_blackout() -> bool {
        if !Self::is_nft_available() {
            return false;
        }
        let rules = Self::generate_blackout_ruleset();
        let child = std::process::Command::new("/usr/bin/nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .ok();
            
        if let Some(mut c) = child {
            if let Some(mut stdin) = c.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(rules.as_bytes());
            }
            if let Ok(status) = c.wait() {
                return status.success();
            }
        }
        false
    }

    pub fn clear_network_blackout() -> bool {
        if !Self::is_nft_available() {
            return false;
        }
        let deadline = std::time::Instant::now() + Duration::from_millis(600);
        crate::subproc::run_cmd_bounded(
            "/usr/bin/nft",
            &["delete", "table", Self::FAMILY, Self::TABLE_NAME],
            &[],
            deadline,
            64 * 1024,
        ).is_some()
    }

    pub fn is_network_blackout_active() -> bool {
        if !Self::is_nft_available() {
            return false;
        }
        let deadline = std::time::Instant::now() + Duration::from_millis(600);
        match crate::subproc::run_cmd_bounded(
            "/usr/bin/nft",
            &["list", "table", Self::FAMILY, Self::TABLE_NAME],
            &[],
            deadline,
            64 * 1024,
        ) {
            Some(stdout) => {
                let s = String::from_utf8_lossy(&stdout);
                s.contains("admin-prohibited") && s.contains("iifname != \"lo\"")
            }
            None => false,
        }
    }

    pub fn toggle_usb_armor() -> bool {
        // USB armor is usually handled via sysfs (e.g. /sys/bus/usb/drivers_autoprobe or auth).
        // For omablock, we simulate or just touch a file for now.
        let state_file = "/tmp/omablock_usb_armor.state";
        let is_active = std::path::Path::new(state_file).exists();
        if is_active {
            let _ = std::fs::remove_file(state_file);
            false
        } else {
            let _ = std::fs::write(state_file, b"1");
            true
        }
    }

    pub fn is_usb_armor_enabled() -> bool {
        std::path::Path::new("/tmp/omablock_usb_armor.state").exists()
    }
}
