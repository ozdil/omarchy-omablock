use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct KernelState {
    pub nft_available: bool,
    pub kernel_active: bool,
    pub kernel_rule_count: usize,
    pub blackout_active: bool,
}

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
    /// Separate table so `--resume-network` never wipes the DoH/DoT enforcement table.
    pub const BLACKOUT_TABLE_NAME: &'static str = "omablock_blackout";
    pub const FAMILY: &'static str = "inet";

    /// Written by the privileged omablock-hosts-sync helper after every nft change.
    /// The engine runs unprivileged and cannot run `nft list` itself (needs CAP_NET_ADMIN).
    pub const STATE_FILE: &'static str = "/run/omablock/kernel_state.json";

    /// Checks if nftables CLI tool is available on the system
    pub fn is_nft_available() -> bool {
        ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]
            .iter()
            .any(|p| Path::new(p).is_file())
    }

    /// Reads the helper-published kernel state; missing or unreadable means nothing is active.
    pub fn read_state() -> KernelState {
        Self::read_state_from(Path::new(Self::STATE_FILE))
    }

    pub fn read_state_from(path: &Path) -> KernelState {
        // The file is root-owned in /run, so it is read directly instead of via secure_fs
        // (which insists on files owned by the current user).
        match std::fs::read(path) {
            Ok(data) if data.len() <= 4096 => serde_json::from_slice(&data).unwrap_or_default(),
            _ => KernelState::default(),
        }
    }

    /// Checks if omablock kernel table is currently active in the Linux kernel
    pub fn is_active() -> bool {
        Self::read_state().kernel_active
    }

    pub fn is_network_blackout_active() -> bool {
        Self::read_state().blackout_active
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
        let state = Self::read_state();
        let active = state.kernel_active;
        let rule_count = state.kernel_rule_count;

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
            blocked_ports: vec![53, 443, 853],
            active_rule_count: rule_count,
            summary,
        }
    }

    fn get_usb_armor_state_path() -> std::path::PathBuf {
        let dir = crate::secure_fs::home_dir().join(".local/state/omarchy/omablock");
        let _ = crate::secure_fs::ensure_state_dir(&dir);
        dir.join("usb_armor.state")
    }

    /// Experimental: only flips a per-user state flag shown in the UI. Nothing enforces
    /// it yet (no udev or usbguard rule is written), so it does not block USB devices.
    pub fn toggle_usb_armor() -> bool {
        let state_file = Self::get_usb_armor_state_path();
        let is_active = state_file.exists();
        if is_active {
            let _ = std::fs::remove_file(state_file);
            false
        } else {
            let _ = std::fs::write(state_file, b"1");
            true
        }
    }

    pub fn is_usb_armor_enabled() -> bool {
        Self::get_usb_armor_state_path().exists()
    }
}
