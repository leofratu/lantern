use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Serialize)]
pub struct Device {
    pub mac: String,
    pub ip: String,
    pub name: String,
    pub source: String,
    pub presence: String,
    pub identity: Identity,
}

#[derive(Clone, Default, Serialize)]
pub struct Identity {
    pub display_name: Option<String>,
    pub operating_system: Option<String>,
    pub manufacturer: Option<String>,
    pub mac_kind: String,
    pub category: String,
    pub hostname: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub services: Vec<String>,
    pub evidence: Vec<String>,
    pub inspected_at: Option<u64>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterKind {
    Openwrt,
    Movistar,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterConfig {
    pub kind: RouterKind,
    pub host: String,
    #[serde(default = "default_user")]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ssh_fingerprint: Option<String>,
}

fn default_user() -> String {
    "root".into()
}

impl RouterConfig {
    pub fn validate(&self) -> Result<()> {
        let ip: Ipv4Addr = self
            .host
            .parse()
            .map_err(|_| "Enter a private IPv4 router address")?;
        if !ip.is_private() {
            return Err("Router address must be on a private network".into());
        }
        if self.user.is_empty()
            || self.user.len() > 32
            || !self
                .user
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err("SSH username must contain only letters, digits, or underscores".into());
        }
        if self.password.len() > 256 || self.password.contains(['\r', '\n']) {
            return Err("Password must be at most 256 bytes and contain no line breaks".into());
        }
        Ok(())
    }
}

pub fn mac_address(value: &str) -> Result<String> {
    let parts: Vec<_> = value.split([':', '-']).collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|v| v.len() != 2 || !v.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("Invalid MAC address".into());
    }
    let normalized = parts.join(":").to_lowercase();
    let first = u8::from_str_radix(parts[0], 16).map_err(|_| "Invalid MAC")?;
    if first & 1 != 0 || normalized == "00:00:00:00:00:00" {
        return Err("A unicast device MAC address is required".into());
    }
    Ok(normalized)
}

#[derive(Clone, Serialize)]
pub struct Event {
    pub at: u64,
    pub message: String,
    pub outcome: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_network_identifiers() {
        assert_eq!(
            mac_address("02-AA-BB-CC-DD-EE").expect("valid unicast MAC"),
            "02:aa:bb:cc:dd:ee"
        );
        for bad in [
            "ff:ff:ff:ff:ff:ff",
            "00:00:00:00:00:00",
            "02:aa:bb:cc:dd:ee;reboot",
        ] {
            assert!(mac_address(bad).is_err());
        }
        let mut cfg = RouterConfig {
            kind: RouterKind::Openwrt,
            host: "192.168.1.1".into(),
            user: "root".into(),
            password: String::new(),
            ssh_fingerprint: None,
        };
        assert!(cfg.validate().is_ok());
        cfg.host = "127.0.0.1".into();
        assert!(cfg.validate().is_err());
        cfg.host = "192.168.1.1".into();
        cfg.user = "-oProxyCommand=evil".into();
        assert!(cfg.validate().is_err());
    }
}
