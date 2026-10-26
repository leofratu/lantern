#[cfg(target_os = "macos")]
use crate::model::RouterKind;
use crate::{
    model::{Result, RouterConfig},
    spike::SpikeInput,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct RelayJob {
    pub id: String,
    pub mac: String,
    pub command: String,
    pub directory: PathBuf,
    pub expires_at: u64,
    pub duration_s: u32,
    pub ipv6_available: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
impl RelayJob {
    pub fn view(&self) -> Value {
        let path = self.directory.join("status.json");
        let metadata = std::fs::symlink_metadata(&path)
            .ok()
            .filter(|m| m.file_type().is_file() && m.len() <= 4096);
        let stale = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|d| d.as_secs() > 12);
        let status = metadata
            .and_then(|_| std::fs::read(&path).ok())
            .and_then(|v| serde_json::from_slice::<Value>(&v).ok());
        let ipv4 = status.as_ref().and_then(|s| s["forwarded_ipv4"].as_u64());
        let ipv6 = status.as_ref().and_then(|s| s["forwarded_ipv6"].as_u64());
        let (state, message, forwarded, dropped, remaining, average) = if let Some(value) = status {
            let state = value["state"]
                .as_str()
                .filter(|s| {
                    [
                        "running",
                        "restoring",
                        "completed",
                        "stopped",
                        "failed",
                        "failed_restored",
                        "failed_or_unknown",
                        "watchdog_restored",
                    ]
                    .contains(s)
                })
                .unwrap_or("failed_or_unknown");
            let state = if ["running", "restoring"].contains(&state)
                && (stale || now() > self.expires_at + u64::from(self.duration_s) + 30)
            {
                "status_unknown"
            } else {
                state
            };
            (
                state.to_string(),
                if state == "status_unknown" {
                    "Relay updates stopped; its state is unknown. If the device cannot connect, reconnect its Wi-Fi.".into()
                } else {
                    value["message"]
                        .as_str()
                        .unwrap_or("Relay status is unknown")
                        .to_string()
                },
                value["forwarded"].as_u64(),
                value["dropped"].as_u64(),
                value["remaining_s"].as_u64(),
                value["avg_hold_ms"].as_f64(),
            )
        } else if self.directory.join("stop").exists() {
            (
                "stopped".into(),
                "Relay request canceled before start.".into(),
                None,
                None,
                None,
                None,
            )
        } else if now() > self.expires_at {
            (
                "expired".into(),
                "Relay request expired; prepare a new one.".into(),
                None,
                None,
                None,
                None,
            )
        } else {
            ("waiting".into(), "Run the displayed command in Terminal and authorize it with your Mac administrator password. Do not enter the password in Lantern.".into(), None,None,None,None)
        };
        json!({
            "id": self.id,
            "mac": self.mac,
            "state": state,
            "message": message,
            "command": self.command,
            "forwarded": forwarded,
            "forwarded_ipv4": ipv4,
            "forwarded_ipv6": ipv6,
            "ipv6_available": self.ipv6_available,
            "dropped": dropped,
            "remaining_s": remaining,
            "avg_hold_ms": average,
        })
    }
    pub fn stop(&self) -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(self.directory.join("stop")) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(format!("Could not request relay stop: {e}")),
        }
    }
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
async fn output(program: &str, arguments: &[&str]) -> Result<String> {
    let mut command = tokio::process::Command::new(program);
    command.args(arguments);
    crate::discovery::command_output(command).await
}

#[cfg(target_os = "macos")]
fn route_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
async fn ipv6_neighbors(interface: &str, target_mac: &str) -> Option<Value> {
    let route = output("route", &["-n", "get", "-inet6", "default"])
        .await
        .ok()?;
    if route_value(&route, "interface:")? != interface {
        return None;
    }
    let gateway: std::net::Ipv6Addr = route_value(&route, "gateway:")?
        .split('%')
        .next()?
        .parse()
        .ok()?;
    if !gateway.is_unicast_link_local() {
        return None;
    }
    let neighbors = output("ndp", &["-an"]).await.ok()?;
    let mut target = None;
    let mut gateway_mac = None;
    for line in neighbors.lines() {
        let mut fields = line.split_whitespace();
        let (Some(ip), Some(mac), Some(netif)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if netif != interface {
            continue;
        }
        let Ok(ip) = ip
            .split('%')
            .next()
            .unwrap_or("")
            .parse::<std::net::Ipv6Addr>()
        else {
            continue;
        };
        let normalized = mac
            .split(':')
            .map(|part| format!("{part:0>2}"))
            .collect::<Vec<_>>()
            .join(":");
        let Ok(mac) = crate::model::mac_address(&normalized) else {
            continue;
        };
        if ip.is_unicast_link_local() && mac == target_mac {
            target = Some(ip);
        }
        if ip == gateway {
            gateway_mac = Some(mac);
        }
    }
    Some(
        json!({"target_ip": target?.to_string(), "gateway_ip": gateway.to_string(), "gateway_mac": gateway_mac?}),
    )
}

#[cfg(target_os = "macos")]
pub async fn prepare(config: &RouterConfig, input: &SpikeInput, ip: &str) -> Result<RelayJob> {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    if !matches!(config.kind, RouterKind::Movistar) {
        return Err("Mac relay is available for the Movistar gateway".into());
    }
    let mac = input.validate()?;
    let target: std::net::Ipv4Addr = ip.parse().map_err(|_| "Invalid target address")?;
    if !target.is_private() {
        return Err("Target must have a private IPv4 address".into());
    }
    let default = output("route", &["-n", "get", "default"]).await?;
    if route_value(&default, "gateway:") != Some(config.host.as_str()) {
        return Err("The connected Movistar router is not this Mac's current gateway".into());
    }
    let interface = crate::limits::interface_name(
        route_value(&default, "interface:").ok_or("Default route has no interface")?,
    )?;
    let route = output("route", &["-n", "get", ip]).await?;
    if route_value(&route, "interface:") != Some(interface)
        || route_value(&route, "gateway:").is_some_and(|value| !value.starts_with("link#"))
    {
        return Err("BEAST and the router must be on this Mac's directly connected network".into());
    }
    if output("sysctl", &["-n", "net.inet.ip.forwarding"])
        .await?
        .trim()
        != "0"
    {
        return Err(
            "Mac IP forwarding is enabled; Lantern will not change global network settings".into(),
        );
    }
    let neighbor = output("arp", &["-n", ip]).await?;
    let target = crate::discovery::parse_neighbors(&neighbor, "neighbor")
        .into_iter()
        .find(|entry| entry.ip == ip && entry.mac == mac)
        .ok_or("The target's current network address does not match its inventory. Refresh the device and try again.")?;
    let gateway = output("arp", &["-n", &config.host]).await?;
    let gateway_mac = crate::discovery::parse_neighbors(&gateway, "neighbor")
        .into_iter()
        .find(|entry| entry.ip == config.host)
        .map(|entry| entry.mac)
        .ok_or("The router's local hardware address is unavailable")?;
    let info = output("ifconfig", &[interface]).await?;
    if !info.lines().any(|line| line.trim() == "status: active") {
        return Err("The selected network interface is not active".into());
    }
    let local_raw = info
        .lines()
        .find_map(|line| line.trim().strip_prefix("ether "))
        .ok_or("The Mac's network address is unavailable")?;
    let local_mac = crate::model::mac_address(local_raw)?;
    if local_mac == mac || local_mac == gateway_mac || mac == gateway_mac {
        return Err("Target, router and Mac hardware addresses must be distinct".into());
    }
    let ipv6 = ipv6_neighbors(interface, &mac).await;
    let expires_at = now() + 120;
    let id = uuid::Uuid::new_v4().to_string();
    let directory = std::env::temp_dir().join(format!("lantern-relay-{id}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|e| format!("Could not prepare relay directory: {e}"))?;
    let helper = directory.join("lantern_relay.py");
    let request = directory.join("request.json");
    let write_file = |path: &std::path::Path, bytes: &[u8]| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())
    };
    if let Err(error) = (|| -> Result<()> {
        write_file(&helper, include_bytes!("../tools/lantern_relay.py"))?;
        let data = json!({
            "interface": interface,
            "target_ip": target.ip,
            "target_mac": mac,
            "gateway_ip": config.host,
            "gateway_mac": gateway_mac,
            "local_mac": local_mac,
            "delay_ms": input.delay_ms,
            "duration_s": input.duration_s,
            "expires_at": expires_at,
            "ipv6": ipv6,
        });
        write_file(
            &request,
            &serde_json::to_vec(&data).map_err(|e| e.to_string())?,
        )
    })() {
        let _ = fs::remove_dir_all(&directory);
        return Err(format!("Could not prepare relay: {error}"));
    }
    let helper = helper.to_str().ok_or("Unsupported helper path")?;
    let request = request.to_str().ok_or("Unsupported request path")?;
    let command = format!(
        "sudo /usr/bin/python3 -I {} --request {}",
        shell_quote(helper),
        shell_quote(request)
    );
    Ok(RelayJob {
        id,
        mac,
        command,
        directory,
        expires_at,
        duration_s: input.duration_s,
        ipv6_available: ipv6.is_some(),
    })
}

#[cfg(not(target_os = "macos"))]
pub async fn prepare(_config: &RouterConfig, _input: &SpikeInput, _ip: &str) -> Result<RelayJob> {
    Err("The Movistar device relay currently requires macOS".into())
}
