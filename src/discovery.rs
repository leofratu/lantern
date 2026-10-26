use crate::model::{Device, Result, mac_address};
use std::{collections::BTreeMap, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

/// Bound both execution time and output; hostile router output must not exhaust memory.
pub async fn command_output(command: Command) -> Result<String> {
    command_input(command, None).await
}

pub async fn command_input(mut command: Command, input: Option<&str>) -> Result<String> {
    command
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| format!("Could not start system command: {e}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("Command output unavailable")?
        .take(2 * 1024 * 1024 + 1);
    let result = timeout(Duration::from_secs(15), async {
        if let Some(input)=input {
            use tokio::io::AsyncWriteExt;
            let mut stdin=child.stdin.take().ok_or("Command input unavailable")?;
            stdin.write_all(input.as_bytes()).await.map_err(|error|error.to_string())?;
            stdin.shutdown().await.map_err(|error|error.to_string())?;
        }
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map_err(|e| e.to_string())?;
        if bytes.len() > 2 * 1024 * 1024 { return Err("Command response exceeded 2 MiB".into()); }
        let status = child.wait().await.map_err(|e| e.to_string())?;
        if !status.success() { return Err("Command failed. Check SSH keys, known_hosts, router permissions, or installed network tools.".into()); }
        String::from_utf8(bytes).map_err(|_| "Command returned invalid UTF-8".into())
    }).await;
    match result {
        Ok(value) => value,
        Err(_) => {
            let _ = child.kill().await;
            Err("Command timed out after 15 seconds".into())
        }
    }
}

pub async fn local_devices() -> Result<Vec<Device>> {
    #[cfg(target_os = "linux")]
    let command = {
        let mut c = Command::new("ip");
        c.args(["-4", "neigh", "show"]);
        c
    };
    #[cfg(target_os = "macos")]
    let command = {
        let mut c = Command::new("arp");
        c.arg("-an");
        c
    };
    #[cfg(target_os = "windows")]
    let command = {
        let mut c = Command::new("arp");
        c.arg("-a");
        c
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Err("This platform is not supported".into());
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    Ok(parse_neighbors(
        &command_output(command).await?,
        "Neighbor cache",
    ))
}

pub fn parse_neighbors(text: &str, source: &str) -> Vec<Device> {
    let mut devices = BTreeMap::new();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        let ip = words.iter().find_map(|w| {
            w.trim_matches(['(', ')'])
                .parse::<std::net::Ipv4Addr>()
                .ok()
        });
        let mac = words.iter().find_map(|w| {
            let padded = w
                .split(':')
                .map(|p| {
                    if p.len() == 1 {
                        format!("0{p}")
                    } else {
                        p.into()
                    }
                })
                .collect::<Vec<_>>()
                .join(":");
            mac_address(&padded).ok()
        });
        if let (Some(ip), Some(mac)) = (ip, mac) {
            if ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() {
                continue;
            }
            devices.insert(
                mac.clone(),
                Device {
                    mac,
                    ip: ip.to_string(),
                    name: "Unidentified device".into(),
                    source: source.into(),
                    presence: "Cached observation".into(),
                    identity: Default::default(),
                },
            );
        }
    }
    devices.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_native_neighbor_formats_without_claiming_presence() {
        let formats = [
            "? (192.168.1.9) at 2:ab:cd:ef:1:2 on en0 ifscope [ethernet]",
            "192.168.1.9 dev eth0 lladdr 02:ab:cd:ef:01:02 STALE",
            "  192.168.1.9       02-ab-cd-ef-01-02     dynamic",
        ];
        for format in formats {
            let devices = parse_neighbors(format, "test");
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].mac, "02:ab:cd:ef:01:02");
            assert_eq!(devices[0].presence, "Cached observation");
        }
        assert!(parse_neighbors("? (192.168.1.8) at (incomplete)", "test").is_empty());
    }
}
