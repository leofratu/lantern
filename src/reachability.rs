use crate::model::Result;
use serde::Serialize;
use std::{net::Ipv4Addr, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

#[derive(Debug, Serialize)]
pub struct PingResult {
    pub ip: Ipv4Addr,
    pub sent: u8,
    pub received: u8,
    pub loss_percent: f64,
    pub roundtrip_ms: Vec<f64>,
}

pub async fn ping(ip: Ipv4Addr) -> Result<PingResult> {
    if !ip.is_private() || ip.is_broadcast() {
        return Err("Ping requires an observed device's private IPv4 address".into());
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut command = {
        let mut command = Command::new("ping");
        command.env("LC_ALL", "C").env("LANG", "C");
        command.args(["-n", "-c", "3", "-W"]);
        #[cfg(target_os = "macos")]
        command.arg("1000");
        #[cfg(target_os = "linux")]
        command.arg("1");
        command.arg(ip.to_string());
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        // .NET returns numeric status/RTT values independently of OS language.
        // Only the validated IPv4 literal is interpolated into this fixed script.
        let script = format!(
            "$ErrorActionPreference='Stop'; $p=New-Object System.Net.NetworkInformation.Ping; $r=@(); try {{ 1..3 | ForEach-Object {{ $reply=$p.Send('{ip}',1000); if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {{ $r += $reply.RoundtripTime }} }}; ConvertTo-Json -InputObject @($r) -Compress }} finally {{ $p.Dispose() }}"
        );
        let mut command = Command::new("powershell.exe");
        command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err("Ping is not supported on this platform".into());

    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Cannot start the system ping tool: {error}"))?;
    let mut output = child
        .stdout
        .take()
        .ok_or("Ping output unavailable")?
        .take(16 * 1024 + 1);
    let result = timeout(Duration::from_secs(8), async {
        let mut bytes = Vec::new();
        output
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| error.to_string())?;
        if bytes.len() > 16 * 1024 {
            return Err("Ping response exceeded 16 KiB".into());
        }
        let status = child.wait().await.map_err(|error| error.to_string())?;
        let text = String::from_utf8(bytes).map_err(|_| "Ping returned invalid text")?;
        #[cfg(target_os = "windows")]
        {
            if !status.success() {
                return Err("The Windows ICMP check failed; reachability is unknown".into());
            }
            let times: Vec<f64> =
                serde_json::from_str(&text).map_err(|_| "Invalid Windows ping reply")?;
            let received = u8::try_from(times.len()).map_err(|_| "Too many ping replies")?;
            result_from_samples(ip, 3, received, times)
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Nonzero exit status can mean ordinary packet loss. Require a valid
            // summary instead of treating every command failure as an offline host.
            let _ = status;
            parse_unix_reply(ip, &text)
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            Err("Ping timed out; the device's reachability is unknown".into())
        }
    }
}

fn result_from_samples(
    ip: Ipv4Addr,
    sent: u8,
    received: u8,
    times: Vec<f64>,
) -> Result<PingResult> {
    if sent != 3
        || received > sent
        || times.len() > usize::from(received)
        || times.iter().any(|time| !time.is_finite() || *time < 0.0)
    {
        return Err("Invalid ping statistics; reachability is unknown".into());
    }
    Ok(PingResult {
        ip,
        sent,
        received,
        loss_percent: 100.0 * f64::from(sent - received) / f64::from(sent),
        roundtrip_ms: times,
    })
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn parse_unix_reply(ip: Ipv4Addr, text: &str) -> Result<PingResult> {
    let summary = text.lines().find(|line| line.contains("packets transmitted,"))
        .ok_or("The system ping tool returned no complete statistics; check its availability and ICMP permissions")?;
    let mut parts = summary.split(',');
    let count = |part: Option<&str>| {
        part.and_then(|part| part.split_whitespace().next())
            .and_then(|word| word.parse::<u8>().ok())
            .ok_or("Invalid ping packet counts")
    };
    let sent = count(parts.next())?;
    let received_part = parts
        .next()
        .filter(|part| part.contains("received"))
        .ok_or("Ping reply count is missing")?;
    let received = count(Some(received_part))?;
    let times = text
        .lines()
        .filter(|line| line.contains("bytes from ") && line.contains("icmp_seq="))
        .filter_map(|line| {
            line.split_once("time=")
                .and_then(|(_, time)| time.split_whitespace().next())
                .and_then(|time| time.parse::<f64>().ok())
        })
        .collect();
    result_from_samples(ip, sent, received, times)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_loss_is_distinct_from_missing_or_malformed_statistics() {
        let ip = Ipv4Addr::new(192, 168, 1, 9);
        // Native macOS/Linux summary formats; synthetic device address.
        let reply = "64 bytes from 192.168.1.9: icmp_seq=0 ttl=64 time=0.124 ms\n3 packets transmitted, 1 packets received, 66.7% packet loss\n";
        let result = parse_unix_reply(ip, reply).expect("complete statistics");
        assert_eq!(result.received, 1);
        assert_eq!(result.roundtrip_ms, vec![0.124]);
        let lost = parse_unix_reply(ip, "3 packets transmitted, 0 received, 100% packet loss")
            .expect("no ICMP replies");
        assert_eq!(lost.loss_percent, 100.0);
        for invalid in [
            "permission denied",
            "3 packets transmitted, 4 received",
            "3 packets transmitted, unknown received",
            "3 packets transmitted,",
        ] {
            assert!(parse_unix_reply(ip, invalid).is_err());
        }
    }
}
