use crate::{
    discovery::command_output,
    model::{Result, RouterConfig, RouterKind, mac_address},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};
use uuid::Uuid;

pub async fn probe(config: &RouterConfig) -> Result<Value> {
    config.validate()?;
    let (fingerprint, _) = key(config).await?;
    Ok(
        json!({"fingerprint":fingerprint,"message":"SSH key reported by this router. Trust it only after checking that this is the gateway you administer."}),
    )
}

async fn key(config: &RouterConfig) -> Result<(String, String)> {
    let mut command = Command::new("ssh-keyscan");
    command.args(["-T", "3", "-t", "ed25519,rsa", &config.host]);
    let output = command_output(command).await?;
    let record = output
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find(|line| line.contains("ssh-ed25519"))
        .or_else(|| {
            output
                .lines()
                .find(|line| line.split_whitespace().nth(1) == Some("ssh-rsa"))
        })
        .ok_or("Router did not return a supported SSH key")?;
    let parts: Vec<_> = record.split_whitespace().collect();
    if parts.len() != 3 {
        return Err("Invalid SSH host-key response".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|_| "Invalid SSH public key")?;
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(bytes)));
    Ok((
        fingerprint,
        format!("{} {} {}\n", config.host, parts[1], parts[2]),
    ))
}

struct KnownHost(PathBuf);
impl Drop for KnownHost {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

async fn cli(config: &RouterConfig, command: &str) -> Result<String> {
    config.validate()?;
    if !matches!(config.kind, RouterKind::Movistar) {
        return Err("Native blacklist controls require a Movistar gateway".into());
    }
    let expected=config.ssh_fingerprint.as_deref().ok_or("Inspect and trust this router's SSH fingerprint in Gateway settings before using SSH controls")?;
    let (fingerprint, key) = key(config).await?;
    if fingerprint != expected {
        return Err("SSH host key changed. Router controls were stopped; verify the gateway identity before trusting a replacement key.".into());
    }
    let known = KnownHost(std::env::temp_dir().join(format!("lantern-host-{}", Uuid::new_v4())));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&known.0)
        .and_then(|mut file| file.write_all(key.as_bytes()))
        .map_err(|error| error.to_string())?;
    let mut ssh = Command::new("ssh");
    ssh.args([
        "-tt",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "HostKeyAlgorithms=+ssh-rsa",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "LogLevel=ERROR",
        "-o",
        &format!("UserKnownHostsFile={}", known.0.display()),
        &format!("1234@{}", config.host),
    ]);
    ssh.env(
        "SSH_ASKPASS",
        std::env::current_exe().map_err(|error| error.to_string())?,
    )
    .env("SSH_ASKPASS_REQUIRE", "force")
    .env("DISPLAY", "lantern:0")
    .env("LANTERN_ASKPASS", "1")
    .env("LANTERN_SSH_PASSWORD", &config.password);
    let text = interactive(ssh, command).await.map_err(|message| {
        if config.password.is_empty() {
            message
        } else {
            message.replace(&config.password, "[REDACTED]")
        }
    })?;
    if text.contains("Invalid")
        || text.contains("Operation Blocked")
        || text.contains("Invalid input")
        || text.contains("Must input")
        || text.contains("Must Input")
        || text.contains("Error:")
    {
        return Err("The router rejected the management command; no successful enforcement has been verified".into());
    }
    Ok(text)
}

async fn prompt(reader: &mut tokio::process::ChildStdout) -> Result<String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("Router closed its SSH shell before returning a command prompt".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 64 * 1024 {
            return Err("Router CLI response exceeded 64 KiB".into());
        }
        if bytes.ends_with(b"> ") {
            return String::from_utf8(bytes).map_err(|_| "Router CLI returned invalid text".into());
        }
    }
}

async fn interactive(mut command: Command, request: &str) -> Result<String> {
    command
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("Cannot launch SSH: {error}"))?;
    let mut input = child.stdin.take().ok_or("SSH input unavailable")?;
    let mut output = child.stdout.take().ok_or("SSH output unavailable")?;
    // Native configuration writes can take over 20 seconds on this firmware.
    let result = timeout(Duration::from_secs(60), async {
        prompt(&mut output).await?;
        input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        let reply = prompt(&mut output).await?;
        input
            .write_all(b"exit\n")
            .await
            .map_err(|error| error.to_string())?;
        drop(input);
        let _ = child.wait().await.map_err(|error| error.to_string())?;
        Ok::<String, String>(reply)
    })
    .await;
    match result {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            let mut diagnostics = String::new();
            if let Some(stderr) = child.stderr.take() {
                let _ = stderr.take(2048).read_to_string(&mut diagnostics).await;
            }
            Err(format!("{error}. {}", diagnostics.trim()))
        }
        Err(_) => {
            let _ = child.kill().await;
            Err("Router SSH session timed out. A command may have been sent; verify association or blacklist state before retrying.".into())
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Blacklist {
    pub enabled: bool,
    pub blocked_macs: Vec<String>,
}

impl Blacklist {
    pub fn contains(&self, mac: &str) -> bool {
        self.blocked_macs.iter().any(|entry| entry == mac)
    }
}

fn parse_blacklist(text: &str) -> Result<Blacklist> {
    let mut enabled = None;
    let mut list_seen = false;
    let mut blocked_macs = std::collections::BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if matches!(line, "show blacklist" | ">") {
            continue;
        }
        match line {
            "mac_blacklist on" | "mac_blacklist off" if enabled.is_none() && !list_seen => {
                enabled = Some(line == "mac_blacklist on");
            }
            "blocked_mac_list" if enabled.is_some() && !list_seen => list_seen = true,
            _ if list_seen => {
                blocked_macs.insert(mac_address(line).map_err(
                    |_| "Unsupported blacklist entry; no changes were authorized by this readback",
                )?);
            }
            _ => return Err("Router returned an unsupported blacklist status format".into()),
        }
    }
    if !list_seen {
        return Err("Incomplete blacklist response; current policy is unknown".into());
    }
    Ok(Blacklist {
        enabled: enabled.ok_or("Blacklist mode is missing")?,
        blocked_macs: blocked_macs.into_iter().collect(),
    })
}

pub async fn blacklist(config: &RouterConfig) -> Result<Blacklist> {
    parse_blacklist(&cli(config, "show blacklist").await?)
}

pub async fn status(config: &RouterConfig) -> Result<Value> {
    let policy = blacklist(config).await?;
    Ok(
        json!({"enabled":policy.enabled,"blocked_macs":policy.blocked_macs,"message":"Blacklist read from the router's authenticated SSH management CLI"}),
    )
}

fn block_plan(
    before: &Blacklist,
    mac: &str,
    blocked: bool,
    enable_mode: bool,
) -> Result<Vec<String>> {
    let mut commands = Vec::new();
    if blocked {
        if !before.enabled {
            if !enable_mode {
                return Err("Blacklist mode is disabled. Inspect gateway rules and explicitly confirm enabling it; this router disables whitelist mode when enabling its blacklist.".into());
            }
            if before.blocked_macs.iter().any(|entry| entry != mac) {
                return Err("The disabled blacklist contains other addresses. Enabling it would also block those devices; review that policy in the router before continuing.".into());
            }
        }
        // Add the target before enabling the filter. Never replace or clear the list.
        if !before.contains(mac) {
            commands.push(format!("add mac_blocked {mac}"));
        }
        if !before.enabled {
            commands.push("set mac_blacklist on".into());
        }
    } else if before.contains(mac) {
        commands.push(format!("remove mac_blocked {mac}"));
    }
    Ok(commands)
}

fn verify_change(before: &Blacklist, after: &Blacklist, mac: &str, blocked: bool) -> Result<()> {
    let retained_before: Vec<_> = before
        .blocked_macs
        .iter()
        .filter(|entry| entry.as_str() != mac)
        .collect();
    let retained_after: Vec<_> = after
        .blocked_macs
        .iter()
        .filter(|entry| entry.as_str() != mac)
        .collect();
    if retained_before != retained_after {
        return Err("Other blacklist entries changed during this operation. The requested policy may be partially applied; inspect gateway rules before retrying.".into());
    }
    if after.contains(mac) != blocked
        || (blocked && !after.enabled)
        || (!blocked && before.enabled != after.enabled)
    {
        return Err("Router readback did not confirm the requested blacklist policy. Inspect gateway rules; the write outcome is unknown.".into());
    }
    Ok(())
}

pub async fn set_block(
    config: &RouterConfig,
    mac: &str,
    blocked: bool,
    enable_mode: bool,
) -> Result<Blacklist> {
    let mac = mac_address(mac)?;
    let before = blacklist(config).await?;
    for command in block_plan(&before, &mac, blocked, enable_mode)? {
        cli(config, &command).await.map_err(|error| format!("Blacklist change may be partially applied: {error}. Inspect gateway rules before retrying."))?;
    }
    // A fresh authenticated session is authoritative; a setter acknowledgement is not.
    let after = blacklist(config)
        .await
        .map_err(|error| format!("Blacklist write outcome is unknown: {error}"))?;
    verify_change(&before, &after, &mac, blocked)?;
    Ok(after)
}

pub async fn disconnect(config: &RouterConfig, mac: &str) -> Result<Value> {
    let mac = mac_address(mac)?;
    // This is the firmware's native command, not an injected wireless frame.
    let reply = cli(config, &format!("set deauthenticate {mac}")).await?;
    let acknowledged = reported_deauthentication(&reply, &mac);
    if acknowledged {
        return Ok(
            json!({"outcome":"router_deauth_reported","router_acknowledged":true,"message":"Router explicitly reported deauthentication for this MAC. The device can reconnect; current radio association is checked separately."}),
        );
    }
    Ok(
        json!({"outcome":"command_sent","message":"Disconnect command sent, but disconnection is unverified. The device is still associated, reconnected immediately, or verification could not be completed."}),
    )
}

fn reported_deauthentication(reply: &str, mac: &str) -> bool {
    reply.lines().any(|line| {
        line.trim()
            .eq_ignore_ascii_case(&format!("deauthenticated MAC {mac}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_echo_is_not_a_deauthentication_acknowledgement() {
        // Sanitized from this firmware's actual CLI reply; no real client identifier.
        let mac = "02:00:00:00:00:01";
        assert!(!reported_deauthentication(
            "set deauthenticate 02:00:00:00:00:01\r\n > ",
            mac
        ));
        assert!(reported_deauthentication(
            "set deauthenticate 02:00:00:00:00:01\r\ndeauthenticated MAC 02:00:00:00:00:01\r\n > ",
            mac
        ));
        assert!(!reported_deauthentication(
            "deauthenticated MAC 02:00:00:00:00:02\r\n > ",
            mac
        ));
    }

    #[test]
    fn blacklist_requires_complete_readback_and_normalizes_real_cli_format() {
        // Actual firmware reply format, with a synthetic client address.
        let policy = parse_blacklist("show blacklist\r\r\nmac_blacklist on\r\r\nblocked_mac_list\r\r\n02:00:00:00:00:01\r\r\n > ").expect("complete reply");
        assert!(policy.enabled);
        assert!(policy.contains("02:00:00:00:00:01"));
        for reply in [
            "show blacklist\n > ",
            "mac_blacklist off\n",
            "mac_blacklist on\nblocked_mac_list\ninvalid",
            "mac_blacklist on\nmac_blacklist off\nblocked_mac_list",
        ] {
            assert!(parse_blacklist(reply).is_err(), "{reply}");
        }
    }

    #[test]
    fn blacklist_changes_are_scoped_idempotent_and_preserve_other_entries() {
        let mac = "02:00:00:00:00:01";
        let other = "02:00:00:00:00:02";
        let mut before = Blacklist {
            enabled: false,
            blocked_macs: vec![],
        };
        assert!(block_plan(&before, mac, true, false).is_err());
        assert_eq!(
            block_plan(&before, mac, true, true).expect("authorized mode change"),
            vec![
                format!("add mac_blocked {mac}"),
                "set mac_blacklist on".into()
            ]
        );
        before.blocked_macs.push(other.into());
        assert!(block_plan(&before, mac, true, true).is_err());
        before.enabled = true;
        let mut after = before.clone();
        after.blocked_macs.insert(0, mac.into());
        assert!(verify_change(&before, &after, mac, true).is_ok());
        assert!(
            block_plan(&after, mac, true, false)
                .expect("already blocked")
                .is_empty()
        );
        assert_eq!(
            block_plan(&after, mac, false, false).expect("unblock"),
            vec![format!("remove mac_blocked {mac}")]
        );
        assert!(verify_change(&after, &before, mac, false).is_ok());
        after.blocked_macs.retain(|entry| entry != other);
        assert!(verify_change(&before, &after, mac, true).is_err());
        assert!(verify_change(&before, &before, mac, true).is_err());
    }
}
