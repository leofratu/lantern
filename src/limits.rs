use crate::{
    model::{Result, RouterConfig, RouterKind, mac_address},
    router::ssh,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const TABLE: &str = "lantern_rate_v1";
const OWNER: &str = "Managed by Lantern rate v1";
const BURST: u64 = 16_384;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitInput {
    pub mac: String,
    pub up_kbps: u32,
    pub down_kbps: u32,
}

impl LimitInput {
    pub fn validate(&self) -> Result<String> {
        let mac = mac_address(&self.mac)?;
        if (self.up_kbps == 0 && self.down_kbps == 0)
            || ((64..=10_000_000).contains(&self.up_kbps)
                && (64..=10_000_000).contains(&self.down_kbps))
        {
            return Ok(mac);
        }
        Err(
            "Set both limits between 64 and 10000000 kbps, or both to zero to remove the limit"
                .into(),
        )
    }
}

#[derive(Debug, Serialize)]
pub struct DeviceLimit {
    pub mac: String,
    pub interface: String,
    pub up_kbps: u32,
    pub down_kbps: u32,
    pub up_dropped_bytes: u64,
    pub down_dropped_bytes: u64,
    #[serde(skip)]
    handles: Vec<(String, u64)>,
}

fn openwrt(config: &RouterConfig) -> Result<()> {
    if !matches!(config.kind, RouterKind::Openwrt) {
        return Err("Device speed caps require an OpenWrt gateway in the traffic path. This Movistar firmware exposes priority settings, not a verified per-device rate cap.".into());
    }
    Ok(())
}

pub(crate) fn interface_name(value: &str) -> Result<&str> {
    if value.is_empty()
        || value.len() > 15
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("Unsupported gateway interface name".into());
    }
    Ok(value)
}

pub(crate) async fn offload_check(config: &RouterConfig) -> Result<()> {
    let settings = ssh(config, "if command -v uci >/dev/null 2>&1; then uci -q get 'firewall.@defaults[0].flow_offloading' || :; uci -q get 'firewall.@defaults[0].flow_offloading_hw' || :; fi").await?;
    if settings.lines().any(|line| line.trim() == "1") {
        return Err("Disable software and hardware flow offloading in OpenWrt before changing device traffic controls. Lantern does not change global offload settings.".into());
    }
    let rules: Value = serde_json::from_str(&ssh(config, "nft -j list ruleset").await?)
        .map_err(|_| "Invalid gateway ruleset")?;
    if rules["nftables"]
        .as_array()
        .ok_or("Gateway omitted its ruleset")?
        .iter()
        .any(|item| item.get("flowtable").is_some())
    {
        return Err("The gateway has a flowtable that may bypass device traffic controls. Review offloading before continuing.".into());
    }
    Ok(())
}

pub(crate) async fn direct_interface(
    config: &RouterConfig,
    ip: Option<&str>,
    mac: &str,
) -> Result<String> {
    let ip: std::net::Ipv4Addr = ip
        .ok_or("Refresh inventory before changing device traffic")?
        .parse()
        .map_err(|_| "Invalid device IP")?;
    if !ip.is_private() {
        return Err("Device must have a private IPv4 route".into());
    }
    let routes: Value = serde_json::from_str(&ssh(config, &format!("ip -j route get {ip}")).await?)
        .map_err(|_| "OpenWrt needs ip-full with JSON route support")?;
    let route = routes
        .as_array()
        .and_then(|routes| routes.first())
        .ok_or("Device route is missing")?;
    if route.get("gateway").is_some() {
        return Err("The device must be directly connected to the OpenWrt LAN".into());
    }
    let interface = interface_name(route["dev"].as_str().ok_or("LAN route has no interface")?)?;
    let neighbors: Value = serde_json::from_str(
        &ssh(config, &format!("ip -j neigh show to {ip} dev {interface}")).await?,
    )
    .map_err(|_| "OpenWrt needs ip-full with JSON neighbor support")?;
    if !neighbors
        .as_array()
        .ok_or("Invalid neighbor response")?
        .iter()
        .any(|entry| {
            entry["lladdr"]
                .as_str()
                .is_some_and(|entry| entry.eq_ignore_ascii_case(mac))
        })
    {
        return Err("The current LAN neighbor does not match this device's MAC. Refresh inventory before changing its traffic.".into());
    }
    Ok(interface.to_string())
}

async fn table(config: &RouterConfig) -> Result<Option<Value>> {
    openwrt(config)?;
    let tables: Value = serde_json::from_str(&ssh(config, "nft -j list tables").await?)
        .map_err(|_| "Invalid gateway table list")?;
    if !tables["nftables"]
        .as_array()
        .ok_or("Gateway omitted its tables")?
        .iter()
        .any(|item| item["table"]["name"] == TABLE && item["table"]["family"] == "netdev")
    {
        return Ok(None);
    }
    let mut value: Value =
        serde_json::from_str(&ssh(config, &format!("nft -j list table netdev {TABLE}")).await?)
            .map_err(|_| "Invalid speed-cap table")?;
    let items = value["nftables"]
        .as_array()
        .ok_or("Gateway omitted speed-cap objects")?;
    if !items.iter().any(|item| {
        item["table"]["comment"] == OWNER
            && item["table"]["name"] == TABLE
            && item["table"]["family"] == "netdev"
    }) {
        return Err("Refusing a speed-cap table without Lantern's ownership marker".into());
    }
    if items.iter().any(|item| {
        item["table"]["flags"]
            .as_array()
            .is_some_and(|flags| !flags.is_empty())
    }) {
        return Err("Speed-cap table flags changed; enforcement is unknown".into());
    }
    // nft 1.0.9 omits netdev bindings from JSON; verify that property through
    // the kernel's canonical text listing, with numeric priorities.
    let bindings =
        device_bindings(&ssh(config, &format!("nft -y list table netdev {TABLE}")).await?)?;
    for item in value["nftables"]
        .as_array_mut()
        .ok_or("Missing speed-cap objects")?
    {
        if let Some(chain) = item.get_mut("chain") {
            let name = chain["name"]
                .as_str()
                .ok_or("Speed-cap chain name missing")?;
            let (hook, device) = bindings
                .get(name)
                .ok_or("Speed-cap device binding could not be verified")?;
            if chain["hook"] != hook.as_str() {
                return Err("Speed-cap hook changed during readback".into());
            }
            chain["dev"] = json!(device);
        }
    }
    Ok(Some(value))
}

fn device_bindings(text: &str) -> Result<std::collections::BTreeMap<String, (String, String)>> {
    let mut bindings = std::collections::BTreeMap::new();
    let mut chain = None;
    for line in text.lines().map(str::trim) {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() == Some(&"chain") && words.len() == 3 && words[2] == "{" {
            chain = Some(words[1].trim_matches('"').to_string());
        } else if line == "}" {
            chain = None;
        } else if words.first() == Some(&"type") {
            if words.len() != 10
                || words[1] != "filter"
                || words[2] != "hook"
                || !matches!(words[3], "ingress" | "egress")
                || words[4] != "device"
                || words[6] != "priority"
                || words[7] != "-10;"
                || words[8] != "policy"
                || words[9] != "accept;"
            {
                return Err("Unrecognized speed-cap device binding".into());
            }
            let name = chain
                .as_ref()
                .ok_or("Device binding appeared outside a chain")?;
            let interface = interface_name(words[5].trim_matches('"'))?;
            if bindings
                .insert(name.clone(), (words[3].into(), interface.into()))
                .is_some()
            {
                return Err("Duplicate speed-cap device binding".into());
            }
        }
    }
    Ok(bindings)
}

fn byte_quantity(limit: &Value, amount: &str, unit: &str) -> Option<u64> {
    let multiplier = match limit[unit].as_str()? {
        "bytes" => 1,
        "kbytes" => 1024,
        "mbytes" => 1024 * 1024,
        _ => return None,
    };
    limit[amount].as_u64()?.checked_mul(multiplier)
}

fn parse_limits(value: &Value) -> Result<Vec<DeviceLimit>> {
    let items = value["nftables"]
        .as_array()
        .ok_or("Missing speed-cap objects")?;
    let mut limits = std::collections::BTreeMap::<String, DeviceLimit>::new();
    for rule in items.iter().filter_map(|item| item.get("rule")) {
        let comment = rule["comment"]
            .as_str()
            .ok_or("Unrecognized rule in Lantern speed-cap table")?;
        let parts: Vec<_> = comment.split(':').collect();
        if parts.len() != 9 || parts[0] != "lantern-rate" {
            return Err("Unrecognized speed-cap marker".into());
        }
        let mac = mac_address(&parts[1..7].join(":"))?;
        let up = match parts[7] {
            "up" => true,
            "down" => false,
            _ => return Err("Invalid speed direction".into()),
        };
        let kbps: u32 = parts[8]
            .parse()
            .map_err(|_| "Invalid speed in gateway marker")?;
        if !(64..=10_000_000).contains(&kbps) {
            return Err("Gateway speed is outside supported bounds".into());
        }
        let chain_name = rule["chain"].as_str().ok_or("Speed-cap chain is missing")?;
        let chain = items
            .iter()
            .filter_map(|item| item.get("chain"))
            .find(|chain| chain["name"] == chain_name)
            .ok_or("Speed-cap chain was not read back")?;
        let interface = interface_name(
            chain["dev"]
                .as_str()
                .ok_or("Speed-cap interface is missing")?,
        )?;
        if chain["type"] != "filter"
            || chain["hook"] != if up { "ingress" } else { "egress" }
            || chain["prio"] != -10
            || chain["policy"] != "accept"
        {
            return Err("Speed-cap hook changed; enforcement is unverified".into());
        }
        let expr = rule["expr"]
            .as_array()
            .ok_or("Speed-cap expressions missing")?;
        let valid = expr.len() == 4
            && expr[0]["match"]["op"] == "=="
            && expr[0]["match"]["left"]["payload"]["protocol"] == "ether"
            && expr[0]["match"]["left"]["payload"]["field"] == if up { "saddr" } else { "daddr" }
            && expr[0]["match"]["right"]
                .as_str()
                .is_some_and(|entry| entry.eq_ignore_ascii_case(&mac))
            && byte_quantity(&expr[1]["limit"], "rate", "rate_unit") == Some(u64::from(kbps) * 125)
            && expr[1]["limit"]["per"] == "second"
            && byte_quantity(&expr[1]["limit"], "burst", "burst_unit") == Some(BURST)
            && expr[1]["limit"]["inv"] == true
            && expr[2].get("counter").is_some()
            && expr[3].get("drop").is_some();
        if !valid {
            return Err("Speed-cap match, rate, burst, counter, or drop action changed; enforcement is unverified".into());
        }
        let entry = limits.entry(mac.clone()).or_insert_with(|| DeviceLimit {
            mac,
            interface: interface.into(),
            up_kbps: 0,
            down_kbps: 0,
            up_dropped_bytes: 0,
            down_dropped_bytes: 0,
            handles: Vec::new(),
        });
        if entry.interface != interface
            || (up && entry.up_kbps != 0)
            || (!up && entry.down_kbps != 0)
        {
            return Err("Duplicate or conflicting speed-cap rules".into());
        }
        let bytes = expr[2]["counter"]["bytes"]
            .as_u64()
            .ok_or("Speed-cap byte counter missing")?;
        if up {
            entry.up_kbps = kbps;
            entry.up_dropped_bytes = bytes;
        } else {
            entry.down_kbps = kbps;
            entry.down_dropped_bytes = bytes;
        }
        entry.handles.push((
            chain_name.into(),
            rule["handle"].as_u64().ok_or("Speed-cap handle missing")?,
        ));
    }
    if limits
        .values()
        .any(|limit| limit.up_kbps == 0 || limit.down_kbps == 0)
    {
        return Err("Only one direction was installed; speed cap is incomplete".into());
    }
    Ok(limits.into_values().collect())
}

pub async fn status(config: &RouterConfig) -> Result<Vec<DeviceLimit>> {
    match table(config).await? {
        Some(value) => parse_limits(&value),
        None => Ok(Vec::new()),
    }
}

pub async fn set(config: &RouterConfig, input: &LimitInput, ip: Option<&str>) -> Result<Value> {
    openwrt(config)?;
    let mac = input.validate()?;
    let current = status(config).await?;
    let existing = current.iter().find(|entry| entry.mac == mac);
    let mut commands = Vec::new();
    if let Some(existing) = existing {
        for (chain, handle) in &existing.handles {
            // Chain names are generated by Lantern and validated before interpolation.
            if !chain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err("Invalid speed-cap chain name".into());
            }
            commands.push(format!(
                "delete rule netdev {TABLE} {chain} handle {handle}"
            ));
        }
    }
    if input.up_kbps != 0 {
        offload_check(config).await?;
        let interface = direct_interface(config, ip, &mac).await?;
        commands.push(format!(
            "add table netdev {TABLE} {{ comment \"{OWNER}\"; }}"
        ));
        for (direction, hook, field, kbps) in [
            ("up", "ingress", "saddr", input.up_kbps),
            ("down", "egress", "daddr", input.down_kbps),
        ] {
            let encoded_interface: String = interface
                .bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let chain = format!("{direction}_{encoded_interface}");
            commands.push(format!("add chain netdev {TABLE} {chain} {{ type filter hook {hook} device \"{interface}\" priority -10; policy accept; }}"));
            commands.push(format!("add rule netdev {TABLE} {chain} ether {field} {mac} limit rate over {} bytes/second burst {BURST} bytes counter drop comment \"lantern-rate:{mac}:{direction}:{kbps}\"", u64::from(kbps) * 125));
        }
    }
    if !commands.is_empty() {
        ssh(config, &format!("nft -f - <<'LANTERN_RATE'\n{}\nLANTERN_RATE", commands.join("\n"))).await.map_err(|error| format!("Speed-cap write failed or is unknown. Netdev ingress/egress support is required; inspect limits before retrying. {error}"))?;
    }
    let after = status(config).await?;
    let actual = after.iter().find(|entry| entry.mac == mac);
    if input.up_kbps == 0 {
        if actual.is_some() {
            return Err("Speed-cap removal could not be verified".into());
        }
    } else if !actual
        .is_some_and(|entry| entry.up_kbps == input.up_kbps && entry.down_kbps == input.down_kbps)
    {
        return Err("Speed-cap readback differs from the request".into());
    }
    for other in current.iter().filter(|entry| entry.mac != mac) {
        if !after.iter().any(|entry| {
            entry.mac == other.mac
                && entry.interface == other.interface
                && entry.up_kbps == other.up_kbps
                && entry.down_kbps == other.down_kbps
        }) {
            return Err(
                "Another device's speed cap changed concurrently; inspect gateway limits".into(),
            );
        }
    }
    Ok(
        json!({"outcome":"rate_policy_verified","limits":after,"message":if input.up_kbps == 0 {"Device speed cap removed and absence verified. Other limits were preserved."} else {"Both device rate policies installed and read back. Excess traffic is dropped above each byte budget, with a 16 KiB burst. Check counters and measured throughput; policies clear on gateway reboot."}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limit_requests_are_bounded_and_remove_both_directions() {
        for (up, down, valid) in [
            (0, 0, true),
            (64, 64, true),
            (10_000_000, 10_000_000, true),
            (0, 1000, false),
            (63, 1000, false),
            (1000, 10_000_001, false),
        ] {
            let input = LimitInput {
                mac: "02:00:00:00:00:01".into(),
                up_kbps: up,
                down_kbps: down,
            };
            assert_eq!(input.validate().is_ok(), valid);
        }
        assert!(interface_name("br-lan;reboot").is_err());
        assert!(interface_name("..").is_err());
    }
}
