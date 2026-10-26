use crate::{
    latency, limits,
    model::{Result, RouterConfig, RouterKind, mac_address},
    router::ssh,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DIR: &str = "/tmp/lantern_spike_v1";
const OWNER: &str = "Lantern spike v1";
const MAP: &str = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpikeInput {
    pub mac: String,
    pub delay_ms: u32,
    pub jitter_ms: u32,
    pub duration_s: u32,
}
impl SpikeInput {
    pub fn validate(&self) -> Result<String> {
        let mac = mac_address(&self.mac)?;
        if !(1..=2000).contains(&self.delay_ms)
            || self.jitter_ms > self.delay_ms
            || !(5..=600).contains(&self.duration_s)
        {
            return Err("Set delay to 1–2000 ms, jitter no greater than delay, and duration to 5–600 seconds".into());
        }
        Ok(mac)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacInput {
    pub mac: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceInput {
    pub interface: String,
}

#[derive(Serialize)]
pub struct Spike {
    pub interface: String,
    pub mac: Option<String>,
    pub remaining_s: Option<u64>,
    pub delay_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub table_present: bool,
    pub queue_present: bool,
}

fn gateway(config: &RouterConfig) -> Result<()> {
    if !matches!(config.kind, RouterKind::Openwrt) {
        return Err("A temporary ping increase requires an OpenWrt gateway in the traffic path. This Movistar firmware has no verified delay control.".into());
    }
    Ok(())
}
fn table_name(interface: &str) -> String {
    format!("lantern_spike_{}", latency::encoded(interface))
}
fn marker(interface: &str) -> String {
    format!("{DIR}/{}", latency::encoded(interface))
}

async fn marker_exists(config: &RouterConfig, interface: &str) -> Result<bool> {
    let file = marker(interface);
    let response = ssh(config, &format!("if [ -L {DIR} ] || [ -L {file} ]; then exit 1; fi; if [ -e {file} ]; then [ -f {file} ] && [ \"$(cat {file})\" = '{OWNER}' ] || exit 1; printf 'owned'; fi")).await?;
    Ok(response.trim() == "owned")
}
async fn queue(config: &RouterConfig, interface: &str) -> Result<(bool, Option<(u32, u32)>)> {
    let qdiscs = latency::qdiscs(config, interface).await?;
    let roots: Vec<_> = qdiscs.iter().filter(|q| q["root"] == true).collect();
    if roots.len() != 1 {
        return Err("Cannot verify the LAN root queue".into());
    }
    if roots[0]["kind"] == "noqueue" {
        return Ok((false, None));
    }
    if roots[0]["kind"] != "prio"
        || roots[0]["handle"] != "ca81:"
        || roots[0]["options"]["bands"] != 3
        || roots[0]["options"]["priomap"]
            .as_array()
            .is_none_or(|a| a.len() != 16 || a.iter().any(|v| v != 0))
    {
        return Err(
            "This LAN interface already has a different root queue; Lantern will not replace it"
                .into(),
        );
    }
    let filters: Vec<Value> = serde_json::from_str(
        &ssh(
            config,
            &format!("tc -j filter show dev {interface} parent ca81:"),
        )
        .await?,
    )
    .map_err(|_| "Invalid lag queue filters")?;
    if !filters.is_empty() {
        return Err("The lag queue contains unrecognized filters".into());
    }
    let mut delay = None;
    for q in &qdiscs {
        let Some(parent) = q["parent"].as_str() else {
            continue;
        };
        if !parent.starts_with("ca81:") {
            continue;
        }
        if parent != "ca81:2"
            || q["kind"] != "netem"
            || q["handle"] != "ca82:"
            || q["options"]["limit"] != 1000
            || q["options"]["ecn"] != false
            || q["options"]["gap"] != 0
            || q["options"]["delay"]["correlation"] != 0
            || q["options"].as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !["limit", "delay", "ecn", "gap"].contains(&k.as_str()))
            })
        {
            return Err("The lag queue has unrecognized settings".into());
        }
        let ms = (q["options"]["delay"]["delay"]
            .as_f64()
            .ok_or("Invalid delay")?
            * 1000.0)
            .round() as u32;
        let jitter = (q["options"]["delay"]["jitter"]
            .as_f64()
            .ok_or("Invalid jitter")?
            * 1000.0)
            .round() as u32;
        if ms == 0 || ms > 2000 || jitter > ms || delay.replace((ms, jitter)).is_some() {
            return Err("Invalid lag queue delay".into());
        }
    }
    Ok((true, delay))
}
async fn table(
    config: &RouterConfig,
    interface: &str,
) -> Result<Option<(Option<String>, Option<u64>)>> {
    let name = table_name(interface);
    let tables: Value = serde_json::from_str(&ssh(config, "nft -j list tables").await?)
        .map_err(|_| "Invalid gateway table list")?;
    let exists = tables["nftables"]
        .as_array()
        .ok_or("Gateway omitted its tables")?
        .iter()
        .any(|item| item["table"]["family"] == "netdev" && item["table"]["name"] == name);
    if !exists {
        return Ok(None);
    }
    let value: Value =
        serde_json::from_str(&ssh(config, &format!("nft -j list table netdev {name}")).await?)
            .map_err(|_| "Invalid lag table")?;
    let items = value["nftables"]
        .as_array()
        .ok_or("Gateway omitted lag objects")?;
    let objects: Vec<_> = items
        .iter()
        .filter(|item| item.get("metainfo").is_none())
        .collect();
    if objects.len() != 4 {
        return Err("Lag table contains unexpected objects".into());
    }
    let owned = objects.iter().any(|item| {
        item["table"]["name"] == name
            && item["table"]["family"] == "netdev"
            && item["table"]["comment"] == OWNER
    });
    let sets: Vec<_> = objects.iter().filter_map(|item| item.get("set")).collect();
    let chains: Vec<_> = objects
        .iter()
        .filter_map(|item| item.get("chain"))
        .collect();
    let rules: Vec<_> = objects.iter().filter_map(|item| item.get("rule")).collect();
    if !owned
        || sets.len() != 1
        || chains.len() != 1
        || rules.len() != 1
        || sets[0]["name"] != "targets"
        || sets[0]["type"] != "ether_addr"
        || sets[0]["flags"] != json!(["timeout"])
        || chains[0]["name"] != "egress"
        || chains[0]["type"] != "filter"
        || chains[0]["hook"] != "egress"
        || chains[0]["prio"] != -10
        || chains[0]["policy"] != "accept"
        || rules[0]["chain"] != "egress"
    {
        return Err("Lag table ownership or configuration cannot be verified".into());
    }
    let expr = rules[0]["expr"].as_array().ok_or("Invalid lag rule")?;
    if expr.len() != 2
        || expr[0]["match"]["op"] != "=="
        || expr[0]["match"]["left"]["payload"]["protocol"] != "ether"
        || expr[0]["match"]["left"]["payload"]["field"] != "daddr"
        || expr[0]["match"]["right"] != "@targets"
        || expr[1]["mangle"]["key"]["meta"]["key"] != "priority"
        || expr[1]["mangle"]["value"] != "ca81:2"
    {
        return Err("Lag rule has an unrecognized match or action".into());
    }
    let chain = ssh(config, &format!("nft -a list chain netdev {name} egress")).await?;
    if !chain.contains(&format!("hook egress device \"{interface}\"")) {
        return Err("Lag rule is not bound to the expected interface".into());
    }
    let elements = match sets[0].get("elem") {
        Some(value) => value.as_array().ok_or("Invalid lag target list")?.clone(),
        None => Vec::new(),
    };
    if elements.len() > 1 {
        return Err("Lag set has unexpected targets".into());
    }
    if let Some(element) = elements.first() {
        let element = &element["elem"];
        let mac = mac_address(element["val"].as_str().ok_or("Lag target is missing")?)?;
        let remaining = element["expires"]
            .as_u64()
            .ok_or("Lag target has no expiry")?;
        let duration = element["timeout"]
            .as_u64()
            .ok_or("Lag target has no timeout")?;
        if duration == 0 || duration > 600 || remaining > duration {
            return Err("Invalid lag expiration".into());
        }
        Ok(Some((Some(mac), Some(remaining))))
    } else {
        Ok(Some((None, None)))
    }
}
async fn inspect(config: &RouterConfig, interface: &str) -> Result<Spike> {
    limits::interface_name(interface)?;
    if !marker_exists(config, interface).await? {
        return Err("Lag queue ownership marker is missing".into());
    }
    let (queue_present, delay) = queue(config, interface).await?;
    let policy = table(config, interface).await?;
    if policy.is_some() && delay.is_none() {
        return Err("Lag policy exists without its queue".into());
    }
    let (mac, remaining_s) = policy.clone().unwrap_or((None, None));
    Ok(Spike {
        interface: interface.into(),
        mac,
        remaining_s,
        delay_ms: delay.map(|d| d.0),
        jitter_ms: delay.map(|d| d.1),
        table_present: policy.is_some(),
        queue_present,
    })
}
pub async fn status(config: &RouterConfig) -> Result<Vec<Spike>> {
    gateway(config)?;
    let files = ssh(config,&format!("if [ -L {DIR} ]; then exit 1; fi; if [ -d {DIR} ]; then for f in {DIR}/*; do [ -e \"$f\" ] || continue; [ -f \"$f\" ] && [ ! -L \"$f\" ] && [ \"$(cat \"$f\")\" = '{OWNER}' ] || exit 1; basename \"$f\"; done; fi")).await?;
    let mut spikes = Vec::new();
    for name in files.lines() {
        spikes.push(inspect(config, &latency::decode(name)?).await?);
    }
    Ok(spikes)
}
pub async fn start(config: &RouterConfig, input: &SpikeInput, ip: Option<&str>) -> Result<Value> {
    gateway(config)?;
    let mac = input.validate()?;
    limits::offload_check(config).await?;
    let interface = limits::direct_interface(config, ip, &mac).await?;
    let name = table_name(&interface);
    let file = marker(&interface);
    let owned = marker_exists(config, &interface).await?;
    if !owned {
        if table(config, &interface).await?.is_some() {
            return Err("Refusing a lag table without its queue ownership marker".into());
        }
        let qdiscs = latency::qdiscs(config, &interface).await?;
        let roots: Vec<_> = qdiscs.iter().filter(|q| q["root"] == true).collect();
        if roots.len() != 1 || roots[0]["kind"] != "noqueue" {
            return Err(
                "This LAN interface already has a root queue; Lantern will not replace it".into(),
            );
        }
        ssh(config,&format!("[ ! -L {DIR} ] && {{ [ -d {DIR} ] || mkdir -m 700 {DIR}; }} && [ ! -e {file} ] && [ ! -L {file} ] && (set -C; printf '%s\\n' '{OWNER}' > {file}) && {{ tc qdisc add dev {interface} root handle ca81: prio bands 3 priomap {MAP} || {{ rm -f {file}; exit 1; }}; }}")).await.map_err(|e| format!("Could not prepare lag queue; inspect it before retrying. {e}"))?;
    }
    let before = inspect(config, &interface).await?;
    if !before.queue_present {
        return Err("The lag queue was not installed. Release its marker before retrying.".into());
    }
    if before.mac.is_some() {
        return Err(
            "A lag spike is already active on this LAN interface; wait or stop it first".into(),
        );
    }
    let verb = if before.delay_ms.is_some() {
        "change"
    } else {
        "add"
    };
    ssh(config,&format!("tc qdisc {verb} dev {interface} parent ca81:2 handle ca82: netem delay {}ms {}ms limit 1000",input.delay_ms,input.jitter_ms)).await.map_err(|e| format!("Lag queue update failed or is unknown; inspect before retrying. {e}"))?;
    let script = if before.table_present {
        format!(
            "add element netdev {name} targets {{ {mac} timeout {}s }}",
            input.duration_s
        )
    } else {
        format!(
            "create table netdev {name} {{ comment \"{OWNER}\"; }}\nadd set netdev {name} targets {{ type ether_addr; flags timeout; }}\nadd chain netdev {name} egress {{ type filter hook egress device \"{interface}\" priority -10; policy accept; }}\nadd rule netdev {name} egress ether daddr @targets meta priority set 0xca810002\nadd element netdev {name} targets {{ {mac} timeout {}s }}",
            input.duration_s
        )
    };
    ssh(
        config,
        &format!("nft -f - <<'LANTERN_SPIKE'\n{script}\nLANTERN_SPIKE"),
    )
    .await
    .map_err(|e| format!("Lag spike write failed or is unknown; inspect before retrying. {e}"))?;
    let after = inspect(config, &interface).await?;
    if after.mac.as_deref() != Some(mac.as_str())
        || after.delay_ms != Some(input.delay_ms)
        || after.jitter_ms != Some(input.jitter_ms)
    {
        return Err("Lag spike could not be verified; it may already have expired".into());
    }
    Ok(
        json!({"spikes":status(config).await?,"message":"Timed lag policy installed and read back. The gateway expires it automatically; actual ping varies."}),
    )
}
pub async fn stop(config: &RouterConfig, mac: &str) -> Result<Value> {
    gateway(config)?;
    let mac = mac_address(mac)?;
    let before = status(config).await?;
    if let Some(spike) = before
        .iter()
        .find(|s| s.mac.as_deref() == Some(mac.as_str()))
    {
        let name = table_name(&spike.interface);
        if let Err(error) = ssh(
            config,
            &format!("nft delete element netdev {name} targets {{ {mac} }}"),
        )
        .await
            && status(config)
                .await?
                .iter()
                .any(|s| s.mac.as_deref() == Some(mac.as_str()))
        {
            return Err(format!("Lag stop failed or is unknown: {error}"));
        }
    }
    let after = status(config).await?;
    if after.iter().any(|s| s.mac.as_deref() == Some(mac.as_str())) {
        return Err("Lag spike removal was not verified".into());
    }
    Ok(json!({"spikes":after,"message":"Temporary ping increase stopped or already expired."}))
}
pub async fn release(config: &RouterConfig, interface: &str) -> Result<Value> {
    gateway(config)?;
    let interface = limits::interface_name(interface)?;
    let current = inspect(config, interface).await?;
    if current.mac.is_some() {
        return Err("Stop the active lag spike before releasing its queue".into());
    }
    let name = table_name(interface);
    let file = marker(interface);
    if current.table_present {
        ssh(config, &format!("nft delete table netdev {name}")).await?;
    }
    if current.queue_present {
        ssh(config, &format!("tc qdisc del dev {interface} root")).await?;
    }
    ssh(config, &format!("rm -f {file}")).await?;
    Ok(json!({"spikes":status(config).await?,"message":"The inactive lag queue was released."}))
}
