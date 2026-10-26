use crate::{
    limits,
    model::{Result, RouterConfig, RouterKind, mac_address},
    router::ssh,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DIR: &str = "/tmp/lantern_latency_v1";
const OWNER: &str = "Lantern latency v1";
const MAP: &str = "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelayInput {
    pub mac: String,
    pub delay_ms: u32,
    pub jitter_ms: u32,
}
impl DelayInput {
    pub fn validate(&self) -> Result<String> {
        let mac = mac_address(&self.mac)?;
        if self.delay_ms > 2000 || self.jitter_ms > self.delay_ms {
            return Err("Delay must be 0–2000 ms and jitter must not exceed delay".into());
        }
        Ok(mac)
    }
}

#[derive(Clone, Serialize)]
pub struct Delay {
    pub mac: String,
    pub interface: String,
    pub delay_ms: u32,
    pub jitter_ms: u32,
    pub packets: u64,
    pub drops: u64,
    #[serde(skip)]
    band: u8,
}

fn check_gateway(config: &RouterConfig) -> Result<()> {
    if !matches!(config.kind, RouterKind::Openwrt) {
        return Err("Device delay requires an OpenWrt gateway in the traffic path; this Movistar firmware has no verified delay control.".into());
    }
    Ok(())
}
fn encoded(interface: &str) -> String {
    interface.bytes().map(|b| format!("{b:02x}")).collect()
}
fn decode(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 30
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("Invalid latency ownership marker".into());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| "Invalid latency marker"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let interface = String::from_utf8(bytes).map_err(|_| "Invalid latency interface")?;
    limits::interface_name(&interface)?;
    Ok(interface)
}
async fn qdiscs(config: &RouterConfig, interface: &str) -> Result<Vec<Value>> {
    serde_json::from_str(&ssh(config, &format!("tc -j -s qdisc show dev {interface}")).await?)
        .map_err(|_| "OpenWrt needs tc-full with JSON support".into())
}
async fn inspect(config: &RouterConfig, interface: &str) -> Result<Vec<Delay>> {
    let qdiscs = qdiscs(config, interface).await?;
    let roots: Vec<_> = qdiscs.iter().filter(|q| q["root"] == true).collect();
    if roots.len() != 1
        || roots[0]["kind"] != "prio"
        || roots[0]["handle"] != "ca71:"
        || roots[0]["options"]["bands"] != 16
        || roots[0]["options"]["priomap"]
            .as_array()
            .is_none_or(|a| a.len() != 16 || a.iter().any(|v| v != 0))
    {
        return Err("Latency queue ownership or configuration cannot be verified".into());
    }
    let mut children = std::collections::BTreeMap::new();
    for q in &qdiscs {
        let Some(parent) = q["parent"].as_str() else {
            continue;
        };
        let Some(band) = parent
            .strip_prefix("ca71:")
            .and_then(|s| u8::from_str_radix(s, 16).ok())
        else {
            continue;
        };
        if !(2..=16).contains(&band)
            || q["kind"] != "netem"
            || q["handle"] != format!("{:x}:", 0xca70 + u32::from(band))
            || q["options"]["limit"] != 1000
            || q["options"]["ecn"] != false
            || q["options"]["gap"] != 0
            || q["options"]["delay"]["correlation"] != 0
        {
            return Err("Unrecognized latency queue; refusing to change it".into());
        }
        let delay = q["options"]["delay"]["delay"]
            .as_f64()
            .ok_or("Invalid delay")?;
        let jitter = q["options"]["delay"]["jitter"]
            .as_f64()
            .ok_or("Invalid jitter")?;
        let delay_ms = (delay * 1000.0).round() as u32;
        let jitter_ms = (jitter * 1000.0).round() as u32;
        if delay_ms == 0
            || delay_ms > 2000
            || jitter_ms > delay_ms
            || q["options"].as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !["limit", "delay", "ecn", "gap"].contains(&k.as_str()))
            })
            || children
                .insert(
                    band,
                    (
                        delay_ms,
                        jitter_ms,
                        q["packets"].as_u64().unwrap_or(0),
                        q["drops"].as_u64().unwrap_or(0),
                    ),
                )
                .is_some()
        {
            return Err("Unrecognized latency settings".into());
        }
    }
    let filters: Vec<Value> = serde_json::from_str(
        &ssh(
            config,
            &format!("tc -j -s filter show dev {interface} parent ca71:"),
        )
        .await?,
    )
    .map_err(|_| "Invalid latency filter readback")?;
    let mut result = Vec::new();
    for f in filters {
        let pref = f["pref"].as_u64().ok_or("Invalid latency filter")?;
        if f["kind"] != "flower"
            || f["protocol"] != "all"
            || f["chain"] != 0
            || !(1002..=1016).contains(&pref)
        {
            return Err("Unrecognized latency filter; refusing to change it".into());
        }
        let Some(options) = f.get("options") else {
            continue;
        };
        let band = (pref - 1000) as u8;
        if options.as_object().is_none_or(|object| {
            object.keys().any(|key| {
                ![
                    "handle",
                    "classid",
                    "keys",
                    "not_in_hw",
                    "in_hw",
                    "in_hw_count",
                ]
                .contains(&key.as_str())
            })
        }) || options["classid"] != format!("ca71:{band:x}")
            || options["keys"]
                .as_object()
                .is_none_or(|keys| keys.len() != 1 || !keys.contains_key("dst_mac"))
        {
            return Err("Unrecognized latency filter settings".into());
        }
        let mac = mac_address(
            options["keys"]["dst_mac"]
                .as_str()
                .ok_or("Missing latency MAC")?,
        )?;
        let (delay_ms, jitter_ms, packets, drops) = children
            .remove(&band)
            .ok_or("Latency filter has no matching queue")?;
        if result.iter().any(|d: &Delay| d.mac == mac) {
            return Err("Duplicate latency policy".into());
        }
        result.push(Delay {
            mac,
            interface: interface.into(),
            delay_ms,
            jitter_ms,
            packets,
            drops,
            band,
        });
    }
    if !children.is_empty() {
        return Err(
            "Latency queue has no matching filter; inspect it before changing anything".into(),
        );
    }
    Ok(result)
}
pub async fn status(config: &RouterConfig) -> Result<Vec<Delay>> {
    check_gateway(config)?;
    let files = ssh(config, &format!("if [ -L {DIR} ]; then exit 1; fi; if [ -d {DIR} ]; then for f in {DIR}/*; do [ -e \"$f\" ] || continue; [ -f \"$f\" ] && [ ! -L \"$f\" ] && [ \"$(cat \"$f\")\" = '{OWNER}' ] || exit 1; basename \"$f\"; done; fi")).await?;
    let mut all = Vec::new();
    for name in files.lines() {
        all.extend(inspect(config, &decode(name)?).await?);
    }
    Ok(all)
}
pub async fn set(config: &RouterConfig, input: &DelayInput, ip: Option<&str>) -> Result<Value> {
    check_gateway(config)?;
    let mac = input.validate()?;
    let before = status(config).await?;
    let existing = before.iter().find(|d| d.mac == mac);
    if input.delay_ms == 0 && existing.is_none() {
        return Ok(
            json!({"policies":before,"message":"No Lantern delay is installed for this device."}),
        );
    }
    let interface = if input.delay_ms > 0 {
        limits::offload_check(config).await?;
        let interface = limits::direct_interface(config, ip, &mac).await?;
        if existing.is_some_and(|d| d.interface != interface) {
            return Err("Device moved interfaces; remove its previous delay first".into());
        }
        interface
    } else {
        existing.ok_or("Missing delay")?.interface.clone()
    };
    let marker = format!("{DIR}/{}", encoded(&interface));
    let owned = before.iter().any(|d| d.interface == interface);
    if !owned && input.delay_ms > 0 {
        let queues = qdiscs(config, &interface).await?;
        let roots: Vec<_> = queues.iter().filter(|q| q["root"] == true).collect();
        if roots.len() != 1 || roots[0]["kind"] != "noqueue" {
            return Err("This LAN interface already has a root queue. Lantern will not replace it; remove or manage that queue separately.".into());
        }
        ssh(config, &format!("[ ! -L {DIR} ] && {{ [ -d {DIR} ] || mkdir -m 700 {DIR}; }} && [ ! -e {marker} ] && [ ! -L {marker} ] && (set -C; printf '%s\\n' '{OWNER}' > {marker}) && {{ tc qdisc add dev {interface} root handle ca71: prio bands 16 priomap {MAP} || {{ rm -f {marker}; exit 1; }}; }}")).await.map_err(|e| format!("Could not install latency queue; inspect gateway before retrying. {e}"))?;
    }
    let band = if let Some(d) = existing {
        d.band
    } else {
        (2..=16)
            .find(|band| {
                !before
                    .iter()
                    .any(|d| d.interface == interface && d.band == *band)
            })
            .ok_or("A LAN interface supports at most 15 delayed devices")?
    };
    let parent = format!("ca71:{band:x}");
    let handle = format!("{:x}:", 0xca70 + u32::from(band));
    let command = if input.delay_ms == 0 {
        format!(
            "tc filter del dev {interface} parent ca71: protocol all pref {} && tc qdisc del dev {interface} parent {parent}",
            1000 + u32::from(band)
        )
    } else if existing.is_some() {
        format!(
            "tc qdisc change dev {interface} parent {parent} handle {handle} netem delay {}ms {}ms limit 1000",
            input.delay_ms, input.jitter_ms
        )
    } else {
        format!(
            "tc qdisc add dev {interface} parent {parent} handle {handle} netem delay {}ms {}ms limit 1000 && {{ tc filter add dev {interface} parent ca71: protocol all pref {} flower dst_mac {mac} classid {parent} || {{ tc qdisc del dev {interface} parent {parent}; exit 1; }}; }}",
            input.delay_ms,
            input.jitter_ms,
            1000 + u32::from(band)
        )
    };
    ssh(config,&command).await.map_err(|e| format!("Latency change failed or its outcome is unknown. Inspect the gateway before retrying. {e}"))?;
    let after = status(config).await?;
    let actual = after.iter().find(|d| d.mac == mac);
    if (input.delay_ms == 0 && actual.is_some())
        || (input.delay_ms > 0
            && !actual
                .is_some_and(|d| d.delay_ms == input.delay_ms && d.jitter_ms == input.jitter_ms))
    {
        return Err("Latency readback differs from the request".into());
    }
    for d in before.iter().filter(|d| d.mac != mac) {
        if !after.iter().any(|a| {
            a.mac == d.mac
                && a.interface == d.interface
                && a.delay_ms == d.delay_ms
                && a.jitter_ms == d.jitter_ms
        }) {
            return Err("Another latency policy changed; inspect the gateway".into());
        }
    }
    if input.delay_ms == 0 && !after.iter().any(|d| d.interface == interface) {
        ssh(
            config,
            &format!("tc qdisc del dev {interface} root && rm -f {marker}"),
        )
        .await
        .map_err(|e| format!("Delay removed, but empty queue cleanup is unknown: {e}"))?;
    }
    Ok(
        json!({"policies":after,"message":if input.delay_ms == 0 {"Device delay removed and verified."} else {"Device delay installed and verified. Actual ping varies; the policy clears on gateway reboot."}}),
    )
}
