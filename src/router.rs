use crate::{
    discovery::{command_output, parse_neighbors},
    model::{Device, Result, RouterConfig, RouterKind, mac_address},
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::process::Command;

const TABLE: &str = "lantern_v1";
const OWNER: &str = "Managed by Lantern v1";

async fn ssh(config: &RouterConfig, script: &str) -> Result<String> {
    config.validate()?;
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=3",
        "-o",
        "ServerAliveCountMax=2",
        &format!("{}@{}", config.user, config.host),
        script,
    ]);
    command_output(cmd).await
}

pub async fn devices(config: &RouterConfig) -> Result<Vec<Device>> {
    config.validate()?;
    match config.kind {
        RouterKind::Openwrt => {
            let text = ssh(
                config,
                "cat /tmp/dhcp.leases; printf '\\nLANTERN_NEIGHBORS\\n'; ip -4 neigh show",
            )
            .await?;
            let (leases, neighbors) = text
                .split_once("LANTERN_NEIGHBORS")
                .ok_or("Unexpected gateway response")?;
            let mut found = parse_neighbors(neighbors, "OpenWrt neighbor cache");
            for line in leases.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    continue;
                }
                let Ok(mac) = mac_address(fields[1]) else {
                    continue;
                };
                let Ok(ip) = fields[2].parse::<std::net::Ipv4Addr>() else {
                    continue;
                };
                let name = if fields[3] == "*" {
                    "Unidentified device"
                } else {
                    fields[3]
                };
                found.retain(|d| d.mac != mac);
                found.push(Device {
                    mac,
                    ip: ip.to_string(),
                    name: name.chars().take(120).collect(),
                    source: "OpenWrt DHCP".into(),
                    presence: "Lease recorded".into(),
                    identity: Default::default(),
                });
            }
            Ok(found)
        }
        RouterKind::Movistar => movistar_devices(config).await,
    }
}

async fn response_text(mut response: reqwest::Response) -> Result<String> {
    if !response.status().is_success() {
        return Err(format!("Router returned HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Could not read router response")?
    {
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err("Router response exceeds 2 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| "Router returned invalid text".into())
}

async fn movistar_client(config: &RouterConfig) -> Result<(reqwest::Client, String)> {
    if config.password.is_empty() {
        return Err("Enter the router admin password; it stays in memory for this session".into());
    }
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let base = format!("http://{}", config.host);
    let encode = |s: &str| {
        s.chars()
            .map(|c| char::from_u32(u32::from(c) ^ 0x1f).unwrap_or(c))
            .collect::<String>()
    };
    // Protocol described by the GPL Movistar integration; see THIRD_PARTY.md.
    response_text(
        client
            .get(&base)
            .send()
            .await
            .map_err(|_| "Cannot reach the Movistar web interface")?,
    )
    .await?;
    response_text(
        client
            .post(format!("{base}/cgi-bin/te_acceso_router.cgi"))
            .form(&[
                ("loginUsername", encode("1234")),
                ("loginPassword", encode(&config.password)),
            ])
            .send()
            .await
            .map_err(|_| "Movistar login failed")?,
    )
    .await?;
    Ok((client, base))
}

async fn movistar_devices(config: &RouterConfig) -> Result<Vec<Device>> {
    let (client, base) = movistar_client(config).await?;
    let html = response_text(
        client
            .get(format!("{base}/te_mapa_red_local.asp"))
            .send()
            .await
            .map_err(|_| "Cannot read the Movistar device map")?,
    )
    .await?;
    parse_movistar_map(&html)
}

fn empty_form_post(client: &reqwest::Client, url: String) -> reqwest::RequestBuilder {
    // This firmware returns HTTP 400 for reqwest's default empty form request.
    client
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=UTF-8",
        )
        .header(reqwest::header::CONTENT_LENGTH, "0")
        .body("")
}

pub async fn movistar_information(config: &RouterConfig) -> Result<Value> {
    let (client, base) = movistar_client(config).await?;
    let mut diagnostics = Vec::<String>::new();
    let (summary, radio24, radio5) = tokio::join!(
        callback_xml(&client, &base, "cbGetSummary", None, 5),
        callback_xml(
            &client,
            &base,
            "cbListWifiAccPtAssociation",
            Some(&[("dpm_cfg_wifi_id", "0")]),
            25
        ),
        callback_xml(
            &client,
            &base,
            "cbListWifiAccPtAssociation",
            Some(&[("dpm_cfg_wifi_id", "1")]),
            25
        )
    );
    let summary = match summary {
        Ok(text) => Some(text),
        Err(error) => {
            diagnostics.push(format!("Firmware request failed: {error}"));
            None
        }
    };
    let (firmware, model) = summary
        .as_deref()
        .and_then(|xml| match roxmltree::Document::parse(xml) {
            Ok(document) => Some(document),
            Err(error) => {
                diagnostics.push(format!("Firmware XML could not be parsed: {error}"));
                None
            }
        })
        .map(|document| {
            let value = |tag: &str| {
                document
                    .descendants()
                    .find(|node| node.has_tag_name(tag))
                    .and_then(|node| node.text())
                    .map(|text| text.chars().take(160).collect::<String>())
            };
            (value("SWVersion"), value("ModelName"))
        })
        .unwrap_or_default();
    if firmware.is_none() {
        diagnostics.push("Firmware summary did not expose a version in this session".into());
    }
    let mut stations = Vec::new();
    let mut radios_read = 0;
    for (radio, response) in [("2.4 GHz", radio24), ("5 GHz", radio5)] {
        let xml = match response {
            Ok(xml) => xml,
            Err(error) => {
                diagnostics.push(format!(
                    "Could not read {radio} client associations: {error}"
                ));
                continue;
            }
        };
        let Ok(document) = roxmltree::Document::parse(&xml) else {
            diagnostics.push(format!("Invalid {radio} association response"));
            continue;
        };
        let success = document
            .descendants()
            .any(|node| node.has_tag_name("Result") && node.text() == Some("0"));
        if !success {
            diagnostics.push(format!("Router rejected {radio} association lookup"));
            continue;
        }
        radios_read += 1;
        for group in document
            .descendants()
            .filter(|node| node.has_tag_name("wifi_association_group"))
        {
            let ssid = group
                .children()
                .find(|node| node.has_tag_name("ssid"))
                .and_then(|node| node.text())
                .unwrap_or("")
                .chars()
                .take(120)
                .collect::<String>();
            for station in group
                .descendants()
                .filter(|node| node.has_tag_name("rtm_cfg_wifi_association"))
            {
                let value = |tag: &str| {
                    station
                        .children()
                        .find(|node| node.has_tag_name(tag))
                        .and_then(|node| node.text())
                };
                if let Some(mac) = value("mac_addr").and_then(|value| mac_address(value).ok()) {
                    stations.push(json!({"mac":mac,"radio":radio,"ssid":ssid,"authorized":value("is_auth")==Some("1"),"signal_dbm":value("uplink_pwr").and_then(|value|value.parse::<i32>().ok())}));
                }
            }
        }
    }
    Ok(
        json!({"firmware":firmware,"model":model,"stations":stations,"radios_read":radios_read,"diagnostics":diagnostics}),
    )
}

async fn callback_xml(
    client: &reqwest::Client,
    base: &str,
    callback: &str,
    fields: Option<&[(&str, &str)]>,
    seconds: u64,
) -> Result<String> {
    let url = format!("{base}/cgi-bin/{callback}.xml");
    let request = if let Some(fields) = fields {
        client.post(url).form(fields)
    } else {
        empty_form_post(client, url)
    };
    let response = request
        .timeout(Duration::from_secs(seconds))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    response_text(response).await
}

fn parse_movistar_map(html: &str) -> Result<Vec<Device>> {
    let value = html
        .split_once("deviceData")
        .and_then(|(_, tail)| tail.split_once('='))
        .map(|(_, tail)| tail.trim_start())
        .ok_or("Device map unavailable: check password and firmware compatibility")?;
    // Find the array boundary without evaluating JavaScript or stripping escapes.
    let mut depth = 0_u32;
    let mut quote = None;
    let mut escaped = false;
    let mut end = None;
    if !value.starts_with('[') {
        return Err("Unsupported Movistar map format".into());
    }
    for (index, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '[' => depth += 1,
            ']' => {
                depth = depth.checked_sub(1).ok_or("Invalid array")?;
                if depth == 0 {
                    end = Some(index + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let rows: Vec<Vec<Value>> = json5::from_str(&value[..end.ok_or("Incomplete device map")?])
        .map_err(|_| "Unsupported Movistar device-map encoding")?;
    let mut devices = Vec::new();
    for row in rows {
        if row.len() < 7 || row[0].as_str() != Some("1") {
            continue;
        }
        let Some(raw_mac) = row[6].as_str() else {
            continue;
        };
        let Ok(mac) = mac_address(raw_mac) else {
            continue;
        };
        let Some(ip) = row[3]
            .as_str()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        else {
            continue;
        };
        devices.push(Device {
            mac,
            ip: ip.to_string(),
            name: row[1]
                .as_str()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or("Unidentified device")
                .chars()
                .take(120)
                .collect(),
            source: "Movistar device map".into(),
            presence: "Reported by router".into(),
            identity: Default::default(),
        });
    }
    Ok(devices)
}

fn openwrt_only(config: &RouterConfig) -> Result<()> {
    if matches!(config.kind, RouterKind::Movistar) {
        return Err("Automatic Movistar enforcement is unavailable for this firmware. Use the router's own access controls.".into());
    }
    Ok(())
}

async fn table(config: &RouterConfig) -> Result<Value> {
    let text = ssh(config, &format!("nft -j list table inet {TABLE}")).await?;
    let value: Value = serde_json::from_str(&text).map_err(|_| "Invalid nftables response")?;
    let owned = value["nftables"]
        .as_array()
        .is_some_and(|items| items.iter().any(|i| i["table"]["comment"] == OWNER));
    if !owned {
        return Err(
            "Refusing to change an nftables table without Lantern's ownership marker".into(),
        );
    }
    Ok(value)
}

pub async fn rule_status(config: &RouterConfig) -> Result<Value> {
    openwrt_only(config)?;
    let all: Value = serde_json::from_str(&ssh(config, "nft -j list tables").await?)
        .map_err(|_| "Invalid nftables response")?;
    let exists = all["nftables"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|i| i["table"]["name"] == TABLE && i["table"]["family"] == "inet")
    });
    if !exists {
        return Ok(json!({"rules": [], "message": "No Lantern rules installed"}));
    }
    let loaded = table(config).await?;
    let items = loaded["nftables"]
        .as_array()
        .ok_or("Gateway omitted nftables objects")?;
    let forward_hook_verified = items.iter().any(|item| {
        let chain = &item["chain"];
        chain["name"] == "forward"
            && chain["type"] == "filter"
            && chain["hook"] == "forward"
            && chain["prio"] == -10
            && chain["policy"] == "accept"
    });
    Ok(
        json!({"rules": items.iter().filter_map(|i| i.get("rule")).collect::<Vec<_>>(),
        "forward_hook_verified": forward_hook_verified,
        "message": "Read back from gateway; counters are evidence of dropped traffic, not Wi-Fi disconnection"}),
    )
}

fn is_forwarding_drop(rule: &Value, mac: &str) -> bool {
    let Some(expressions) = rule["expr"].as_array() else {
        return false;
    };
    rule["chain"] == "forward"
        && expressions.len() == 3
        && expressions.iter().any(|expression| {
            let condition = &expression["match"];
            condition["op"] == "=="
                && condition["left"]["payload"]["protocol"] == "ether"
                && condition["left"]["payload"]["field"] == "saddr"
                && condition["right"]
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case(mac))
        })
        && expressions
            .iter()
            .any(|expression| expression.get("counter").is_some())
        && expressions
            .last()
            .is_some_and(|expression| expression.get("drop").is_some())
}

pub async fn block(config: &RouterConfig, mac: &str, blocked: bool) -> Result<Value> {
    openwrt_only(config)?;
    let mac = mac_address(mac)?;
    let status = rule_status(config).await?;
    let existing = status["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["comment"].as_str() == Some(&format!("lantern:{mac}")))
        .cloned();
    if blocked && existing.is_none() {
        // A separate early forward chain catches established flows unless offloaded.
        // One nft batch makes creation + rule insertion atomic. Never flush other tables.
        let script = format!(
            "nft -f - <<'LANTERN_NFT'\nadd table inet {TABLE} {{ comment \"{OWNER}\"; }}\nadd chain inet {TABLE} forward {{ type filter hook forward priority -10; policy accept; }}\nadd rule inet {TABLE} forward ether saddr {mac} counter drop comment \"lantern:{mac}\"\nLANTERN_NFT"
        );
        ssh(config, &script).await?;
    } else if !blocked && let Some(rule) = existing {
        let handle = rule["handle"]
            .as_u64()
            .ok_or("Gateway omitted rule handle")?;
        ssh(
            config,
            &format!("nft delete rule inet {TABLE} forward handle {handle}"),
        )
        .await?;
    }
    let observed = rule_status(config).await.map_err(|_| "Write attempted, but gateway readback failed. Outcome is unknown; refresh rules before retrying.")?;
    let present = observed["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| r["comment"].as_str() == Some(&format!("lantern:{mac}")));
    if present != blocked {
        return Err(
            "Gateway readback did not match the requested rule. Outcome is unknown.".into(),
        );
    }
    if blocked
        && (observed["forward_hook_verified"] != true
            || !observed["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|rule| {
                    rule["comment"].as_str() == Some(&format!("lantern:{mac}"))
                        && is_forwarding_drop(rule, &mac)
                }))
    {
        return Err("A rule with this marker exists, but its live match, drop action, or forward hook differs. Enforcement is unverified; inspect and remove the rule before retrying.".into());
    }
    Ok(
        json!({"outcome": "rule_verified", "message": if blocked {"Forwarding block installed and read back. Wi-Fi may remain connected; hardware-offloaded traffic may bypass this rule. Rules expire on reboot."} else {"Lantern forwarding rule removed and absence verified."}, "evidence": observed}),
    )
}

pub async fn kick(config: &RouterConfig, mac: &str) -> Result<Value> {
    openwrt_only(config)?;
    let mac = mac_address(mac)?;
    let services = ssh(config, "ubus -S list 'hostapd.*'").await?;
    let mut matched = Vec::new();
    for service in services.lines().filter(|s| {
        s.starts_with("hostapd.")
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    }) {
        let clients: Value =
            serde_json::from_str(&ssh(config, &format!("ubus call {service} get_clients")).await?)
                .map_err(|_| "Invalid hostapd response")?;
        if clients["clients"]
            .as_object()
            .is_some_and(|obj| obj.keys().any(|key| key.eq_ignore_ascii_case(&mac)))
        {
            matched.push(service.to_owned());
        }
    }
    if matched.is_empty() {
        return Err(
            "Device is not associated with this gateway's Wi-Fi radios; no disconnect was sent"
                .into(),
        );
    }
    for service in &matched {
        ssh(config, &format!("ubus call {service} del_client '{{\"addr\":\"{mac}\",\"deauth\":true,\"reason\":5,\"ban_time\":60000}}'")).await.map_err(|_| "Disconnect may be partially applied; refresh device status before retrying")?;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    for service in &matched {
        let response = ssh(config, &format!("ubus call {service} get_clients"))
            .await
            .map_err(|_| "Disconnect sent, but verification failed; outcome unknown")?;
        let clients: Value =
            serde_json::from_str(&response).map_err(|_| "Invalid verification response")?;
        let obj = clients["clients"]
            .as_object()
            .ok_or("Verification omitted client list")?;
        if obj.keys().any(|key| key.eq_ignore_ascii_case(&mac)) {
            return Err("Disconnect requested, but device is still associated".into());
        }
    }
    Ok(
        json!({"outcome":"disassociation_verified", "message":"Device absent from the affected radios after disconnect. Reconnection ban lasts 60 seconds; this is not a permanent block."}),
    )
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    #[test]
    fn empty_callbacks_include_the_length_required_by_actual_firmware() {
        let client = reqwest::Client::new();
        let request = empty_form_post(
            &client,
            "http://192.168.1.1/cgi-bin/cbGetSummary.xml".into(),
        )
        .build()
        .expect("build callback request");
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.headers()[reqwest::header::CONTENT_LENGTH], "0");
        assert_eq!(
            request.headers()[reqwest::header::CONTENT_TYPE],
            "application/x-www-form-urlencoded; charset=UTF-8"
        );
    }
}
