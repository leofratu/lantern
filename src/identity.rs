use crate::model::{Device, Result};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
};
use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout},
};

static VENDORS: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();

pub fn enrich(devices: &mut [Device]) {
    let vendors = VENDORS.get_or_init(|| {
        include_str!("../data/vendors.tsv")
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .collect()
    });
    for device in devices {
        let private = u8::from_str_radix(&device.mac[..2], 16).is_ok_and(|value| value & 2 != 0);
        device.identity.mac_kind = if private {
            "Locally administered / private"
        } else {
            "Globally assigned"
        }
        .into();
        let prefix = device.mac.replace(':', "").to_uppercase();
        if !private {
            device.identity.manufacturer = vendors.get(&prefix[..6]).map(|value| (*value).into());
            if device.identity.manufacturer.is_some() {
                device.identity.evidence.push("Network-interface manufacturer from the offline IEEE MA-L registry; this may differ from the device brand".into());
            }
        } else {
            device.identity.evidence.push(
                "Private or locally assigned MAC: manufacturer lookup is not reliable".into(),
            );
        }
        if device.name != "Unidentified device" {
            device.identity.display_name = Some(device.name.clone());
            device.identity.hostname = Some(device.name.clone());
            device
                .identity
                .evidence
                .push(format!("Name reported by {}", device.source));
        }
        classify(device);
    }
}

pub fn retain_observations(devices: &mut [Device], previous: &[Device]) {
    for device in devices {
        if let Some(old) = previous.iter().find(|old| {
            old.mac == device.mac
                && old.ip == device.ip
                && old.name == device.name
                && old.identity.inspected_at.is_some()
        }) {
            device.identity = old.identity.clone();
        }
    }
}

pub async fn inspect_inventory(devices: &mut [Device], gateway: Option<Ipv4Addr>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let mut jobs = tokio::task::JoinSet::new();
    let mut results = Vec::new();
    for device in devices.iter().take(32) {
        if device
            .identity
            .inspected_at
            .is_some_and(|at| now.saturating_sub(at) < 600)
        {
            continue;
        }
        let candidate = device.clone();
        jobs.spawn(async move {
            timeout(Duration::from_secs(5), inspect(candidate, gateway))
                .await
                .ok()
                .and_then(std::result::Result::ok)
        });
        if jobs.len() == 4 {
            let completed = jobs.join_next().await;
            if let Some(Ok(Some(result))) = completed {
                results.push(result);
            }
        }
    }
    while let Some(completed) = jobs.join_next().await {
        if let Ok(Some(result)) = completed {
            results.push(result);
        }
    }
    for result in results {
        if let Some(device) = devices
            .iter_mut()
            .find(|device| device.mac == result.mac && device.ip == result.ip)
        {
            *device = result;
        }
    }
}

async fn mdns_services(ip: Ipv4Addr) -> Vec<(String, String)> {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    if socket.connect((ip, 5353)).await.is_err() {
        return Vec::new();
    }
    let mut message = Message::new();
    let services = [
        "_device-info._tcp.local.",
        "_airplay._tcp.local.",
        "_googlecast._tcp.local.",
        "_ipp._tcp.local.",
        "_smb._tcp.local.",
        "_hap._tcp.local.",
    ];
    for service in services {
        let Ok(name) = Name::from_ascii(service) else {
            continue;
        };
        let mut query = Query::query(name, RecordType::PTR);
        query.set_mdns_unicast_response(true);
        message.add_query(query);
    }
    let Ok(bytes) = message.to_vec() else {
        return Vec::new();
    };
    if socket.send(&bytes).await.is_err() {
        return Vec::new();
    }
    let deadline = Instant::now() + Duration::from_millis(1000);
    let mut buffer = [0_u8; 16384];
    let mut found = Vec::new();
    while Instant::now() < deadline && found.len() < 40 {
        let Ok(Ok(length)) = tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await
        else {
            break;
        };
        let Ok(response) = Message::from_vec(&buffer[..length]) else {
            continue;
        };
        for record in response.answers().iter().chain(response.additionals()) {
            if !services
                .iter()
                .any(|service| record.name().to_utf8().to_lowercase().ends_with(service))
            {
                continue;
            }
            if let RData::TXT(txt) = record.data() {
                for entry in txt.txt_data().iter().take(20) {
                    if let Ok(entry) = std::str::from_utf8(entry)
                        && let Some((key, value)) = entry.split_once('=')
                        && let Some(value) = clean(value)
                    {
                        found.push((key.to_lowercase(), value));
                    }
                }
            }
            if let RData::PTR(ptr) = record.data() {
                found.push(("service".into(), ptr.0.to_utf8()));
            }
        }
    }
    found
}

fn classify(device: &mut Device) {
    let name = device
        .identity
        .hostname
        .as_deref()
        .unwrap_or(&device.name)
        .to_lowercase();
    let category = if name.contains("iphone") {
        "Phone (name suggests iPhone)"
    } else if name.contains("ipad") {
        "Tablet (name suggests iPad)"
    } else if name.contains("macbook") || name.contains("imac") {
        "Computer (name suggests Mac)"
    } else if name.contains("printer") || name.contains("epson") || name.contains("laserjet") {
        "Printer (name-based estimate)"
    } else if name.contains("chromecast") || name.contains("appletv") || name.contains("roku") {
        "Media device (name-based estimate)"
    } else {
        "Unknown device type"
    };
    device.identity.category = category.into();
}

fn clean(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    if value.is_empty() {
        None
    } else {
        Some(
            value
                .chars()
                .filter(|c| !c.is_control())
                .take(160)
                .collect(),
        )
    }
}

/// Resolve only the observed address; no subnet sweep or global inventory upload.
async fn reverse_name(ip: Ipv4Addr, resolver: Ipv4Addr, mdns: bool) -> Option<String> {
    let octets = ip.octets();
    let name = Name::from_ascii(format!(
        "{}.{}.{}.{}.in-addr.arpa.",
        octets[3], octets[2], octets[1], octets[0]
    ))
    .ok()?;
    let mut query = Query::query(name.clone(), RecordType::PTR);
    query.set_mdns_unicast_response(mdns);
    let mut message = Message::new();
    let id = if mdns {
        0
    } else {
        u16::from_be_bytes([octets[2], octets[3]])
    };
    message
        .set_id(id)
        .set_recursion_desired(!mdns)
        .add_query(query);
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket
        .connect((resolver, if mdns { 5353 } else { 53 }))
        .await
        .ok()?;
    socket.send(&message.to_vec().ok()?).await.ok()?;
    let mut buffer = [0_u8; 8192];
    let length = timeout(Duration::from_millis(900), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    let response = Message::from_vec(&buffer[..length]).ok()?;
    if response.id() != id {
        return None;
    }
    response.answers().iter().find_map(|record| {
        if record.name() != &name {
            return None;
        }
        match record.data() {
            RData::PTR(ptr) => clean(&ptr.0.to_utf8()),
            _ => None,
        }
    })
}

async fn bounded_text(mut response: reqwest::Response) -> Option<(String, Option<String>)> {
    if !response.status().is_success() {
        return None;
    }
    let server = response
        .headers()
        .get("server")
        .and_then(|h| h.to_str().ok())
        .and_then(clean);
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > 128 * 1024 {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    Some((String::from_utf8_lossy(&bytes).into_owned(), server))
}

async fn upnp_description(
    client: &reqwest::Client,
    ip: Ipv4Addr,
) -> Option<(String, Option<String>)> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect((ip, 1900)).await.ok()?;
    socket.send(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n").await.ok()?;
    let mut buffer = [0_u8; 8192];
    let length = timeout(Duration::from_millis(1400), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    let headers = std::str::from_utf8(&buffer[..length]).ok()?;
    let location = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))?
        .1
        .trim();
    let url = reqwest::Url::parse(location).ok()?;
    // An untrusted SSDP reply cannot redirect discovery to another host or credentialed URL.
    if url.scheme() != "http"
        || url.host_str() != Some(ip.to_string().as_str())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    bounded_text(client.get(url).send().await.ok()?).await
}

fn apply_description(device: &mut Device, xml: &str) {
    let Ok(document) = roxmltree::Document::parse(xml) else {
        return;
    };
    let Some(root) = document
        .descendants()
        .find(|node| node.has_tag_name("device"))
    else {
        return;
    };
    let value = |tag: &str| {
        root.children()
            .find(|node| node.has_tag_name(tag))
            .and_then(|node| node.text())
            .and_then(clean)
    };
    if let Some(name) = value("friendlyName")
        && device.name == "Unidentified device"
    {
        device.identity.display_name = Some(name);
    }
    if let Some(brand) = value("manufacturer") {
        device
            .identity
            .evidence
            .push(format!("Device advertises manufacturer: {brand}"));
    }
    device.identity.model = value("modelName");
    device.identity.firmware = value("firmwareVersion").or_else(|| value("softwareVersion"));
    if device.identity.firmware.is_some() {
        device.identity.evidence.push(
            "Firmware/software version advertised explicitly by the device's UPnP description"
                .into(),
        );
    }
    // modelNumber is a hardware model, not a firmware version.
    if device.identity.model.is_some() {
        device
            .identity
            .evidence
            .push("Model advertised in the device's UPnP description".into());
    }
    device.identity.services = root
        .descendants()
        .filter(|node| node.has_tag_name("serviceType"))
        .filter_map(|node| node.text().and_then(clean))
        .take(24)
        .collect();
    if let Some(kind) = value("deviceType") {
        device.identity.category = format!("UPnP: {kind}");
    }
}

pub async fn inspect(mut device: Device, gateway: Option<Ipv4Addr>) -> Result<Device> {
    device.identity = Default::default();
    enrich(std::slice::from_mut(&mut device));
    let ip: Ipv4Addr = device
        .ip
        .parse()
        .map_err(|_| "Device has an invalid IPv4 address")?;
    if !ip.is_private() {
        return Err("Identification is limited to observed private network addresses".into());
    }
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(1600));
    builder = builder.user_agent("Lantern local device identification/0.2");
    let client = builder.build().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let (dns, mdns, description, http, services) = tokio::join!(
        async {
            if let Some(gateway) = gateway {
                reverse_name(ip, gateway, false).await
            } else {
                None
            }
        },
        reverse_name(ip, ip, true),
        upnp_description(&client, ip),
        async { bounded_text(client.get(format!("http://{ip}/")).send().await.ok()?).await },
        mdns_services(ip)
    );
    let name_source = if mdns.is_some() {
        "mDNS"
    } else {
        "Gateway reverse DNS"
    };
    if let Some(name) = mdns.or(dns) {
        device.identity.hostname = Some(name.clone());
        if device.name == "Unidentified device"
            || !name
                .trim_end_matches(".local")
                .eq_ignore_ascii_case(&device.name)
        {
            device.identity.display_name = Some(name.trim_end_matches(".local").into());
            if device.name != "Unidentified device" {
                device.identity.evidence.push(format!("Conflicting names: router reported '{}'; {name_source} returned '{name}'. Neither name is authenticated.",device.name));
            }
        }
        device.identity.evidence.push(format!(
            "{name_source} hostname returned for this IP address"
        ));
        classify(&mut device);
    }
    if let Some((xml, server)) = description {
        apply_description(&mut device, &xml);
        if let Some(server) = server {
            device
                .identity
                .evidence
                .push(format!("UPnP HTTP server advertises: {server}"));
        }
    }
    if let Some((_, server)) = http {
        device
            .identity
            .services
            .push("HTTP management or web service".into());
        if let Some(server) = server {
            device.identity.evidence.push(format!(
                "HTTP Server header: {server} (software banner, not confirmed firmware)"
            ));
        }
    }
    for (key, value) in services {
        match key.as_str() {
            "service" if !device.identity.services.contains(&value) => {
                device.identity.services.push(value);
            }
            "model" | "md" => {
                device.identity.model = Some(value);
                device
                    .identity
                    .evidence
                    .push("Model advertised in mDNS service metadata".into());
            }
            "fv" | "firmwareversion" | "swver" | "softwareversion" => {
                device.identity.firmware = Some(value);
                device.identity.evidence.push(
                    "Software/firmware version advertised explicitly in mDNS metadata".into(),
                );
            }
            _ => {}
        }
    }
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await
        && socket.connect((ip, 9)).await.is_ok()
        && socket
            .local_addr()
            .is_ok_and(|address| address.ip() == std::net::IpAddr::V4(ip))
    {
        // hostname takes no parameters on macOS/Windows/Linux.
        let command = tokio::process::Command::new("hostname");
        if let Ok(hostname) = crate::discovery::command_output(command).await
            && let Some(hostname) = clean(&hostname)
        {
            device.identity.hostname = Some(hostname.clone());
            device.identity.display_name = Some(hostname);
        }
        device.identity.category = "This computer".into();
        device.identity.operating_system = Some(std::env::consts::OS.into());
        device.identity.evidence.push("This IP is assigned to the local computer according to its network route; operating system was identified locally".into());
        #[cfg(target_os = "macos")]
        {
            let mut command = tokio::process::Command::new("sw_vers");
            command.arg("-productVersion");
            if let Ok(version) = crate::discovery::command_output(command).await
                && let Some(version) = clean(&version)
            {
                device.identity.operating_system = Some(format!("macOS {version}"));
            }
            let mut command = tokio::process::Command::new("sysctl");
            command.args(["-n", "hw.model"]);
            if let Ok(model) = crate::discovery::command_output(command).await {
                device.identity.model = clean(&model);
            }
        }
    }
    if device.identity.display_name.is_none()
        && device.identity.model.is_none()
        && device.identity.hostname.is_none()
    {
        device
            .identity
            .evidence
            .push("No hostname or model was advertised during this inspection".into());
    }
    device.identity.evidence.push(format!(
        "Targeted inspection completed in {} ms; absent replies do not prove a device is offline",
        started.elapsed().as_millis()
    ));
    device.identity.inspected_at = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
    );
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device(mac: &str, name: &str) -> Device {
        Device {
            mac: mac.into(),
            name: name.into(),
            ip: "192.168.1.7".into(),
            source: "test DHCP".into(),
            presence: "Lease recorded".into(),
            identity: Default::default(),
        }
    }
    #[test]
    fn private_macs_never_get_manufacturer_guesses() {
        let mut devices = vec![
            device("02:17:f2:00:00:01", "Unidentified device"),
            device("00:17:f2:00:00:01", "iPhone"),
        ];
        enrich(&mut devices);
        assert!(devices[0].identity.manufacturer.is_none());
        assert!(
            devices[1]
                .identity
                .manufacturer
                .as_deref()
                .is_some_and(|name| name.contains("Apple"))
        );
        assert!(devices[1].identity.category.contains("name suggests"));
        assert!(devices[1].identity.firmware.is_none());
    }
    #[test]
    fn invalid_xml_never_erases_identity_or_becomes_firmware() {
        let mut device = device("00:17:f2:00:00:01", "iPhone");
        apply_description(&mut device, "<invalid>");
        assert_eq!(device.name, "iPhone");
        assert!(device.identity.firmware.is_none());
    }
}
