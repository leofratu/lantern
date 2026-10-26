use crate::{
    model::{Result, RouterConfig, RouterKind},
    router,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[derive(Clone, Debug)]
pub struct Counters {
    pub name: String,
    pub received: u64,
    pub transmitted: u64,
    pub receive_errors: Option<u64>,
    pub transmit_errors: Option<u64>,
}

#[derive(Serialize)]
pub struct InterfaceTraffic {
    pub name: String,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
    pub receive_errors: Option<u64>,
    pub transmit_errors: Option<u64>,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
}

#[derive(Default)]
pub struct History {
    pub generation: u64,
    samples: BTreeMap<String, (Instant, u64, u64)>,
}

impl History {
    pub fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.samples.clear();
    }

    pub fn sample(&mut self, counters: Vec<Counters>, now: Instant) -> Vec<InterfaceTraffic> {
        let mut next = BTreeMap::new();
        let mut result = Vec::with_capacity(counters.len());
        for counter in counters {
            let rates = self
                .samples
                .get(&counter.name)
                .and_then(|(previous_time, rx, tx)| {
                    let elapsed = now.checked_duration_since(*previous_time)?.as_secs_f64();
                    if !(0.5..=120.0).contains(&elapsed) {
                        return None;
                    }
                    let down = counter.received.checked_sub(*rx)?;
                    let up = counter.transmitted.checked_sub(*tx)?;
                    Some((
                        down as f64 * 8.0 / elapsed / 1_000_000.0,
                        up as f64 * 8.0 / elapsed / 1_000_000.0,
                    ))
                });
            next.insert(
                counter.name.clone(),
                (now, counter.received, counter.transmitted),
            );
            result.push(InterfaceTraffic {
                name: counter.name,
                received_bytes: counter.received,
                transmitted_bytes: counter.transmitted,
                receive_errors: counter.receive_errors,
                transmit_errors: counter.transmit_errors,
                download_mbps: rates.map(|pair| pair.0),
                upload_mbps: rates.map(|pair| pair.1),
            });
        }
        self.samples = next;
        result
    }
}

pub fn movistar_counters(xml: &str) -> Result<Vec<Counters>> {
    let doc =
        roxmltree::Document::parse(xml).map_err(|_| "Router traffic response is not valid XML")?;
    let root = doc
        .descendants()
        .find(|node| node.has_tag_name("cbGetStatistic"))
        .ok_or("Router omitted traffic statistics")?;
    if !root
        .children()
        .any(|node| node.has_tag_name("Result") && node.text() == Some("0"))
    {
        return Err("Router rejected the traffic statistics request".into());
    }
    let mut names = BTreeSet::new();
    let mut result = Vec::new();
    for interface in root
        .descendants()
        .filter(|node| node.has_tag_name("rtm_cfg_ip_intf"))
    {
        let field = |name: &str| {
            interface
                .children()
                .find(|node| node.has_tag_name(name))
                .and_then(|node| node.text())
                .map(str::trim)
        };
        let name = field("name")
            .filter(|name| !name.is_empty() && name.len() <= 120)
            .ok_or("WAN interface name is missing")?;
        if !names.insert(name.to_owned()) || result.len() >= 128 {
            return Err("Router returned duplicate or excessive WAN interfaces".into());
        }
        let number = |name: &str| field(name).and_then(|value| value.parse::<u64>().ok());
        result.push(Counters {
            name: name.into(),
            received: number("rx_byte").ok_or("WAN download counter missing")?,
            transmitted: number("tx_byte").ok_or("WAN upload counter missing")?,
            receive_errors: number("rx_pkt_err"),
            transmit_errors: number("tx_pkt_err"),
        });
    }
    if result.is_empty() {
        return Err("Router reported no WAN traffic interfaces".into());
    }
    Ok(result)
}

pub async fn read(config: &RouterConfig) -> Result<Vec<Counters>> {
    match config.kind {
        RouterKind::Movistar => movistar_counters(&router::movistar_traffic(config).await?),
        RouterKind::Openwrt => {
            let status: serde_json::Value = serde_json::from_str(
                &router::ssh(config, "ubus call network.interface.wan status").await?,
            )
            .map_err(|_| "OpenWrt WAN status is invalid")?;
            if status["up"] != true {
                return Err("OpenWrt WAN is not reported as up".into());
            }
            let interface = status["l3_device"]
                .as_str()
                .or_else(|| status["device"].as_str())
                .ok_or("OpenWrt WAN did not report an interface")?;
            crate::limits::interface_name(interface)?;
            let path = format!("/sys/class/net/{interface}/statistics");
            let output = router::ssh(
                config,
                &format!("cat {path}/rx_bytes {path}/tx_bytes {path}/rx_errors {path}/tx_errors"),
            )
            .await?;
            let numbers: Vec<u64> = output
                .lines()
                .map(|line| line.trim().parse())
                .collect::<std::result::Result<_, _>>()
                .map_err(|_| "OpenWrt WAN counters are invalid")?;
            if numbers.len() != 4 {
                return Err("OpenWrt WAN counters are incomplete".into());
            }
            Ok(vec![Counters {
                name: interface.into(),
                received: numbers[0],
                transmitted: numbers[1],
                receive_errors: Some(numbers[2]),
                transmit_errors: Some(numbers[3]),
            }])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn router_samples_are_strict_and_rates_reset_with_counters() {
        // Sanitized from this firmware's cbGetStatistic response format.
        let xml = "<cbGetStatistic><Result>0</Result><rtm_cfg_ip_intf><name>wan0</name><rx_byte>1000000</rx_byte><tx_byte>2000000</tx_byte><rx_pkt_err>2</rx_pkt_err><tx_pkt_err>3</tx_pkt_err></rtm_cfg_ip_intf></cbGetStatistic>";
        let first = movistar_counters(xml).expect("valid counters");
        let now = Instant::now();
        let mut history = History::default();
        assert!(
            history.sample(first.clone(), now)[0]
                .download_mbps
                .is_none()
        );
        let mut second = first.clone();
        second[0].received += 250_000;
        second[0].transmitted += 125_000;
        let rate = history.sample(second, now + Duration::from_secs(2));
        assert_eq!(rate[0].download_mbps, Some(1.0));
        assert_eq!(rate[0].upload_mbps, Some(0.5));
        assert!(
            history.sample(first, now + Duration::from_secs(4))[0]
                .download_mbps
                .is_none()
        );
        assert!(movistar_counters("<cbGetStatistic><Result>1</Result></cbGetStatistic>").is_err());
        assert!(movistar_counters("<cbGetStatistic><Result>0</Result><rtm_cfg_ip_intf><name>x</name><rx_byte>oops</rx_byte></rtm_cfg_ip_intf></cbGetStatistic>").is_err());
    }
}
