mod discovery;
mod identity;
mod limits;
mod model;
mod movistar_cli;
mod proxy;
mod reachability;
mod router;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use model::{Device, Event, Result, RouterConfig};
use proxy::{Profile, ProfileInput};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
};
use uuid::Uuid;

struct App {
    token: String,
    authority: String,
    config: Mutex<Option<RouterConfig>>,
    devices: Mutex<Vec<Device>>,
    profiles: Mutex<BTreeMap<Uuid, Arc<Profile>>>,
    events: Mutex<VecDeque<Event>>,
    gate: Mutex<()>,
    capacity: Arc<Semaphore>,
    router_info: Mutex<Value>,
    access_policy: Mutex<Value>,
    speed_limits: Mutex<Value>,
}

struct ApiError(String);
impl From<String> for ApiError {
    fn from(value: String) -> Self {
        Self(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(json!({"error":self.0}))).into_response()
    }
}
type ApiResult = std::result::Result<Json<Value>, ApiError>;

impl App {
    async fn cache_policy(&self, mut policy: Value) {
        policy["checked_at"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs())
        );
        *self.access_policy.lock().await = policy;
    }
    async fn event(&self, message: String, outcome: &str) {
        let mut events = self.events.lock().await;
        if events.len() == 100 {
            events.pop_back();
        }
        events.push_front(Event {
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            message,
            outcome: outcome.into(),
        });
    }
    async fn configured(&self) -> Result<RouterConfig> {
        self.config
            .lock()
            .await
            .clone()
            .ok_or("Connect a gateway first".into())
    }
}

async fn security(State(app): State<Arc<App>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|h| h.to_str().ok());
    let same_origin = format!("http://{}", app.authority);
    if host != Some(app.authority.as_str()) || origin.is_some_and(|o| o != same_origin) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if request.uri().path().starts_with("/api/")
        && headers.get("x-lantern-token").and_then(|h| h.to_str().ok()) != Some(&app.token)
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("constant header"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().expect("constant header"));
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("constant header"),
    );
    headers.insert(
        "referrer-policy",
        "no-referrer".parse().expect("constant header"),
    );
    response
}

async fn index(State(app): State<Arc<App>>) -> Html<String> {
    Html(include_str!("../web/index.html").replace("__TOKEN__", &app.token))
}

async fn state(State(app): State<Arc<App>>) -> Json<Value> {
    let config = app.config.lock().await;
    let gateway = config
        .as_ref()
        .map(|c| json!({"kind":c.kind, "host":c.host, "user":c.user, "ssh_fingerprint":c.ssh_fingerprint}));
    drop(config);
    let profiles: Vec<_> = app.profiles.lock().await.values().cloned().collect();
    let mut views = Vec::with_capacity(profiles.len());
    for profile in profiles {
        views.push(profile.view().await);
    }
    Json(
        json!({"platform":std::env::consts::OS, "gateway":gateway, "router_info":app.router_info.lock().await.clone(), "access_policy":app.access_policy.lock().await.clone(), "speed_limits":app.speed_limits.lock().await.clone(), "devices":app.devices.lock().await.clone(), "profiles":views, "events":app.events.lock().await.clone()}),
    )
}

async fn connect(State(app): State<Arc<App>>, Json(config): Json<RouterConfig>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    config.validate()?;
    match router::devices(&config).await {
        Ok(mut devices) => {
            identity::enrich(&mut devices);
            identity::inspect_inventory(&mut devices, config.host.parse().ok()).await;
            *app.devices.lock().await = devices;
            let access = router::access_policy(&config).await;
            let speed = if matches!(config.kind, model::RouterKind::Openwrt) {
                limits::status(&config)
                    .await
                    .ok()
                    .map(|limits| json!({"limits":limits}))
            } else {
                None
            };
            *app.config.lock().await = Some(config);
            *app.router_info.lock().await = Value::Null;
            *app.access_policy.lock().await = Value::Null;
            *app.speed_limits.lock().await = speed.unwrap_or(Value::Null);
            let policy_note = match access {
                Ok(policy) => {
                    app.cache_policy(policy).await;
                    String::new()
                }
                Err(error) => format!(" Access status is unknown: {error}"),
            };
            app.event(
                "Gateway connected; device inventory updated".into(),
                "success",
            )
            .await;
            Ok(Json(
                json!({"message":format!("Gateway connected. Credentials are held in memory until exit.{policy_note}")}),
            ))
        }
        Err(error) => {
            app.event(error.clone(), "failed").await;
            Err(error.into())
        }
    }
}

async fn refresh(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let config = app.config.lock().await.clone();
    let gateway = config.as_ref().and_then(|config| config.host.parse().ok());
    let result = if let Some(config) = config {
        router::devices(&config).await
    } else {
        discovery::local_devices().await
    };
    match result {
        Ok(mut devices) => {
            identity::enrich(&mut devices);
            let count = devices.len();
            identity::retain_observations(&mut devices, &app.devices.lock().await);
            identity::inspect_inventory(&mut devices, gateway).await;
            *app.devices.lock().await = devices;
            app.event(
                format!("Inventory refreshed: {count} observations"),
                "success",
            )
            .await;
            Ok(Json(
                json!({"message":format!("Found {count} device observations. Cached entries do not prove a device is online.")}),
            ))
        }
        Err(error) => {
            app.event(error.clone(), "failed").await;
            Err(error.into())
        }
    }
}

async fn disconnect(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    *app.config.lock().await = None;
    *app.router_info.lock().await = Value::Null;
    *app.access_policy.lock().await = Value::Null;
    *app.speed_limits.lock().await = Value::Null;
    app.devices.lock().await.clear();
    app.event(
        "Gateway session disconnected. Existing gateway rules remain in place.".into(),
        "success",
    )
    .await;
    Ok(Json(
        json!({"message":"Gateway credentials cleared. Existing router policies remain in place; reconnect to inspect or remove them."}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentifyDevice {
    mac: String,
}

async fn ping_device(State(app): State<Arc<App>>, Json(input): Json<IdentifyDevice>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let mac = model::mac_address(&input.mac)?;
    let device = app
        .devices
        .lock()
        .await
        .iter()
        .find(|device| device.mac == mac)
        .cloned()
        .ok_or_else(|| {
            ApiError("Refresh inventory and select an observed device before pinging".into())
        })?;
    let ip = device
        .ip
        .parse()
        .map_err(|_| ApiError("Device has no valid IPv4 address".into()))?;
    let result = reachability::ping(ip).await?;
    Ok(Json(
        json!({"message":format!("{} of {} ICMP replies. A missing reply does not prove blocking; devices can ignore ICMP.",result.received,result.sent),"ping":result}),
    ))
}

async fn identify_device(
    State(app): State<Arc<App>>,
    Json(input): Json<IdentifyDevice>,
) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let mac = model::mac_address(&input.mac)?;
    let device = app
        .devices
        .lock()
        .await
        .iter()
        .find(|device| device.mac == mac)
        .cloned()
        .ok_or_else(|| ApiError("Refresh inventory and select an observed device".into()))?;
    let gateway = app
        .config
        .lock()
        .await
        .as_ref()
        .and_then(|config| config.host.parse().ok());
    let identified = identity::inspect(device, gateway).await?;
    let mut devices = app.devices.lock().await;
    let slot = devices
        .iter_mut()
        .find(|device| device.mac == mac)
        .ok_or_else(|| ApiError("Device disappeared during inspection".into()))?;
    *slot = identified;
    drop(devices);
    app.event(
        format!("Identification completed for {mac}; evidence is available in device details"),
        "success",
    )
    .await;
    Ok(Json(
        json!({"message":"Device inspected. Open its details for manufacturer, names, advertised services, and identification evidence."}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceAction {
    mac: String,
    action: String,
    #[serde(default)]
    enable_blacklist: bool,
}

async fn ssh_probe(Json(config): Json<RouterConfig>) -> ApiResult {
    Ok(Json(movistar_cli::probe(&config).await?))
}

async fn inspect_router(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let config = app.configured().await?;
    if !matches!(config.kind, model::RouterKind::Movistar) {
        return Err(ApiError(
            "Movistar telemetry requires a Movistar gateway session".into(),
        ));
    }
    let information = router::movistar_information(&config).await?;
    *app.router_info.lock().await = information;
    app.event(
        "Router firmware and Wi-Fi association evidence refreshed".into(),
        "success",
    )
    .await;
    Ok(Json(
        json!({"message":"Router information refreshed. Missing fields and radio-read failures are listed in gateway details."}),
    ))
}

async fn cli_status(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    *app.access_policy.lock().await = Value::Null;
    let policy = movistar_cli::status(&app.configured().await?).await?;
    app.cache_policy(policy.clone()).await;
    Ok(Json(policy))
}

async fn access_status(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    *app.access_policy.lock().await = Value::Null;
    let policy = router::access_policy(&app.configured().await?).await?;
    app.cache_policy(policy).await;
    Ok(Json(
        json!({"message":"Ban status refreshed from the router."}),
    ))
}

async fn limit_status(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    *app.speed_limits.lock().await = Value::Null;
    let limits = limits::status(&app.configured().await?).await?;
    let value = json!({"limits":limits,"message":"Device speed-cap policies refreshed from OpenWrt. Counters report excess traffic dropped; policies clear on gateway reboot."});
    *app.speed_limits.lock().await = value.clone();
    Ok(Json(value))
}

async fn set_limit(
    State(app): State<Arc<App>>,
    Json(input): Json<limits::LimitInput>,
) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let mac = input.validate()?;
    let config = app.configured().await?;
    let device = app
        .devices
        .lock()
        .await
        .iter()
        .find(|device| device.mac == mac)
        .cloned();
    if input.up_kbps != 0 && device.is_none() {
        return Err(ApiError(
            "Refresh inventory and select an observed device before setting a speed cap".into(),
        ));
    }
    *app.speed_limits.lock().await = Value::Null;
    match limits::set(
        &config,
        &input,
        device.as_ref().map(|device| device.ip.as_str()),
    )
    .await
    {
        Ok(value) => {
            *app.speed_limits.lock().await = json!({"limits":value["limits"]});
            app.event(
                format!(
                    "Speed cap {mac}: {}",
                    value["message"].as_str().unwrap_or("Readback completed")
                ),
                "rule_verified",
            )
            .await;
            Ok(Json(value))
        }
        Err(error) => {
            app.event(format!("Speed cap {mac}: {error}"), "failed_or_unknown")
                .await;
            Err(error.into())
        }
    }
}

fn associated(information: &Value, mac: &str) -> bool {
    information["stations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|station| station["mac"] == mac)
}

#[derive(Default)]
struct AssociationVerification {
    consecutive_absent: u8,
    samples: Vec<Value>,
}

impl AssociationVerification {
    fn observe(&mut self, information: &Value, mac: &str) {
        let complete = information["radios_read"] == 2;
        let present = associated(information, mac);
        if complete && !present {
            self.consecutive_absent += 1;
        } else {
            self.consecutive_absent = 0;
        }
        self.samples.push(json!({"radios_read":information["radios_read"],"target_associated":present,"diagnostics":information["diagnostics"]}));
    }

    fn verified(&self) -> bool {
        self.consecutive_absent >= 2
    }
}

async fn persistent_movistar_block(
    app: &App,
    config: &RouterConfig,
    mac: &str,
    blocked: bool,
    enable_mode: bool,
) -> Result<Value> {
    // Invalidate cached policy before any write; a failed read must not display stale success.
    *app.access_policy.lock().await = Value::Null;
    let policy = movistar_cli::set_block(config, mac, blocked, enable_mode).await?;
    app.cache_policy(serde_json::to_value(&policy).map_err(|error| error.to_string())?)
        .await;
    if !blocked {
        return Ok(
            json!({"outcome":"unblock_verified","message":"This MAC was removed from the router blacklist and absence was verified in a fresh SSH session. Other entries and the filter mode were preserved. The device can reconnect when it is ready."}),
        );
    }
    let mut diagnostics = Vec::new();
    if let Err(error) = movistar_cli::disconnect(config, mac).await {
        diagnostics.push(format!(
            "Policy is installed, but disconnect could not be confirmed: {error}"
        ));
    }
    let mut verification = AssociationVerification::default();
    // Firmware applies filter changes asynchronously. Allow settling, but require
    // consecutive complete observations and never turn a failed radio into absence.
    for _ in 0..4 {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        match router::movistar_information(config).await {
            Ok(information) => {
                verification.observe(&information, mac);
                *app.router_info.lock().await = information;
            }
            Err(error) => {
                verification.consecutive_absent = 0;
                diagnostics.push(format!("Association verification failed: {error}"));
            }
        }
        if verification.verified() {
            break;
        }
    }
    let final_policy = movistar_cli::blacklist(config).await?;
    app.cache_policy(serde_json::to_value(&final_policy).map_err(|error| error.to_string())?)
        .await;
    if !final_policy.enabled
        || !final_policy.contains(mac)
        || final_policy.blocked_macs != policy.blocked_macs
    {
        return Err("The blacklist policy changed during verification. The device is not confirmed blocked; inspect gateway rules.".into());
    }
    let verified = verification.verified();
    Ok(json!({
        "outcome": if verified {"persistent_block_verified"} else {"block_policy_verified"},
        "message": if verified {"Router blacklist enabled and this MAC read back in fresh SSH sessions. The device was absent from both Wi-Fi radios in two successive checks. The router holds this policy after Lantern closes; use Unblock to remove it."} else {"The router blacklist contains this MAC and is enabled, but two complete radio checks did not both confirm absence. The policy remains installed; inspect gateway rules to verify again or unblock."},
        "verification":{"policy_verified":true,"absent_samples":verification.consecutive_absent,"required_samples":2,"radio_samples":verification.samples,"diagnostics":diagnostics}
    }))
}

async fn device_action(State(app): State<Arc<App>>, Json(input): Json<DeviceAction>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let config = app.configured().await?;
    let mac = model::mac_address(&input.mac)?;
    if input.action != "unblock" && !app.devices.lock().await.iter().any(|d| d.mac == mac) {
        return Err(ApiError(
            "Refresh inventory and select an observed device".into(),
        ));
    }
    if matches!(input.action.as_str(), "block" | "unblock") {
        *app.access_policy.lock().await = Value::Null;
    }
    let result = match input.action.as_str() {
        "block" | "unblock" if matches!(config.kind, model::RouterKind::Movistar) => {
            tokio::time::timeout(std::time::Duration::from_secs(300), persistent_movistar_block(&app, &config, &mac, input.action == "block", input.enable_blacklist))
                .await.unwrap_or_else(|_| Err("Router operation timed out. The blacklist may have changed; inspect gateway rules before retrying.".into()))
        }
        "block" => router::block(&config, &mac, true).await,
        "unblock" => router::block(&config, &mac, false).await,
        "kick" => {
            if matches!(config.kind, model::RouterKind::Movistar) {
                let before = router::movistar_information(&config).await?;
                if !before["stations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|station| station["mac"] == mac)
                {
                    return Err(ApiError("The device is not confirmed associated in the available router radio data. Refresh router evidence before sending a disconnect.".into()));
                }
                let sent = movistar_cli::disconnect(&config, &mac).await?;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let after = router::movistar_information(&config).await?;
                let target_is_associated = after["stations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|station| station["mac"] == mac);
                let absent = after["radios_read"] == 2 && !target_is_associated;
                *app.router_info.lock().await = after;
                if absent {
                    Ok(
                        json!({"outcome":"disassociation_verified","message":"Device absent from both router Wi-Fi association lists after the disconnect request. It may reconnect."}),
                    )
                } else if sent["router_acknowledged"] == true {
                    Ok(
                        json!({"outcome":"router_deauth_reported","message":if target_is_associated {"Router reported this device was deauthenticated. It is associated at readback, so it may have reconnected. This was a one-off disconnect, not a persistent block."} else {"Router reported deauthentication, but a complete radio readback was unavailable. Its current connection state is unknown."}}),
                    )
                } else {
                    Ok(sent)
                }
            } else {
                router::kick(&config, &mac).await
            }
        }
        _ => Err("Unknown device action".into()),
    };
    match result {
        Ok(value) => {
            if matches!(config.kind, model::RouterKind::Openwrt)
                && matches!(input.action.as_str(), "block" | "unblock")
            {
                *app.access_policy.lock().await = Value::Null;
                if let Ok(policy) = router::access_policy(&config).await {
                    app.cache_policy(policy).await;
                }
            }
            app.event(
                format!(
                    "{} {mac}: {}",
                    input.action,
                    value["message"].as_str().unwrap_or("Completed")
                ),
                if value["outcome"] == "router_deauth_reported" {
                    "router_reported"
                } else if value["outcome"] == "command_sent"
                    || value["outcome"] == "block_policy_verified"
                {
                    "unverified"
                } else {
                    "verified"
                },
            )
            .await;
            Ok(Json(value))
        }
        Err(error) => {
            app.event(
                format!("{} {mac}: {error}", input.action),
                "failed_or_unknown",
            )
            .await;
            Err(error.into())
        }
    }
}

async fn rules(State(app): State<Arc<App>>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let config = app.configured().await?;
    *app.access_policy.lock().await = Value::Null;
    if matches!(config.kind, model::RouterKind::Movistar) {
        *app.access_policy.lock().await = Value::Null;
        let policy = movistar_cli::status(&config).await?;
        app.cache_policy(policy.clone()).await;
        let information = router::movistar_information(&config).await?;
        *app.router_info.lock().await = information.clone();
        return Ok(Json(
            json!({"kind":"movistar","blacklist":policy,"router_info":information,"message":"Fresh router blacklist and Wi-Fi association readback. A listed MAC is blocked only while blacklist mode is enabled; incomplete radio reads cannot prove absence."}),
        ));
    }
    let result = router::rule_status(&config).await?;
    *app.access_policy.lock().await = Value::Null;
    app.cache_policy(router::access_policy(&config).await?)
        .await;
    Ok(Json(result))
}

async fn add_profile(State(app): State<Arc<App>>, Json(input): Json<ProfileInput>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    if app.profiles.lock().await.len() >= 16 {
        return Err(ApiError("At most 16 app profiles can run at once".into()));
    }
    let profile = Profile::start(input, app.capacity.clone()).await?;
    let view = profile.view().await;
    app.profiles.lock().await.insert(profile.id, profile);
    app.event(
        format!("App proxy started on 127.0.0.1:{}", view.port),
        "success",
    )
    .await;
    Ok(Json(
        json!({"message":"Proxy started. Configure this app to use the displayed SOCKS5 address.", "profile":view}),
    ))
}

async fn update_profile(
    State(app): State<Arc<App>>,
    Path(id): Path<Uuid>,
    Json(input): Json<ProfileInput>,
) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let profile = app
        .profiles
        .lock()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| ApiError("Profile not found".into()))?;
    profile.update(input).await?;
    app.event("App bandwidth limits updated".into(), "success")
        .await;
    Ok(Json(
        json!({"message":"Limits updated. Existing chunks may finish under the previous limit."}),
    ))
}

async fn stop_profile(State(app): State<Arc<App>>, Path(id): Path<Uuid>) -> ApiResult {
    let _guard = app
        .gate
        .try_lock()
        .map_err(|_| ApiError("Another operation is in progress".into()))?;
    let profile = app
        .profiles
        .lock()
        .await
        .remove(&id)
        .ok_or_else(|| ApiError("Profile not found".into()))?;
    profile.stop();
    app.event(
        "App proxy stopped; its active connections are closing".into(),
        "success",
    )
    .await;
    Ok(Json(
        json!({"message":"Proxy stopped. Remove its proxy setting from the app to restore direct access."}),
    ))
}

fn routes(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(index))
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route("/api/state", get(state))
        .route("/api/router", post(connect).merge(delete(disconnect)))
        .route("/api/refresh", post(refresh))
        .route("/api/device", post(device_action))
        .route(
            "/identity.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/identity.css"),
                )
            }),
        )
        .route("/api/device/identify", post(identify_device))
        .route("/api/device/ping", post(ping_device))
        .route("/api/router/ssh/probe", post(ssh_probe))
        .route("/api/router/inspect", post(inspect_router))
        .route("/api/router/cli/status", post(cli_status))
        .route("/api/rules", post(rules))
        .route("/api/access", post(access_status))
        .route("/api/limits", post(limit_status))
        .route("/api/device/limit", post(set_limit))
        .route("/api/profiles", post(add_profile))
        .route(
            "/api/profiles/{id}",
            put(update_profile).merge(delete(stop_profile)),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(app.clone(), security))
        .with_state(app)
}

#[tokio::main(worker_threads = 2)]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if std::env::var("LANTERN_ASKPASS").as_deref() == Ok("1") {
        let prompt = std::env::args().nth(1).unwrap_or_default();
        if !prompt.to_lowercase().contains("password") {
            return Err("Unexpected SSH authentication prompt".into());
        }
        println!(
            "{}",
            std::env::var("LANTERN_SSH_PASSWORD").map_err(|_| "SSH credential unavailable")?
        );
        return Ok(());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut port = 0;
    let mut open = true;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--port" => {
                port = iter
                    .next()
                    .ok_or("--port requires a value")?
                    .parse::<u16>()?;
            }
            "--no-open" => open = false,
            "--help" => {
                println!(
                    "Lantern 0.1.0\nUsage: lantern [--port PORT] [--no-open]\nLocal network administration. Credentials are session-only; router policies can outlive the app."
                );
                return Ok(());
            }
            _ => return Err(format!("Unknown option: {arg}").into()),
        }
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let authority = listener.local_addr()?.to_string();
    let url = format!("http://{authority}");
    let app = Arc::new(App {
        token: Uuid::new_v4().to_string(),
        authority,
        config: Mutex::new(None),
        devices: Mutex::new(Vec::new()),
        profiles: Mutex::new(BTreeMap::new()),
        events: Mutex::new(VecDeque::new()),
        gate: Mutex::new(()),
        capacity: Arc::new(Semaphore::new(128)),
        router_info: Mutex::new(Value::Null),
        access_policy: Mutex::new(Value::Null),
        speed_limits: Mutex::new(Value::Null),
    });
    println!(
        "Lantern 0.1.0 — {url}\nNo gateway connected. No network changes made. Ctrl+C to quit."
    );
    if open {
        open_browser(&url);
    }
    axum::serve(listener, routes(app.clone()))
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            for profile in app.profiles.lock().await.values() {
                profile.stop();
            }
        })
        .await?;
    Ok(())
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "linux")]
    let command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let command = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    if let Err(error) = {
        let mut c = command;
        c.spawn()
    } {
        eprintln!("Open the printed URL in your browser: {error}");
    }
}

#[cfg(test)]
mod verification_tests {
    use super::*;

    #[test]
    fn association_verification_requires_two_consecutive_complete_absences() {
        let mac = "02:00:00:00:00:01";
        let absent = json!({"radios_read":2,"stations":[],"diagnostics":[]});
        let partial = json!({"radios_read":1,"stations":[],"diagnostics":["5 GHz unavailable"]});
        let present = json!({"radios_read":2,"stations":[{"mac":mac}],"diagnostics":[]});
        let mut verification = AssociationVerification::default();
        for information in [&present, &absent, &partial, &absent, &present, &absent] {
            verification.observe(information, mac);
            assert!(!verification.verified());
        }
        verification.observe(&absent, mac);
        assert!(verification.verified());
    }
}
