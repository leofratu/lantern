function el(id) {
    const found = document.getElementById(id);
    if (!found)
        throw new Error(`Missing interface element: ${id}`);
    return found;
}
const token = document.querySelector('meta[name="lantern-token"]')
    ?.content ?? "";
const escape = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
let snapshot = {
    platform: "",
    gateway: null,
    router_info: null,
    access_policy: null,
    speed_limits: null,
    devices: [],
    profiles: [],
    events: [],
};
let probedFingerprint = null;
let busy = false;
let editingProfile = null;
let renderedDevices = "";
let renderedProfiles = "";
let renderedEvents = "";
let syncSequence = 0;
let pingTarget = null;
let limitTarget = null;
let trafficSample = null;
let trafficBusy = false;
let trafficCompletion = Promise.resolve();
let trafficSuggested = false;
let trafficGateway = "";
let trafficHistory = [];
async function api(path, method = "GET", data) {
    let response;
    try {
        response = await fetch(`/api/${path}`, {
            method,
            headers: { "Content-Type": "application/json", "X-Lantern-Token": token },
            ...(data === undefined ? {} : { body: JSON.stringify(data) }),
            signal: AbortSignal.timeout(360_000),
        });
    }
    catch {
        throw new Error("The local service did not respond. If a change was requested, its outcome is unknown; inspect gateway rules before retrying.");
    }
    const result = await response.json().catch(() => null);
    if (!response.ok) {
        const message = result &&
            typeof result === "object" &&
            "error" in result &&
            typeof result.error === "string"
            ? result.error
            : `Request failed (${response.status})`;
        throw new Error(message);
    }
    return result;
}
function notice(message, error = false) {
    const target = el("notice");
    target.textContent = message;
    target.hidden = false;
    target.classList.toggle("error", error);
    document.querySelectorAll(".inline-notice").forEach((node) => node.remove());
    const dialog = document.querySelector("dialog[open]");
    if (dialog) {
        const inline = document.createElement("p");
        inline.className = "inline-notice";
        inline.setAttribute("role", "status");
        inline.textContent = message;
        dialog.querySelector(".dialog-heading")?.after(inline);
    }
}
async function operation(work) {
    if (busy)
        return;
    const previousDialog = document.querySelector("dialog[open]");
    busy = true;
    const buttons = Array.from(document.querySelectorAll("button,input,select"));
    const previous = buttons.map((button) => button.disabled);
    buttons.forEach((button) => {
        button.disabled = true;
    });
    notice("Working… waiting for the local service and gateway evidence.");
    try {
        // Avoid logging in to the router for telemetry while an action is using it.
        await trafficCompletion;
        const message = await work();
        try {
            await sync();
            notice(message);
        }
        catch {
            notice(`${message} The view could not refresh; retry Refresh devices.`, true);
        }
    }
    catch (error) {
        notice(error instanceof Error ? error.message : "The operation failed", true);
        try {
            await sync();
        }
        catch {
            /* The original operation error remains visible. */
        }
    }
    finally {
        busy = false;
        buttons.forEach((button, i) => {
            button.disabled = previous[i] ?? false;
        });
        applyCapabilities();
        const dialog = document.querySelector("dialog[open]");
        if (dialog && dialog !== previousDialog) {
            dialog
                .querySelector("button.close")
                ?.focus({ preventScroll: true });
            dialog.scrollTop = 0;
        }
    }
}
async function sync() {
    const sequence = ++syncSequence;
    const next = await api("state");
    if (sequence !== syncSequence)
        return;
    snapshot = next;
    const currentGateway = snapshot.gateway
        ? `${snapshot.gateway.kind}:${snapshot.gateway.host}`
        : "";
    if (currentGateway !== trafficGateway) {
        trafficGateway = currentGateway;
        trafficSample = null;
        trafficHistory = [];
        el("traffic-interface").innerHTML =
            '<option value="">Waiting for router data</option>';
        if (currentGateway)
            void refreshTraffic();
        else
            clearTraffic("Connect a gateway to see network traffic.");
    }
    el("platform").textContent = `${snapshot.platform || "Local"} · Session only`;
    const gateway = snapshot.gateway;
    el("gateway-name").textContent = gateway
        ? gateway.kind === "openwrt"
            ? "OpenWrt gateway"
            : "Movistar Askey RTF8115VW"
        : "No gateway connected";
    el("gateway-address").textContent = gateway
        ? `${gateway.host} · ${gateway.kind === "openwrt" || gateway.ssh_fingerprint ? "SSH management" : "Device inventory"}`
        : "Local inventory is available";
    el("gateway-button").textContent = gateway
        ? "Gateway settings"
        : "Connect gateway";
    el("device-count").textContent = String(snapshot.devices.length);
    el("named-count").textContent = String(snapshot.devices.filter((d) => Boolean(d.identity.display_name)).length);
    el("control-status").textContent = gateway
        ? gateway.kind === "openwrt"
            ? "OpenWrt controls"
            : gateway.ssh_fingerprint
                ? "SSH device controls"
                : "SSH setup needed"
        : "Not connected";
    el("control-detail").textContent = gateway
        ? gateway.kind === "openwrt"
            ? "Verified per request"
            : "Wi-Fi association evidence available"
        : "Connect a supported gateway";
    el("inventory-source").textContent = gateway
        ? `Reported by ${gateway.host}`
        : "From this computer’s neighbor cache";
    renderDevices();
    renderProfiles();
    renderEvents();
    applyCapabilities();
}
function clearTraffic(message) {
    el("traffic-status").textContent = message;
    for (const id of [
        "traffic-download",
        "traffic-upload",
        "traffic-down-total",
        "traffic-up-total",
    ])
        el(id).textContent = "—";
    for (const id of ["traffic-download-meter", "traffic-upload-meter"])
        el(id).style.width = "0%";
    for (const direction of ["download", "upload"]) {
        const plan = Number(el(direction === "download" ? "traffic-plan-down" : "traffic-plan-up").value);
        el(`traffic-${direction}-capacity`).textContent =
            plan > 0 && plan <= 1_000_000
                ? `${plan} Mbps plan · awaiting sample`
                : "Plan speed not set";
    }
    el("traffic-graph").innerHTML = "";
    el("traffic-chart-note").textContent = "Rates appear after two samples.";
}
function trafficRate(value) {
    return value === null || !Number.isFinite(value)
        ? "—"
        : `${value.toFixed(value < 10 ? 2 : 1)} Mbps`;
}
function renderTraffic() {
    const select = el("traffic-interface");
    const current = trafficSample?.interfaces.find((item) => item.name === select.value);
    if (!trafficSample || !current) {
        clearTraffic("No WAN interface is available.");
        return;
    }
    el("traffic-download").textContent = trafficRate(current.download_mbps);
    el("traffic-upload").textContent = trafficRate(current.upload_mbps);
    el("traffic-down-total").textContent = bytes(current.received_bytes);
    el("traffic-up-total").textContent = bytes(current.transmitted_bytes);
    const status = `Updated ${new Date(trafficSample.sampled_at * 1000).toLocaleTimeString()} · ${current.receive_errors ?? "—"} receive errors · ${current.transmit_errors ?? "—"} transmit errors`;
    el("traffic-status").textContent = trafficSuggested
        ? `${status} · Suggested interface has the highest observed byte total; verify your internet interface.`
        : status;
    for (const [direction, value] of [
        ["download", current.download_mbps],
        ["upload", current.upload_mbps],
    ]) {
        const plan = Number(el(direction === "download" ? "traffic-plan-down" : "traffic-plan-up").value);
        const valid = Number.isFinite(plan) && plan > 0 && plan <= 1_000_000;
        const percent = valid && value !== null ? (value / plan) * 100 : null;
        el(`traffic-${direction}-capacity`).textContent = valid
            ? percent === null
                ? `${plan} Mbps plan · collecting rate`
                : `${percent.toFixed(1)}% of ${plan} Mbps plan`
            : "Plan speed not set";
        el(`traffic-${direction}-meter`).style.width =
            percent === null ? "0%" : `${Math.min(100, Math.max(0, percent))}%`;
    }
    const graph = document.querySelector("#traffic-graph");
    if (!graph)
        return;
    if (!trafficHistory.length) {
        graph.innerHTML = "";
        el("traffic-chart-note").textContent = "Rates appear after two samples.";
        return;
    }
    const max = Math.max(0.1, ...trafficHistory.flatMap((sample) => [sample.down, sample.up]));
    const points = (key) => trafficHistory
        .map((sample, index) => `${((index * 600) / Math.max(1, trafficHistory.length - 1)).toFixed(1)},${(76 - (sample[key] / max) * 70).toFixed(1)}`)
        .join(" ");
    graph.innerHTML = `<line x1="0" y1="76" x2="600" y2="76" class="traffic-grid"/><polyline points="${points("down")}" class="traffic-line down"/><polyline points="${points("up")}" class="traffic-line up"/>`;
    el("traffic-chart-note").textContent =
        `Last ${trafficHistory.length} sampled rates · graph scale ${trafficRate(max)}`;
}
async function refreshTraffic() {
    if (trafficBusy ||
        !snapshot.gateway ||
        document.hidden ||
        el("network-page").hidden)
        return;
    const gateway = trafficGateway;
    trafficBusy = true;
    let finishTraffic = () => { };
    trafficCompletion = new Promise((resolve) => {
        finishTraffic = resolve;
    });
    el("traffic-refresh").disabled = true;
    if (!trafficSample)
        el("traffic-status").textContent = "Reading gateway traffic counters…";
    try {
        const result = await api("network/traffic", "POST", {});
        if (gateway !== trafficGateway)
            return;
        const select = el("traffic-interface");
        const previous = select.value;
        const names = result.interfaces.map((item) => item.name);
        if (!names.includes(previous)) {
            const suggested = result.interfaces.reduce((best, item) => item.received_bytes + item.transmitted_bytes >
                best.received_bytes + best.transmitted_bytes
                ? item
                : best);
            select.innerHTML = result.interfaces
                .map((item) => `<option value="${escape(item.name)}">${escape(item.name)}</option>`)
                .join("");
            select.value = suggested.name;
            trafficSuggested = result.interfaces.length > 1;
            trafficHistory = [];
        }
        else if (names.join("\0") !==
            Array.from(select.options)
                .map((option) => option.value)
                .join("\0")) {
            select.innerHTML = result.interfaces
                .map((item) => `<option value="${escape(item.name)}">${escape(item.name)}</option>`)
                .join("");
            select.value = previous;
        }
        trafficSample = result;
        const current = result.interfaces.find((item) => item.name === select.value);
        if (current &&
            current.download_mbps !== null &&
            current.upload_mbps !== null) {
            trafficHistory.push({
                down: current.download_mbps,
                up: current.upload_mbps,
            });
            if (trafficHistory.length > 20)
                trafficHistory.shift();
        }
        else
            trafficHistory = [];
        renderTraffic();
    }
    catch (error) {
        if (gateway === trafficGateway) {
            trafficHistory = [];
            trafficSample = null;
            clearTraffic(error instanceof Error
                ? `Traffic unavailable: ${error.message}`
                : "Traffic unavailable.");
        }
    }
    finally {
        trafficBusy = false;
        finishTraffic();
        el("traffic-refresh").disabled =
            busy || !snapshot.gateway;
    }
}
el("traffic-refresh").addEventListener("click", () => {
    void refreshTraffic();
});
el("traffic-interface").addEventListener("change", () => {
    trafficSuggested = false;
    trafficHistory = [];
    renderTraffic();
});
for (const id of ["traffic-plan-down", "traffic-plan-up"])
    el(id).addEventListener("input", renderTraffic);
setInterval(() => {
    if (!busy)
        void refreshTraffic();
}, 10_000);
function applyCapabilities() {
    el("traffic-refresh").disabled =
        busy || trafficBusy || !snapshot.gateway;
    el("inspect-rules").disabled =
        busy ||
            !snapshot.gateway ||
            (snapshot.gateway.kind === "movistar" && !snapshot.gateway.ssh_fingerprint);
    el("router-information").disabled =
        busy || snapshot.gateway?.kind !== "movistar";
    const canControl = Boolean(snapshot.gateway &&
        (snapshot.gateway.kind === "openwrt" || snapshot.gateway.ssh_fingerprint));
    el("refresh-access").disabled = busy || !canControl;
    const canLimit = snapshot.gateway?.kind === "openwrt";
    el("inspect-limits").disabled = busy || !canLimit;
    document
        .querySelectorAll("#limit-form input")
        .forEach((input) => {
        input.disabled = busy || !canLimit;
    });
    el("apply-limit").disabled =
        busy || !canLimit || !limitTarget;
    el("remove-limit").disabled =
        busy || !canLimit || !limitTarget;
    document
        .querySelectorAll("[data-action]")
        .forEach((button) => {
        button.disabled = busy || !canControl;
    });
    document
        .querySelectorAll("[data-ping]")
        .forEach((button) => {
        button.disabled = busy;
    });
    el("ping-again").disabled =
        busy ||
            !pingTarget ||
            !snapshot.devices.some((device) => device.mac === pingTarget);
}
function renderDevices() {
    const search = el("search").value.toLowerCase();
    const devices = snapshot.devices.filter((d) => `${d.name} ${d.ip} ${d.mac} ${d.identity.display_name ?? ""} ${d.identity.manufacturer ?? ""} ${d.identity.model ?? ""} ${d.identity.hostname ?? ""} ${d.identity.category}`
        .toLowerCase()
        .includes(search));
    const key = JSON.stringify([
        search,
        devices,
        snapshot.access_policy,
        snapshot.speed_limits,
        snapshot.gateway,
    ]);
    if (key === renderedDevices)
        return;
    renderedDevices = key;
    el("device-empty").hidden = devices.length > 0;
    const heading = el("device-empty").querySelector("h3");
    const paragraph = el("device-empty").querySelector("p");
    if (heading)
        heading.textContent = search
            ? "No matching devices"
            : "A clearer view starts here";
    if (paragraph)
        paragraph.textContent = search
            ? "Try another name, IP address, or MAC address."
            : "Refresh the local neighbor cache, or connect your gateway for a fuller device inventory.";
    el("devices").innerHTML = devices
        .map((d) => `<tr><td><div class="device-name"><span class="device-initial" aria-hidden="true">${d.identity.category.startsWith("Phone") ? "▯" : "▣"}</span><div><strong>${escape(d.identity.display_name ?? d.name)}</strong><small>${escape(d.identity.manufacturer ?? d.identity.mac_kind)}</small>${d.identity.model ? `<small>${escape(d.identity.model)}</small>` : ""}</div></div></td><td>${escape(d.ip)}</td><td class="code">${escape(d.mac)}</td><td>${accessBadge(d.mac)}${speedBadge(d.mac)}<small class="access-observation">${escape(d.presence)}</small></td><td><div class="row-actions"><button class="secondary" data-ping="${escape(d.mac)}" aria-label="Ping ${escape(d.identity.display_name ?? d.name)}">Ping</button><button class="secondary" data-device="${escape(d.mac)}" aria-label="Manage ${escape(d.identity.display_name ?? d.name)}">Details</button><button class="danger" data-action="block" data-mac="${escape(d.mac)}" aria-label="Ban ${escape(d.identity.display_name ?? d.name)}">Ban</button><button class="secondary" data-action="unblock" data-mac="${escape(d.mac)}" aria-label="Unban ${escape(d.identity.display_name ?? d.name)}">Unban</button><button class="secondary row-speed" data-speed="${escape(d.mac)}" aria-label="Speed limit ${escape(d.identity.display_name ?? d.name)}">Speed limit</button></div></td></tr>`)
        .join("");
}
function accessBadge(mac) {
    const policy = snapshot.access_policy;
    if (!policy)
        return '<span class="badge access-unknown">Unknown · refresh status</span>';
    const banned = policy.enabled && policy.blocked_macs.includes(mac);
    const checked = policy.checked_at
        ? new Date(policy.checked_at * 1000).toLocaleTimeString()
        : "last router read";
    const scope = policy.scope === "forwarding"
        ? "Lantern forwarding policy"
        : "Router blacklist";
    return `<span class="badge ${banned ? "access-banned" : "access-allowed"}">${banned ? "Banned" : "Not banned"}</span><small class="access-observation" title="${escape(scope)}">Checked ${escape(checked)}</small>`;
}
function speedBadge(mac) {
    if (snapshot.gateway?.kind !== "openwrt")
        return '<small class="access-observation">Speed caps need OpenWrt</small>';
    if (!snapshot.speed_limits)
        return '<small class="access-observation">Speed cap unknown</small>';
    const limit = snapshot.speed_limits.limits.find((limit) => limit.mac === mac);
    return `<small class="access-observation">${limit ? `↓ ${limit.down_kbps / 1000} / ↑ ${limit.up_kbps / 1000} Mbps` : "No Lantern speed cap"}</small>`;
}
function openLimit(mac) {
    limitTarget = mac;
    const device = snapshot.devices.find((device) => device.mac === mac);
    const limit = snapshot.speed_limits?.limits.find((limit) => limit.mac === mac);
    el("limit-title").textContent =
        `Speed limit · ${device?.identity.display_name ?? device?.name ?? mac}`;
    el("limit-target").textContent = device ? `${device.ip} · ${mac}` : mac;
    el("limit-support").textContent =
        snapshot.gateway?.kind === "openwrt"
            ? "Applies to this MAC on its directly connected OpenWrt LAN interface. Requires ip-full, nftables netdev ingress/egress support, and disabled flow offloading. Other devices keep their own budgets."
            : "Connect an OpenWrt gateway in the device’s traffic path to enforce these limits. The connected Movistar firmware exposes priority controls, without a verified bandwidth-cap API. Local app proxy limits are available under App bandwidth.";
    const form = el("limit-form");
    field(form, "down").value = String(limit ? limit.down_kbps / 1000 : 10);
    field(form, "up").value = String(limit ? limit.up_kbps / 1000 : 10);
    modal("limit-dialog").showModal();
    applyCapabilities();
}
el("limit-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy || !limitTarget || snapshot.gateway?.kind !== "openwrt")
        return;
    const mac = limitTarget;
    const form = el("limit-form");
    const down = Math.round(Number(field(form, "down").value) * 1000);
    const up = Math.round(Number(field(form, "up").value) * 1000);
    void (async () => {
        if (!(await confirmAction("Apply device speed cap?", `Limit ${mac} to ${down / 1000} Mbps download and ${up / 1000} Mbps upload at OpenWrt. Excess packets will be dropped above those budgets. Rules are runtime-only.`, "Apply limit")))
            return;
        await operation(async () => {
            const result = await api("device/limit", "POST", {
                mac,
                up_kbps: up,
                down_kbps: down,
            });
            modal("limit-dialog").close();
            modal("limit-list-dialog").close();
            return result.message;
        });
    })();
});
el("remove-limit").addEventListener("click", () => {
    if (busy || !limitTarget || snapshot.gateway?.kind !== "openwrt")
        return;
    const mac = limitTarget;
    void (async () => {
        if (!(await confirmAction("Remove this speed cap?", `Remove both Lantern rate policies for ${mac}. Other devices’ caps are preserved.`, "Remove limit")))
            return;
        await operation(async () => {
            const result = await api("device/limit", "POST", {
                mac,
                up_kbps: 0,
                down_kbps: 0,
            });
            modal("limit-dialog").close();
            modal("limit-list-dialog").close();
            return result.message;
        });
    })();
});
el("inspect-limits").addEventListener("click", () => {
    void operation(async () => {
        const result = await api("limits", "POST", {});
        el("limit-list-results").innerHTML =
            `<p>${escape(result.message)}</p>${result.limits.length ? result.limits.map((limit) => `<div class="rule"><div><strong class="code">${escape(limit.mac)}</strong><p>↓ ${limit.down_kbps / 1000} / ↑ ${limit.up_kbps / 1000} Mbps · ${escape(limit.interface)}</p><p>Dropped: ↑ ${bytes(limit.up_dropped_bytes)} · ↓ ${bytes(limit.down_dropped_bytes)}</p></div><button class="secondary" data-speed="${escape(limit.mac)}">Edit / remove</button></div>`).join("") : "<p>No Lantern device speed caps are installed.</p>"}`;
        modal("limit-list-dialog").showModal();
        return result.message;
    });
});
el("refresh-access").addEventListener("click", () => {
    void operation(async () => (await api("access", "POST")).message);
});
async function pingDevice(mac) {
    if (busy)
        return;
    const device = snapshot.devices.find((device) => device.mac === mac);
    if (!device) {
        notice("Refresh inventory before pinging this device.", true);
        return;
    }
    pingTarget = mac;
    el("ping-title").textContent =
        `Ping ${device.identity.display_name ?? device.name}`;
    el("ping-target").textContent = `${device.ip} · ${device.mac}`;
    el("ping-results").textContent = "Sending 3 ICMP echo requests…";
    if (!modal("ping-dialog").open)
        modal("ping-dialog").showModal();
    await operation(async () => {
        try {
            const result = await api("device/ping", "POST", { mac });
            const { ping } = result;
            const average = ping.roundtrip_ms.length
                ? ping.roundtrip_ms.reduce((sum, time) => sum + time, 0) /
                    ping.roundtrip_ms.length
                : null;
            el("ping-results").innerHTML =
                `<div class="ping-metrics"><div><span>Replies</span><strong>${ping.received} / ${ping.sent}</strong></div><div><span>Packet loss</span><strong>${ping.loss_percent.toFixed(0)}%</strong></div><div><span>Average RTT</span><strong>${average === null ? "—" : `${average.toFixed(2)} ms`}</strong></div></div><p>${ping.received ? "ICMP replies received" : "No ICMP replies"} · ${escape(new Date().toLocaleTimeString())}</p>${ping.roundtrip_ms.length ? `<div class="ping-samples">${ping.roundtrip_ms.map((time) => `<span>${time.toFixed(2)} ms</span>`).join("")}</div>` : ""}`;
            return result.message;
        }
        catch (error) {
            el("ping-results").textContent =
                "Ping could not complete. Reachability is unknown.";
            throw error;
        }
    });
}
el("ping-again").addEventListener("click", () => {
    if (pingTarget)
        void pingDevice(pingTarget);
});
function bytes(n) {
    if (n < 1000)
        return `${n} B`;
    if (n < 1e6)
        return `${(n / 1000).toFixed(1)} KB`;
    if (n < 1e9)
        return `${(n / 1e6).toFixed(1)} MB`;
    return `${(n / 1e9).toFixed(2)} GB`;
}
function renderProfiles() {
    const key = JSON.stringify(snapshot.profiles);
    if (key === renderedProfiles ||
        el("profiles").contains(document.activeElement))
        return;
    renderedProfiles = key;
    el("profile-empty").hidden = snapshot.profiles.length > 0;
    el("profiles").innerHTML = snapshot.profiles
        .map((p) => `<article class="profile"><div class="profile-heading"><h3>${escape(p.name)}</h3><span class="badge">Proxy listening</span></div><div class="proxy-address">SOCKS5 · 127.0.0.1:${p.port}</div><small>Set this address in your app’s proxy settings.</small><div class="profile-limits"><div><span>↓ Download limit</span><strong>${p.down_kbps / 1000} <small>Mbps</small></strong></div><div><span>↑ Upload limit</span><strong>${p.up_kbps / 1000} <small>Mbps</small></strong></div></div><small>${p.active} active connections · ${bytes(p.downloaded)} received · ${bytes(p.uploaded)} sent</small><p class="footnote">${p.failures} failed or rejected connections</p><div class="profile-actions"><button class="secondary" data-edit-profile="${p.id}">Edit limits</button><button class="text-button" data-stop-profile="${p.id}">Stop proxy</button></div></article>`)
        .join("");
}
function renderEvents() {
    const key = JSON.stringify(snapshot.events);
    if (key === renderedEvents)
        return;
    renderedEvents = key;
    el("events").innerHTML = snapshot.events.length
        ? snapshot.events
            .map((e) => `<div class="event"><time datetime="${new Date(e.at * 1000).toISOString()}">${escape(new Date(e.at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }))}</time><span class="badge ${e.outcome.startsWith("failed") ? "failed" : ""}">${escape(e.outcome.replaceAll("_", " "))}</span><div>${escape(e.message)}</div></div>`)
            .join("")
        : '<div class="empty"><h3>No activity yet</h3><p>Gateway requests and app proxy changes will appear here.</p></div>';
}
function modal(id) {
    return el(id);
}
function openGateway() {
    const form = el("gateway-form");
    if (snapshot.gateway) {
        field(form, "kind").value = snapshot.gateway.kind;
        field(form, "host").value = snapshot.gateway.host;
        field(form, "user").value = snapshot.gateway.user;
    }
    field(form, "password").value = "";
    probedFingerprint = snapshot.gateway?.ssh_fingerprint ?? null;
    el("ssh-fingerprint").textContent = probedFingerprint ?? "";
    el("trust-ssh").checked = Boolean(probedFingerprint);
    gatewayHelp();
    modal("gateway-dialog").showModal();
}
function field(form, name) {
    const input = form.elements.namedItem(name);
    if (!(input instanceof HTMLInputElement || input instanceof HTMLSelectElement))
        throw new Error(`Missing form field: ${name}`);
    return input;
}
function gatewayHelp() {
    const openwrt = el("router-kind").value === "openwrt";
    el("ssh-field").hidden = !openwrt;
    el("password-field").hidden = openwrt;
    el("movistar-ssh").hidden = openwrt;
    el("router-help").textContent = openwrt
        ? "Requires OpenSSH on this computer, key-based access, and a verified SSH host key. Blocking requires nftables; Wi-Fi disconnect requires hostapd ubus support. Rules are temporary until gateway reboot."
        : "Reads device inventory, firmware, and Wi-Fi client associations. SSH device controls use the router’s native management CLI and require a trusted host identity. Firmware and client versions are shown only when exposed by the device.";
    el("disconnect-gateway").hidden = !snapshot.gateway;
}
function openProfile(profile) {
    editingProfile = profile?.id ?? null;
    const form = el("profile-form");
    form.reset();
    if (profile) {
        field(form, "name").value = profile.name;
        field(form, "down").value = String(profile.down_kbps / 1000);
        field(form, "up").value = String(profile.up_kbps / 1000);
    }
    el("profile-title").textContent = profile
        ? "Edit app limits"
        : "New app profile";
    const submit = form.querySelector('button[type="submit"]');
    if (submit)
        submit.textContent = profile ? "Save limits" : "Start app proxy";
    modal("profile-dialog").showModal();
}
function openDevice(mac) {
    const d = snapshot.devices.find((device) => device.mac === mac);
    if (!d)
        return;
    const supported = snapshot.gateway?.kind === "openwrt";
    el("selected-name").textContent = d.identity.display_name ?? d.name;
    el("selected-device").innerHTML =
        `<dl class="device-facts"><dt>IP address</dt><dd>${escape(d.ip)}</dd><dt>MAC address</dt><dd class="code">${escape(d.mac)}</dd><dt>Source</dt><dd>${escape(d.source)}</dd><dt>Observation</dt><dd>${escape(d.presence)}</dd></dl>${supported ? `<p>Disconnect removes a Wi-Fi association for 60 seconds. A forwarding block prevents routed traffic matching this MAC; it does not turn off the device’s Wi-Fi.</p><div class="device-controls"><button class="danger" data-action="block" data-mac="${escape(mac)}">Block forwarding</button><button class="secondary" data-action="unblock" data-mac="${escape(mac)}">Remove block</button><button class="secondary" data-action="kick" data-mac="${escape(mac)}">Disconnect Wi-Fi</button></div><div class="form-help">Gateway rules expire on reboot. Hardware offloading may bypass forwarding rules. Inspect counters to see whether traffic was dropped.</div>` : `<div class="form-help">${snapshot.gateway ? "This Movistar firmware has no verified automatic enforcement adapter. Use its router administration page for access controls." : "Connect an OpenWrt gateway to enable access controls. Local neighbor discovery cannot enforce network policy."}</div>`}`;
    modal("device-dialog").showModal();
    const details = document.createElement("section");
    details.className = "identity-details";
    const identity = d.identity;
    details.innerHTML = `<h3>Device identification</h3><dl class="device-facts"><dt>Manufacturer</dt><dd>${escape(identity.manufacturer ?? "Not established")}</dd><dt>MAC type</dt><dd>${escape(identity.mac_kind)}</dd><dt>Device type</dt><dd>${escape(identity.category)}</dd><dt>Hostname</dt><dd>${escape(identity.hostname ?? "Not advertised")}</dd><dt>Model</dt><dd>${escape(identity.model ?? "Not advertised")}</dd><dt>Firmware</dt><dd>${escape(identity.firmware ?? "Not exposed by this device")}</dd></dl>${identity.services.length ? `<h3>Advertised services</h3><ul>${identity.services.map((service) => `<li>${escape(service)}</li>`).join("")}</ul>` : ""}<h3>Identification evidence</h3><ul>${identity.evidence.map((item) => `<li>${escape(item)}</li>`).join("")}</ul><p>Names, models, and versions are device-reported. A manufacturer prefix identifies the network interface, not necessarily the device brand.</p><button class="primary" data-identify="${escape(mac)}">${identity.inspected_at ? "Inspect device again" : "Inspect hostname, model & services"}</button>`;
    el("selected-device").prepend(details);
    if (identity.operating_system) {
        const operating = document.createElement("p");
        operating.textContent = `Operating system: ${identity.operating_system}`;
        details.prepend(operating);
    }
    const station = snapshot.router_info?.stations.find((station) => station.mac === mac);
    if (station) {
        const evidence = document.createElement("p");
        evidence.className = "form-help";
        evidence.textContent = `Router association: ${station.radio}, ${station.ssid}, ${station.authorized ? "authorized" : "not authorized"}${station.signal_dbm !== null ? `, signal ${station.signal_dbm} dBm` : ""}.`;
        details.prepend(evidence);
    }
    if (snapshot.gateway?.kind === "movistar") {
        el("selected-device").querySelector(":scope > .form-help")?.remove();
        const controls = document.createElement("section");
        const listed = snapshot.access_policy?.blocked_macs.includes(mac);
        controls.innerHTML = `<h3>Movistar device controls</h3><p>Block stores this MAC in the router’s blacklist, disconnects it, and verifies the policy and both Wi-Fi radios. The policy remains after Lantern closes. A device using another MAC or access point is outside this block.</p><p>${listed ? (snapshot.access_policy?.enabled ? "Last policy read: this MAC is blocked." : "Last policy read: this MAC is listed, but blacklist mode is disabled.") : "Inspect gateway rules to read the current blacklist."}</p>${snapshot.gateway.ssh_fingerprint ? `<div class="device-controls"><button class="danger" data-action="block" data-mac="${escape(mac)}">Block until unblocked</button><button class="secondary" data-action="unblock" data-mac="${escape(mac)}">Unblock</button><button class="secondary" data-action="kick" data-mac="${escape(mac)}">Disconnect once</button></div>` : "<p>Enable SSH controls in Gateway settings by inspecting and trusting the router’s host identity.</p>"}`;
        el("selected-device").append(controls);
    }
}
async function confirmAction(title, description, label) {
    const dialog = modal("confirm-dialog");
    el("confirm-title").textContent = title;
    el("confirm-description").textContent = description;
    el("confirm-action").textContent = label;
    return new Promise((resolve) => {
        const finish = (confirmed) => {
            dialog.close();
            yes.removeEventListener("click", accept);
            no.removeEventListener("click", cancel);
            dialog.removeEventListener("cancel", cancel);
            resolve(confirmed);
        };
        const accept = () => finish(true);
        const cancel = () => finish(false);
        const yes = el("confirm-action");
        const no = el("cancel-action");
        yes.addEventListener("click", accept);
        no.addEventListener("click", cancel);
        dialog.addEventListener("cancel", cancel);
        dialog.showModal();
        no.focus();
    });
}
async function actOnDevice(mac, action) {
    if (busy)
        return;
    const movistar = snapshot.gateway?.kind === "movistar";
    const enableMode = movistar && action === "block" && snapshot.access_policy?.enabled === false;
    const description = action === "kick"
        ? `Disconnect ${mac} from the gateway’s Wi-Fi.${snapshot.gateway?.kind === "openwrt" ? " A 60-second reconnect ban is requested." : " The device may reconnect immediately."} Selecting your own device may interrupt this session.`
        : movistar
            ? action === "block"
                ? `Store ${mac} in the router blacklist until you unblock it, then verify the policy and two successive reads of both radios. Selecting your own device will interrupt its connection.${enableMode ? " This also enables blacklist mode, which disables this router’s whitelist mode. Existing unrelated blacklist entries will prevent this mode change." : ""}`
                : `Remove only ${mac} from the router blacklist and verify its absence. Other blocked addresses and the filter mode are preserved.`
            : action === "block"
                ? `Block routed traffic from ${mac} at this gateway. Existing offloaded connections may continue. You can remove this rule later.`
                : `Remove Lantern’s forwarding block for ${mac}. Other router restrictions remain in place.`;
    if (!(await confirmAction(action === "unblock"
        ? movistar
            ? "Unblock this device?"
            : "Remove forwarding block?"
        : action === "kick"
            ? "Disconnect this device?"
            : movistar
                ? "Block until unblocked?"
                : "Block this device’s forwarding?", description, action === "unblock"
        ? "Unblock"
        : action === "kick"
            ? "Disconnect Wi-Fi"
            : movistar
                ? "Block device"
                : "Block forwarding")))
        return;
    await operation(async () => {
        const result = await api("device", "POST", {
            mac,
            action,
            enable_blacklist: enableMode,
        });
        if (result.outcome === "command_sent" ||
            result.outcome === "block_policy_verified")
            throw new Error(result.message);
        modal("device-dialog").close();
        modal("rules-dialog").close();
        return result.message;
    });
}
document.querySelectorAll("[data-page]").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".page").forEach((page) => {
        page.hidden = page.id !== `${button.dataset.page}-page`;
    });
    document
        .querySelectorAll("[data-page]")
        .forEach((item) => item.classList.toggle("active", item === button));
    el("breadcrumb").textContent = button.textContent?.trim() ?? "";
}));
document
    .querySelectorAll(".close")
    .forEach((button) => button.addEventListener("click", () => button.closest("dialog")?.close()));
el("search").addEventListener("input", renderDevices);
el("gateway-button").addEventListener("click", openGateway);
el("empty-connect").addEventListener("click", openGateway);
el("router-kind").addEventListener("change", gatewayHelp);
el("probe-ssh").addEventListener("click", () => {
    void operation(async () => {
        const form = el("gateway-form");
        const result = await api("router/ssh/probe", "POST", {
            kind: "movistar",
            host: field(form, "host").value.trim(),
            user: "1234",
        });
        probedFingerprint = result.fingerprint;
        el("ssh-fingerprint").textContent = result.fingerprint;
        el("trust-ssh").checked = false;
        return result.message;
    });
});
field(el("gateway-form"), "host").addEventListener("input", () => {
    probedFingerprint = null;
    el("ssh-fingerprint").textContent = "";
    el("trust-ssh").checked = false;
});
el("router-information").addEventListener("click", () => {
    void operation(async () => {
        const result = await api("router/inspect", "POST");
        await sync();
        const info = snapshot.router_info;
        el("router-info-results").innerHTML = info
            ? `<dl class="device-facts"><dt>Router model</dt><dd>${escape(info.model ?? "Not advertised")}</dd><dt>Firmware</dt><dd>${escape(info.firmware ?? "Not exposed in this session")}</dd><dt>Radios read</dt><dd>${info.radios_read} of 2</dd></dl><h3>Current Wi-Fi associations</h3>${info.stations.map((station) => `<div class="radio-evidence"><strong class="code">${escape(station.mac)}</strong><p>${escape(station.radio)} · ${escape(station.ssid)} · ${station.authorized ? "Authorized" : "Not authorized"}${station.signal_dbm !== null ? ` · ${station.signal_dbm} dBm` : ""}</p></div>`).join("")}${info.diagnostics.length ? `<h3>Diagnostics</h3><ul>${info.diagnostics.map((message) => `<li>${escape(message)}</li>`).join("")}</ul>` : ""}`
            : "<p>No router evidence was returned.</p>";
        if (snapshot.gateway?.ssh_fingerprint)
            el("router-info-results").insertAdjacentHTML("beforeend", '<button class="secondary" id="read-blacklist">Read native blacklist status</button>');
        modal("router-info-dialog").showModal();
        return result.message;
    });
});
el("refresh").addEventListener("click", () => {
    void operation(async () => (await api("refresh", "POST")).message);
});
el("new-profile").addEventListener("click", () => openProfile());
el("gateway-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const form = el("gateway-form");
    void operation(async () => {
        const kind = field(form, "kind").value;
        const result = await api("router", "POST", {
            kind,
            host: field(form, "host").value.trim(),
            user: field(form, "user").value.trim() || "root",
            password: kind === "movistar" ? field(form, "password").value : "",
            ssh_fingerprint: kind === "movistar" && el("trust-ssh").checked
                ? probedFingerprint
                : null,
        });
        field(form, "password").value = "";
        modal("gateway-dialog").close();
        return result.message;
    });
});
el("disconnect-gateway").addEventListener("click", () => {
    void operation(async () => {
        const result = await api("router", "DELETE");
        modal("gateway-dialog").close();
        return result.message;
    });
});
el("profile-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const form = el("profile-form");
    void operation(async () => {
        const result = await api(editingProfile ? `profiles/${editingProfile}` : "profiles", editingProfile ? "PUT" : "POST", {
            name: field(form, "name").value,
            down_kbps: Math.round(Number(field(form, "down").value) * 1000),
            up_kbps: Math.round(Number(field(form, "up").value) * 1000),
        });
        modal("profile-dialog").close();
        return result.message;
    });
});
document.addEventListener("click", (event) => {
    const button = event.target instanceof Element
        ? event.target.closest("button")
        : null;
    if (!button || busy)
        return;
    if (button.id === "read-blacklist")
        void operation(async () => {
            const result = await api("router/cli/status", "POST");
            const output = document.createElement("p");
            output.textContent = `Native blacklist ${result.enabled ? "enabled" : "disabled"}. ${result.blocked_macs.length} blocked addresses: ${result.blocked_macs.join(", ") || "none"}.`;
            el("router-info-results").append(output);
            return result.message;
        });
    const { device, editProfile, stopProfile, action, mac, identify, ping, speed, } = button.dataset;
    if (speed)
        openLimit(speed);
    if (ping)
        void pingDevice(ping);
    if (identify)
        void operation(async () => {
            const result = await api("device/identify", "POST", {
                mac: identify,
            });
            await sync();
            modal("device-dialog").close();
            openDevice(identify);
            return result.message;
        });
    if (device)
        openDevice(device);
    if (editProfile) {
        const profile = snapshot.profiles.find((p) => p.id === editProfile);
        if (profile)
            openProfile(profile);
    }
    if (stopProfile)
        void (async () => {
            if (!(await confirmAction("Stop this app proxy?", "Connections through this proxy will close. Remove the proxy setting from the app to restore its direct connection.", "Stop proxy")))
                return;
            await operation(async () => (await api(`profiles/${stopProfile}`, "DELETE")).message);
        })();
    if (action && mac)
        void actOnDevice(mac, action);
});
el("inspect-rules").addEventListener("click", () => {
    void operation(async () => {
        const result = await api("rules", "POST");
        if ("kind" in result && result.kind === "movistar") {
            const { blacklist, router_info: info } = result;
            el("rule-results").innerHTML =
                `<p>${escape(result.message)}</p><p><strong>Blacklist mode: ${blacklist.enabled ? "enabled" : "disabled"}</strong></p>${blacklist.blocked_macs.length
                    ? blacklist.blocked_macs
                        .map((mac) => {
                        const present = info.stations.some((station) => station.mac === mac);
                        const evidence = present
                            ? "Still associated: disconnection is not verified."
                            : info.radios_read === 2
                                ? "Absent from both Wi-Fi radios at this read."
                                : "Radio verification incomplete; connection state unknown.";
                        return `<div class="rule"><div><strong class="code">${escape(mac)}</strong><p>${escape(evidence)}</p></div><button class="secondary" data-action="unblock" data-mac="${escape(mac)}">Unblock</button></div>`;
                    })
                        .join("")
                    : "<p>No addresses in the router blacklist.</p>"}<p>These are router policies, including entries created outside Lantern. Unblock removes only the selected address. A missing Wi-Fi association does not prove anything about Ethernet or another access point.</p><button class="secondary" id="verify-blocks">Verify again</button>`;
            modal("rules-dialog").showModal();
            return "Blacklist and both-radio verification refreshed from the router.";
        }
        const nft = result;
        el("rule-results").innerHTML = `<p>${escape(nft.message)}</p>${nft.rules.length
            ? nft.rules
                .map((rule) => {
                const mac = rule.comment?.startsWith("lantern:")
                    ? rule.comment.slice(8)
                    : null;
                const counter = rule.expr?.find((expr) => expr.counter)?.counter;
                return `<div class="rule"><div><strong class="code">${escape(mac ?? "Unrecognized rule")}</strong><p>${counter ? `${counter.packets} packets · ${bytes(counter.bytes)} dropped` : "No traffic counters available"}</p></div>${mac ? `<button class="secondary" data-action="unblock" data-mac="${escape(mac)}">Remove block</button>` : ""}</div>`;
            })
                .join("")
            : '<div class="empty"><h3>No Lantern blocks installed</h3></div>'}<p>Rules are temporary. A zero counter does not prove access is allowed or denied; the device may be idle or using an offloaded flow.</p>`;
        modal("rules-dialog").showModal();
        return "Gateway rules refreshed from the router.";
    });
});
document.addEventListener("click", (event) => {
    if (event.target instanceof HTMLElement &&
        event.target.closest("#verify-blocks") &&
        !busy)
        el("inspect-rules").click();
});
void sync().catch((error) => notice(error instanceof Error ? error.message : "Could not load the local session", true));
setInterval(() => {
    if (!busy && !document.hidden)
        void sync().catch(() => {
            notice("Lost contact with the local Lantern service. Restart it and reopen its printed URL.", true);
        });
}, 2500);
export {};
