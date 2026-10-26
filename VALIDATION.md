# Validation — 26 October 2026

This file distinguishes automated checks, live router observations, and unverified behavior. It contains no client inventory or credentials.

## Current build checks

| Check | Environment | Result |
| --- | --- | --- |
| Strict TypeScript type checking and compilation | macOS, TypeScript 5.9 | Passed |
| Frontend formatting check | Prettier, source HTML/CSS/TypeScript/configuration | Passed |
| Rust formatting and Clippy with warnings denied | Isolated Linux x86-64 runner | Passed |
| Rust tests | Linux x86-64 | 18 passed |
| Real-service API smoke tests | Linux x86-64 and optimized native Apple Silicon macOS executable | 3 passed on each |
| Real nftables namespace integration | Isolated Linux user/network namespace | Passed |
| Device rate-cap integration | Isolated Linux bridge, ingress/egress hooks, real Ethernet traffic | Passed |
| Optimized native macOS build | Apple Silicon, Rust 1.91.1 | Passed |
| Native Windows build | Windows host unreachable over SSH | Not performed |

The Linux runs used a dedicated directory and one build job. Their output is retained locally in `blocking-validation.log`, `ping-validation.log`, `rate-validation.log`, and `traffic-validation.log`, excluded from Git. The runner directory is removed after collecting results. No existing runner services or host firewall were modified.

The Rust suite covers identifier validation, platform neighbor parsing, identification boundaries, shared proxy pacing and real relay cancellation, the firmware's empty-POST contract, native deauthentication acknowledgements, strict blacklist parsing, scoped/idempotent policy planning, unrelated-entry preservation, consecutive complete radio verification, and reset-safe WAN rate calculation. Incomplete radio observations and intervening associations reset the verification streak.

The API suite uses actual handler responses and checks Host/Origin/token/CSP boundaries, invalid input, absence of implicit gateway configuration, identification boundaries, profile lifecycle, and explicit UDP rejection. It does not contact a router.

The nftables integration substitutes SSH transport but executes the real firewall implementation in an isolated kernel namespace. It checks install/readback, idempotency, multiple rules, unblocking after a device vanishes, unrelated-table preservation, altered-rule detection, and ownership rejection. It refuses the host network namespace.

## Live Movistar observations

Hardware: Askey RTF8115VW REV5, firmware `ES_g14.17_RTF_TEF001_V9.17_V034`.

- Authenticated local HTTP inventory, firmware/model, and both Wi-Fi association APIs were read successfully. Partial radio failures remain diagnostics rather than empty successful lists.
- The native SSH host key was pinned and authenticated with the existing administration account. Commands were sent interactively, waiting for the firmware's prompt.
- The firmware accepts native `add mac_blocked` and `remove mac_blocked` commands even though they are omitted from its top-level command help.
- The user-selected Wi-Fi client's address was added to the enabled blacklist and read back. A later complete read of both radios showed it absent.
- The first app-level block test confirmed the enabled policy but only one of its first two radio observations showed absence. The app returned `block_policy_verified`, not full verification. The implementation was then changed to allow up to four settling observations while still requiring two consecutive complete absences; that sequence is covered by the Rust regression test.
- The user then requested unblocking. The native app removed that selected entry, verified absence in a fresh SSH session, and confirmed absence again with another authenticated status read. Both-radio readback showed the client associated again.
- Other blacklist entries and filter mode are preserved by the adapter. Disabling a global whitelist requires an explicit mode-change confirmation, and activating a disabled list with unrelated addresses is refused.
- The user subsequently requested another block. The optimized macOS executable returned `persistent_block_verified`: the enabled blacklist contained the selected MAC, two consecutive complete reads of both radios showed it absent, and a further authenticated status read confirmed the entry. One firmware-summary read failed during these observations; both radio reads succeeded and were recorded independently. The selected client was left blocked as requested.
- A later user-requested unblock was verified through a fresh SSH session and another authenticated policy read. The selected client remains unblocked in the current session.

Router policy readback is distinct from traffic measurement. No router reboot was performed, no Ethernet enforcement measurement was taken, and no client-side reconnect/packet trace was captured. Power-cycle durability and every forwarding/offload path remain unverified.

## Identification and interface checks

The optimized macOS app read three WAN counter sets from the Movistar router's authenticated statistics callback. Two successive samples produced nonnegative upload/download rates; the interface selector changed the displayed totals, and optional plan-speed inputs updated utilization percentages. Test plan values were cleared afterward. The overview labels its busiest-interface suggestion and reports counters as since-reset values rather than billing usage. OpenWrt WAN telemetry follows its documented `network.interface.wan` L3 device but has not been exercised on a physical OpenWrt gateway.

The device rows now expose Ban, Unban, Ping, and Speed limit actions. Ban status is read from the router and displayed as Banned, Not banned, or Unknown with a read timestamp. A dedicated refresh reads policy again; failure invalidates the cached status. OpenWrt status concerns Lantern forwarding rules, not every possible external router restriction.

The native macOS ping endpoint and dialog were exercised against observed devices: one returned three ICMP replies and RTT samples; another returned no ICMP replies. The latter is shown as no response, not proof of a ban. The endpoint accepts an observed MAC, resolves its inventory IP server-side, refuses an arbitrary caller-supplied IP, and bounds command duration/output. Native Windows ping execution remains unverified.

The OpenWrt speed-cap adapter was tested with a real isolated Linux bridge, virtual Ethernet pair, and packets matching synthetic client MACs. Ingress upload and egress download counters showed excess-byte drops. A different MAC did not consume the selected client's budget. Tests cover asymmetric caps, numeric unit normalization, idempotent updates, removal after the device disappears, unrelated-table preservation, offload refusal, malformed rule rejection, and ownership rejection. Kernel rule readback is not a physical router throughput benchmark.

The tested nftables version omits netdev device bindings from JSON, so the adapter checks the canonical text device binding as well. Both numeric-priority text bindings and actual JSON rate/burst units are exercised by the namespace integration.

The timed ping-increase adapter was exercised on an isolated Linux bridge with two synthetic clients. A 350 ms, 60-second spike increased the selected client's ping while the other remained unaffected. Lantern was terminated during the spike; the gateway's nftables timeout expired and ping returned to baseline. Separate checks covered early stop, queue release, rejection of altered rules and refusal to replace an existing root queue. This was not a live test on BEAST or a physical OpenWrt gateway; the connected Movistar firmware has no verified delay control.

The temporary Mac relay's IPv4 path was exercised on BEAST through the Movistar network: one run relayed 946 IPv4 packets with a 499 ms average hold and reported no drops. It sent restoration frames at the end; the observation did not independently prove BEAST accepted them or measure game-server RTT. The Mac had no IPv6 default route during development, so the IPv6 path has not been verified on that network.

In disposable Linux network namespaces, the dual-stack relay increased the selected synthetic client's IPv4 and IPv6 ping by about 350 ms after neighbor entries converged; another client stayed unaffected. Both protocols returned to baseline after expiration, explicit stop, and forced relay or watchdog termination. An IPv4-only run left IPv6 unaffected. These tests do not prove physical macOS IPv6 injection or recovery; some initial IPv4 packets bypassed the relay while the neighbor entry changed.

Live identification resolved network-interface manufacturers for globally assigned MACs, declined manufacturer guesses for private MACs, discovered the local Mac's hostname/model/OS, and exposed a conflict between a router label and an mDNS hostname. No live inventory fixture is committed. Firmware fields are populated only from explicit device metadata.

The interface provides in-flight guards, visible operation results, separate one-off disconnect and persistent block controls, blacklist inspection, and unblocking for entries absent from device inventory. Frontend source was expanded with consistent formatting instead of compressed one-line implementations.

## Remaining limits

- Native Windows execution is unverified.
- Physical OpenWrt SSH/hostapd interruption requires live hardware validation; namespace firewall validation does not replace it.
- Movistar power-cycle durability, wired enforcement, client-side connectivity measurement, and continuous monitoring have not been verified.
- OpenWrt rate caps have isolated kernel validation but no physical OpenWrt gateway validation. No OpenWrt address or SSH access was available in the current network. The connected Movistar firmware was inspected read-only: its priority CLI and advanced queue/classification pages do not expose a verified bandwidth-cap control. No QoS settings were changed there.
- Native process interception, local proxy UDP/QUIC shaping, smooth queue shaping, Movistar device rate caps, native installers, automatic updates, persistent local configuration/audit logs, universal firmware discovery, and performance benchmarks are not implemented.

Source publication excludes build output, dependencies, test logs, credentials, cookies, label images, private router keys/fingerprints, and live client identifiers. The public IEEE registry is included with attribution.
