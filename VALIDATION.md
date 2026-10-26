# Validation — 26 October 2026

This file distinguishes automated checks, live router observations, and unverified behavior. It contains no client inventory or credentials.

## Current build checks

| Check | Environment | Result |
| --- | --- | --- |
| Strict TypeScript type checking and compilation | macOS, TypeScript 5.9 | Passed |
| Frontend formatting check | Prettier, source HTML/CSS/TypeScript/configuration | Passed |
| Rust formatting and Clippy with warnings denied | Isolated Linux x86-64 runner | Passed |
| Rust tests | Linux x86-64 | 11 passed |
| Real-service API smoke tests | Linux x86-64 and optimized native Apple Silicon macOS executable | 3 passed on each |
| Real nftables namespace integration | Isolated Linux user/network namespace | Passed |
| Optimized native macOS build | Apple Silicon, Rust 1.91.1 | Passed |
| Native Windows build | Windows host unreachable over SSH | Not performed |

The Linux run used a dedicated directory and one build job. Its output is retained locally in `blocking-validation.log`, excluded from Git. The runner directory is removed after collecting results. No existing runner services or host firewall were modified.

The Rust suite covers identifier validation, platform neighbor parsing, identification boundaries, shared proxy pacing and real relay cancellation, the firmware's empty-POST contract, native deauthentication acknowledgements, strict blacklist parsing, scoped/idempotent policy planning, unrelated-entry preservation, and consecutive complete radio verification. Incomplete radio observations and intervening associations reset the verification streak.

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

Router policy readback is distinct from traffic measurement. No router reboot was performed, no Ethernet enforcement measurement was taken, and no client-side reconnect/packet trace was captured. Power-cycle durability and every forwarding/offload path remain unverified.

## Identification and interface checks

Live identification resolved network-interface manufacturers for globally assigned MACs, declined manufacturer guesses for private MACs, discovered the local Mac's hostname/model/OS, and exposed a conflict between a router label and an mDNS hostname. No live inventory fixture is committed. Firmware fields are populated only from explicit device metadata.

The interface provides in-flight guards, visible operation results, separate one-off disconnect and persistent block controls, blacklist inspection, and unblocking for entries absent from device inventory. Frontend source was expanded with consistent formatting instead of compressed one-line implementations.

## Remaining limits

- Native Windows execution is unverified.
- Physical OpenWrt SSH/hostapd interruption requires live hardware validation; namespace firewall validation does not replace it.
- Movistar power-cycle durability, wired enforcement, client-side connectivity measurement, and continuous monitoring have not been verified.
- Native process interception, UDP/QUIC shaping, router-level bandwidth controls, native installers, automatic updates, persistent local configuration/audit logs, universal firmware discovery, and performance benchmarks are not implemented.

Source publication excludes build output, dependencies, test logs, credentials, cookies, label images, private router keys/fingerprints, and live client identifiers. The public IEEE registry is included with attribution.
