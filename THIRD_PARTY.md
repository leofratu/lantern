# Sources and attribution

Lantern is licensed under GPL-3.0-or-later.

The Movistar local web protocol and seven-field device-map layout were informed by the GPL-3.0 Home Assistant integration maintained at:

- https://github.com/luis-garza/movistar_rft8115vw
- https://github.com/jardenberg/ha-movistar-askey
- Protocol reference: `custom_components/movistar_rft8115vw/client.py` in the former project.

Attribution: the original integration contributors, Luis Garza and contributors, and the modernization contributors including Jocke Jardenberg. Lantern implements this protocol in Rust. It does not import or execute the Python integration. GPL licensing preserves compatibility with this source material.

Management semantics were checked against primary documentation:

- OpenWrt firewall configuration: https://openwrt.org/docs/guide-user/firewall/firewall_configuration
- OpenWrt SSH configuration: https://openwrt.org/docs/guide-user/base-system/dropbear
- LuCI hostapd disconnect semantics: https://openwrt.github.io/luci/jsapi/network.js.html
- nftables command language: https://netfilter.org/projects/nftables/manpage.html
- Movistar model manual index: https://www.movistar.es/atencion-cliente/manuales

Rust dependencies and their exact versions are recorded in `Cargo.lock`; frontend tooling is recorded in `package-lock.json`. Their respective licenses continue to apply. No proprietary HelmoCut/NetCut code, branding, assets, or attachment credentials are included.
