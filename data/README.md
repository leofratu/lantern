# Offline network-interface manufacturers

`vendors.tsv` contains 40,394 MA-L (24-bit) assignments downloaded from the IEEE Registration Authority public listing on 26 October 2026:

https://standards-oui.ieee.org/oui/oui.csv

Only the assignment and organization name are retained. Names are factual registry entries; no device inventory or personal network data was used. The source CSV was parsed with Python's standard CSV library, normalized to one tab-separated record per assignment, and sorted by prefix. Trailing whitespace is removed from organization names.

The runtime embeds this file and never sends MAC addresses to a lookup service. Locally administered MAC addresses are deliberately excluded from manufacturer lookup. The registered manufacturer can be the network-adapter supplier rather than the product brand. MA-M and MA-S assignments are not included in this version; missing registrations remain unidentified.
