"""Real nftables integration. Run ONLY in an isolated user+network namespace.

unshare -Urn python3 tests/gateway_namespace.py target/debug/lantern
The SSH transport is replaced locally; discovery and nft replies come from the
actual isolated kernel. No router credentials, fixtures, or host firewall access.
"""
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    current_namespace = os.readlink("/proc/self/ns/net")
    parent_namespace = os.environ.get("LANTERN_PARENT_NETNS")
    if parent_namespace is None:
        subprocess.run(
            ["unshare", "-Urn", sys.executable, __file__, sys.argv[1]],
            env=dict(os.environ, LANTERN_PARENT_NETNS=current_namespace),
            check=True,
        )
        return
    if current_namespace == parent_namespace:
        raise SystemExit("Refusing to run outside an isolated network namespace")
    binary = str(Path(sys.argv[1]).resolve())
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "link", "add", "lantern-test", "type", "dummy"], check=True)
    subprocess.run(["ip", "link", "set", "lantern-test", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "192.168.66.1/24", "dev", "lantern-test"], check=True)
    subprocess.run(["ip", "neigh", "add", "192.168.66.2", "lladdr", "02:aa:bb:cc:dd:ee", "dev", "lantern-test"], check=True)
    subprocess.run(["nft", "add", "table", "inet", "unrelated_test"], check=True)
    with tempfile.TemporaryDirectory(prefix="lantern-ssh-") as directory:
        transport = Path(directory) / "ssh"
        transport.write_text('#!/bin/sh\nfor arg do script=$arg; done\nexec /bin/sh -c "$script"\n')
        transport.chmod(0o700)
        env = dict(os.environ, PATH=f'{directory}:{os.environ["PATH"]}')
        process = subprocess.Popen([binary, "--no-open"], stdout=subprocess.PIPE, text=True, env=env)
        try:
            line = process.stdout.readline()
            port = int(re.search(r"http://127\.0\.0\.1:(\d+)", line)[1])

            def request(path, method="GET", payload=None, token=None):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["X-Lantern-Token"] = token
                connection.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
                response = connection.getresponse()
                code, data = response.status, response.read().decode()
                connection.close()
                return code, data

            token = re.search(r'name="lantern-token" content="([^"]+)"', request("/")[1])[1]

            def api(path, payload=None, method="POST", expected=200):
                code, body = request(f"/api/{path}", method, payload, token)
                assert code == expected, (code, body)
                return json.loads(body)

            api("router", {"kind": "openwrt", "host": "192.168.66.1", "user": "root"})
            state = api("state", method="GET")
            assert any(d["mac"] == "02:aa:bb:cc:dd:ee" for d in state["devices"])
            action = {"mac": "02:aa:bb:cc:dd:ee", "action": "block"}
            assert api("device", action)["outcome"] == "rule_verified"
            # Repeating block must not duplicate a rule.
            api("device", action)
            rules = api("rules")["rules"]
            assert len(rules) == 1, rules
            rule = rules[0]
            assert rule["comment"] == "lantern:02:aa:bb:cc:dd:ee"
            assert any("drop" in expression for expression in rule["expr"])
            assert any("counter" in expression for expression in rule["expr"])
            # A second device exercises adding to an already-existing chain.
            subprocess.run(["ip", "neigh", "add", "192.168.66.3", "lladdr", "02:aa:bb:cc:dd:ef", "dev", "lantern-test"], check=True)
            api("refresh")
            api("device", {"mac": "02:aa:bb:cc:dd:ef", "action": "block"})
            assert len(api("rules")["rules"]) == 2
            # A vanished neighbor must still be unblockable from the rule view.
            subprocess.run(["ip", "neigh", "del", "192.168.66.2", "dev", "lantern-test"], check=True)
            api("refresh")
            action["action"] = "unblock"
            api("device", action)
            api("device", action)
            assert len(api("rules")["rules"]) == 1
            subprocess.run(["nft", "list", "table", "inet", "unrelated_test"], check=True, stdout=subprocess.DEVNULL)
            # A retained comment cannot turn an ACCEPT into verified enforcement.
            remaining = api("rules")["rules"][0]
            subprocess.run(["nft", "replace", "rule", "inet", "lantern_v1", "forward", "handle", str(remaining["handle"]), "ether", "saddr", "02:aa:bb:cc:dd:ef", "counter", "accept", "comment", '"lantern:02:aa:bb:cc:dd:ef"'], check=True)
            result = api("device", {"mac": "02:aa:bb:cc:dd:ef", "action": "block"}, expected=400)
            assert "unverified" in result["error"]
            # Never adopt another program's table merely because its name matches.
            subprocess.run(["nft", "delete", "table", "inet", "lantern_v1"], check=True)
            subprocess.run(["nft", "add", "table", "inet", "lantern_v1"], check=True)
            result = api("device", {"mac": "02:aa:bb:cc:dd:ef", "action": "block"}, expected=400)
            assert "ownership" in result["error"]
            print("PASS: real nft block/readback, idempotency, multiple rules, vanished-device unblock, unrelated-table preservation, altered-rule detection, ownership rejection")
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdout.close()


if __name__ == "__main__":
    main()
