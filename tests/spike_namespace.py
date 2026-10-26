"""Verify timed lag spikes with real traffic in isolated namespaces."""

import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def main():
    if "LANTERN_PARENT_NETNS" not in os.environ:
        subprocess.run(
            ["unshare", "-Urnm", sys.executable, __file__, sys.argv[1]],
            env=dict(os.environ, LANTERN_PARENT_NETNS=os.readlink("/proc/self/ns/net")),
            check=True,
        )
        return
    assert os.readlink("/proc/self/ns/net") != os.environ["LANTERN_PARENT_NETNS"]
    binary = str(Path(sys.argv[1]).resolve())
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "tmpfs", "/tmp")
    children = []
    process = None
    try:
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "br-lan", "type", "bridge")
        run("ip", "link", "set", "br-lan", "up")
        run("ip", "addr", "add", "192.168.66.1/24", "dev", "br-lan")
        macs = ["02:aa:bb:cc:dd:ee", "02:aa:bb:cc:dd:ef"]
        for index, mac in enumerate(macs):
            child = subprocess.Popen(["unshare", "-n", "sleep", "180"])
            children.append(child)
            run(
                "ip",
                "link",
                "add",
                f"lan{index}",
                "type",
                "veth",
                "peer",
                "name",
                f"client{index}",
            )
            run("ip", "link", "set", f"lan{index}", "master", "br-lan")
            run("ip", "link", "set", f"lan{index}", "up")
            run("ip", "link", "set", f"client{index}", "netns", str(child.pid))

            def inside(*args):
                return run("nsenter", "-t", str(child.pid), "-n", *args)

            inside("ip", "link", "set", "lo", "up")
            inside("ip", "link", "set", f"client{index}", "address", mac)
            inside("ip", "link", "set", f"client{index}", "up")
            inside(
                "ip",
                "addr",
                "add",
                f"192.168.66.{index + 2}/24",
                "dev",
                f"client{index}",
            )
            run("ping", "-n", "-c", "1", "-W", "2", f"192.168.66.{index + 2}")
            run(
                "ip",
                "neigh",
                "replace",
                f"192.168.66.{index + 2}",
                "lladdr",
                mac,
                "nud",
                "permanent",
                "dev",
                "br-lan",
            )
        run("nft", "add", "table", "inet", "unrelated_test")
        Path("/tmp/dhcp.leases").write_text(
            "\n".join(
                f"9999999999 {mac} 192.168.66.{index + 2} synthetic-{index} *"
                for index, mac in enumerate(macs)
            )
            + "\n"
        )
        with tempfile.TemporaryDirectory(prefix="lantern-spike-") as directory:
            transport = Path(directory) / "ssh"
            transport.write_text(
                '#!/bin/sh\nfor arg do script=$arg; done\nexec /bin/sh -c "$script"\n'
            )
            transport.chmod(0o700)
            process = subprocess.Popen(
                [binary, "--no-open"],
                stdout=subprocess.PIPE,
                text=True,
                env=dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}"),
            )
            port = int(
                re.search(r"http://127\.0\.0\.1:(\d+)", process.stdout.readline())[1]
            )

            def request(path, data=None, token=""):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                connection.request(
                    "POST" if data is not None else "GET",
                    path,
                    json.dumps(data) if data is not None else None,
                    {"Content-Type": "application/json", "X-Lantern-Token": token},
                )
                response = connection.getresponse()
                code, body = response.status, response.read().decode()
                connection.close()
                return code, body

            token = re.search(
                r'name="lantern-token" content="([^"]+)"', request("/")[1]
            )[1]

            def api(path, data, expected=200):
                code, body = request("/api/" + path, data, token)
                assert code == expected, (code, body)
                return json.loads(body)

            def ping(index):
                output = run(
                    "ping", "-n", "-c", "2", "-W", "2", f"192.168.66.{index + 2}"
                )
                return float(re.search(r"= [\d.]+/([\d.]+)/", output)[1])

            api("router", {"kind": "openwrt", "host": "192.168.66.1", "user": "root"})
            code, state = request("/api/state", token=token)
            assert code == 200
            inventory = json.loads(state)["devices"]
            assert all(
                any(device["mac"] == mac for device in inventory) for mac in macs
            ), (inventory, run("ip", "-4", "neigh", "show"))
            api(
                "device/spike",
                {"mac": macs[0], "delay_ms": 350, "jitter_ms": 0, "duration_s": 60},
            )
            assert ping(0) >= 300 and ping(1) < 60
            active = api("spikes", {})["spikes"]
            assert (
                len(active) == 1
                and active[0]["mac"] == macs[0]
                and active[0]["delay_ms"] == 350
                and 0 < active[0]["remaining_s"] <= 60
            )
            assert (
                "already active"
                in api(
                    "device/spike",
                    {"mac": macs[1], "delay_ms": 200, "jitter_ms": 0, "duration_s": 8},
                    400,
                )["error"]
            )
            # The kernel timeout must end the effect even when Lantern has stopped.
            process.terminate()
            process.wait(timeout=5)
            process = None
            time.sleep(61)
            assert ping(0) < 60
            process = subprocess.Popen(
                [binary, "--no-open"],
                stdout=subprocess.PIPE,
                text=True,
                env=dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}"),
            )
            port = int(
                re.search(r"http://127\.0\.0\.1:(\d+)", process.stdout.readline())[1]
            )
            token = re.search(
                r'name="lantern-token" content="([^"]+)"', request("/")[1]
            )[1]
            api("router", {"kind": "openwrt", "host": "192.168.66.1", "user": "root"})
            expired = api("spikes", {})["spikes"]
            assert len(expired) == 1 and expired[0]["mac"] is None
            api("device/spike/release", {"interface": "br-lan"})
            assert (
                json.loads(run("tc", "-j", "qdisc", "show", "dev", "br-lan"))[0]["kind"]
                == "noqueue"
            )
            api(
                "device/spike",
                {"mac": macs[0], "delay_ms": 150, "jitter_ms": 10, "duration_s": 10},
            )
            assert ping(0) >= 100
            api("device/spike/stop", {"mac": macs[0]})
            assert ping(0) < 60
            table = "lantern_spike_" + "br-lan".encode().hex()
            run("nft", "add", "rule", "netdev", table, "egress", "counter", "accept")
            assert "unexpected" in api("spikes", {}, 400)["error"].lower()
            assert api("device/spike/release", {"interface": "br-lan"}, 400)["error"]
            rules = json.loads(run("nft", "-j", "list", "table", "netdev", table))[
                "nftables"
            ]
            extra = [item["rule"] for item in rules if "rule" in item][-1]
            run(
                "nft",
                "delete",
                "rule",
                "netdev",
                table,
                "egress",
                "handle",
                str(extra["handle"]),
            )
            api("device/spike/release", {"interface": "br-lan"})
            run("nft", "list", "table", "inet", "unrelated_test")
            run("tc", "qdisc", "add", "dev", "br-lan", "root", "fq_codel")
            assert (
                "root queue"
                in api(
                    "device/spike",
                    {"mac": macs[0], "delay_ms": 100, "jitter_ms": 0, "duration_s": 10},
                    400,
                )["error"]
            )
            assert (
                json.loads(run("tc", "-j", "qdisc", "show", "dev", "br-lan"))[0]["kind"]
                == "fq_codel"
            )
            print(
                "PASS: selected-device ping spike, other device unaffected, autonomous expiry after app exit, explicit stop, queue release, and existing queue preservation"
            )
    finally:
        if process:
            process.terminate()
            process.wait(timeout=5)
        for child in children:
            child.terminate()
            child.wait(timeout=5)


if __name__ == "__main__":
    main()
