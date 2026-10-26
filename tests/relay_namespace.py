"""Exercise the packet relay and watchdog in disposable Linux namespaces."""

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
            ["unshare", "-Urnm", sys.executable, __file__],
            env=dict(os.environ, LANTERN_PARENT_NETNS=os.readlink("/proc/self/ns/net")),
            check=True,
        )
        return
    assert os.readlink("/proc/self/ns/net") != os.environ["LANTERN_PARENT_NETNS"]
    helper = Path(__file__).resolve().parent.parent / "tools" / "lantern_relay.py"
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "tmpfs", "/tmp")
    children = []
    process = None
    try:
        run("sysctl", "-w", "net.ipv4.ip_forward=0")
        run("ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "br-lan", "type", "bridge")
        run("ip", "link", "set", "br-lan", "up")
        for index in range(3):
            child = subprocess.Popen(["unshare", "-n", "sleep", "120"])
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
                f"peer{index}",
            )
            run("ip", "link", "set", f"lan{index}", "master", "br-lan")
            run("ip", "link", "set", f"lan{index}", "up")
            run("ip", "link", "set", f"peer{index}", "netns", str(child.pid))

            def inside(*args):
                return run("nsenter", "-t", str(child.pid), "-n", *args)

            inside("ip", "link", "set", "lo", "up")
            inside(
                "ip",
                "link",
                "set",
                f"peer{index}",
                "address",
                f"02:aa:bb:cc:dd:0{index + 1}",
            )
            inside("ip", "link", "set", f"peer{index}", "up")
            inside(
                "ip", "addr", "add", f"192.168.66.{index + 1}/24", "dev", f"peer{index}"
            )
            inside(
                "ip",
                "-6",
                "addr",
                "add",
                f"fe80::{index + 1}/64",
                "dev",
                f"peer{index}",
                "nodad",
            )
            inside(
                "ip",
                "-6",
                "addr",
                "add",
                f"fd42:66::{index + 1}/64",
                "dev",
                f"peer{index}",
                "nodad",
            )
            if index == 0:
                inside(
                    "ip", "-6", "addr", "add", "fd42:77::1/128", "dev", "lo", "nodad"
                )
            else:
                inside(
                    "ip",
                    "-6",
                    "route",
                    "add",
                    "fd42:77::/64",
                    "via",
                    "fe80::1",
                    "dev",
                    f"peer{index}",
                )
        # Give the relay its own address, separate from all synthetic clients.
        run("ip", "addr", "add", "192.168.66.10/24", "dev", "br-lan")
        run("ip", "-6", "addr", "add", "fe80::10/64", "dev", "br-lan", "nodad")
        for index in (1, 2):
            run(
                "ip",
                "neigh",
                "replace",
                f"192.168.66.{index}",
                "lladdr",
                f"02:aa:bb:cc:dd:0{index}",
                "nud",
                "permanent",
                "dev",
                "br-lan",
            )
            run(
                "ip",
                "-6",
                "neigh",
                "replace",
                f"fe80::{index}",
                "lladdr",
                f"02:aa:bb:cc:dd:0{index}",
                "nud",
                "permanent",
                "dev",
                "br-lan",
            )
        local_mac = json.loads(run("ip", "-j", "link", "show", "br-lan"))[0]["address"]

        def target(index, *args):
            return run("nsenter", "-t", str(children[index].pid), "-n", *args)

        def ping(index, count=2):
            output = target(
                index,
                "ping",
                "-n",
                "-c",
                str(count),
                "-i",
                "0.3",
                "-W",
                "2",
                "192.168.66.1",
            )
            return float(re.search(r"= [\d.]+/([\d.]+)/", output)[1])

        def ping6(index, count=2):
            output = target(
                index,
                "ping",
                "-6",
                "-n",
                "-c",
                str(count),
                "-i",
                "0.3",
                "-W",
                "2",
                "fd42:77::1",
            )
            return float(re.search(r"= [\d.]+/([\d.]+)/", output)[1])

        def wait_for_both_neighbors():
            consecutive = 0
            for _ in range(24):
                v4 = target(1, "ip", "neigh", "show", "192.168.66.1")
                v6 = target(1, "ip", "-6", "neigh", "show", "fe80::1")
                consecutive = (
                    consecutive + 1 if local_mac in v4 and local_mac in v6 else 0
                )
                if consecutive >= 3:
                    return
                time.sleep(0.25)
            raise AssertionError(
                "Both gateway neighbor entries did not converge on the relay"
            )

        assert ping(1) < 100 and ping(2) < 100
        assert ping6(1) < 100 and ping6(2) < 100
        time.sleep(1.5)

        def launch(duration, ipv6=True):
            folder = Path(tempfile.mkdtemp(prefix="lantern-relay-test-"))
            folder.chmod(0o700)
            request = folder / "request.json"
            request.write_text(
                json.dumps(
                    {
                        "interface": "br-lan",
                        "target_ip": "192.168.66.2",
                        "target_mac": "02:aa:bb:cc:dd:02",
                        "gateway_ip": "192.168.66.1",
                        "gateway_mac": "02:aa:bb:cc:dd:01",
                        "local_mac": local_mac,
                        "delay_ms": 350,
                        "duration_s": duration,
                        "expires_at": int(time.time()) + 120,
                        "ipv6": {
                            "target_ip": "fe80::2",
                            "gateway_ip": "fe80::1",
                            "gateway_mac": "02:aa:bb:cc:dd:01",
                        }
                        if ipv6
                        else None,
                    }
                )
            )
            request.chmod(0o600)
            child = subprocess.Popen(
                [sys.executable, str(helper), "--request", str(request)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(100):
                if (folder / "status.json").exists():
                    state = json.loads((folder / "status.json").read_text())
                    if state["state"] == "running":
                        return child, folder
                    raise AssertionError(state)
                if child.poll() is not None:
                    raise AssertionError(child.stderr.read())
                time.sleep(0.05)
            raise AssertionError("Relay did not start")

        duration = int(os.environ.get("LANTERN_RELAY_TEST_SECONDS", "60"))
        process, folder = launch(duration)
        first_started = time.monotonic()
        wait_for_both_neighbors()
        delayed = ping(1, 4)
        unaffected = ping(2)
        assert delayed >= 250 and unaffected < 100, (delayed, unaffected)
        delayed6 = ping6(1, 3)
        unaffected6 = ping6(2)
        assert delayed6 >= 250 and unaffected6 < 100, (delayed6, unaffected6)
        code = process.wait(timeout=70)
        if code:
            raise AssertionError(process.stderr.read())
        process = None
        result = json.loads((folder / "status.json").read_text())
        assert result["state"] == "completed" and result["forwarded"] > 0, result
        assert result["avg_hold_ms"] >= 300, result
        assert result["forwarded_ipv4"] > 0 and result["forwarded_ipv6"] > 0, result
        assert duration - 2 <= time.monotonic() - first_started <= duration + 10
        assert ping(1) < 100
        assert ping6(1) < 100
        replay = subprocess.run(
            [sys.executable, str(helper), "--request", str(folder / "request.json")],
            capture_output=True,
            text=True,
        )
        assert (
            replay.returncode != 0
            and json.loads((folder / "status.json").read_text())["state"] == "completed"
        )
        # An explicit stop must restore the target before the timer ends.
        time.sleep(1.5)
        process, folder = launch(20)
        wait_for_both_neighbors()
        assert ping(1, 3) >= 200
        assert ping6(1, 2) >= 200
        (folder / "stop").write_text("")
        code = process.wait(timeout=10)
        if code:
            raise AssertionError(process.stderr.read())
        process = None
        assert json.loads((folder / "status.json").read_text())["state"] == "stopped"
        assert ping(1) < 100
        assert ping6(1) < 100
        # Killing the relay must not kill its watchdog; it restores the target.
        time.sleep(1.5)
        process, folder = launch(20)
        wait_for_both_neighbors()
        assert ping(1, 3) >= 200
        assert ping6(1, 2) >= 200
        process.kill()
        process.wait(timeout=5)
        process = None
        for _ in range(100):
            state = json.loads((folder / "status.json").read_text())
            if state["state"] == "watchdog_restored":
                break
            time.sleep(0.1)
        assert state["state"] == "watchdog_restored", state
        assert ping(1) < 100
        assert ping6(1) < 100
        # If the watchdog itself dies, the relay must attempt restoration.
        time.sleep(1.5)
        process, folder = launch(20)
        wait_for_both_neighbors()
        assert ping(1, 3) >= 200
        assert ping6(1, 2) >= 200
        children_file = Path(f"/proc/{process.pid}/task/{process.pid}/children")
        watchdog = int(children_file.read_text().split()[0])
        os.kill(watchdog, 9)
        assert process.wait(timeout=10) != 0
        process = None
        state = json.loads((folder / "status.json").read_text())
        assert state["state"] == "failed_restored", state
        assert ping(1) < 100
        assert ping6(1) < 100
        # An unavailable IPv6 gateway must leave IPv6 alone while IPv4 works.
        time.sleep(1.5)
        process, folder = launch(20, ipv6=False)
        time.sleep(4)
        assert ping(1, 3) >= 200
        assert ping6(1, 2) < 100
        (folder / "stop").write_text("")
        assert process.wait(timeout=10) == 0
        process = None
        result = json.loads((folder / "status.json").read_text())
        assert result["forwarded_ipv4"] > 0 and result["forwarded_ipv6"] == 0, result
        assert ping(1) < 100
        print(
            "PASS: IPv4/IPv6 relay, unaffected peer, IPv4-only fallback, automatic restoration, and watchdog recovery"
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
