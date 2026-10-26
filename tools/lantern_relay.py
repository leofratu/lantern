#!/usr/bin/env python3
"""One-device IP relay. Run only with explicit administrator authorization.

This helper holds target-to-gateway packets in memory; it never stores packet
contents. A separate watchdog restores the target's gateway ARP entry if the
relay exits or reaches its deadline. See README for limits and recovery.
"""

import argparse
import ctypes
import ctypes.util
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import stat
import struct
import subprocess
import sys
import time
from collections import deque

MAX_QUEUED_BYTES = 32 * 1024 * 1024
MAX_FRAME = 65535


def mac_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value
    ):
        raise ValueError("Invalid Ethernet address")
    address = bytes.fromhex(value.replace(":", ""))
    if address[0] & 1 or not any(address):
        raise ValueError("Ethernet address must be unicast")
    return address


def arp_frame(local_mac, target_mac, target_ip, gateway_mac, gateway_ip, *, restore):
    # Ethernet source remains the Mac's own address; only the ARP payload is
    # changed, so the switch does not learn the gateway MAC on the Mac's port.
    sender = gateway_mac if restore else local_mac
    ethernet = target_mac + local_mac + b"\x08\x06"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
    return (
        ethernet + arp + sender + gateway_ip.packed + target_mac + target_ip.packed
    ).ljust(60, b"\0")


def neighbor_frame(
    local_mac, target_mac, target_ip, gateway_mac, gateway_ip, *, restore
):
    """Unsolicited router advertisement for a single target's neighbor cache."""
    sender = gateway_mac if restore else local_mac
    body = struct.pack("!BBHI", 136, 0, 0, 0xA0000000) + gateway_ip.packed
    body += b"\x02\x01" + sender
    pseudo = gateway_ip.packed + target_ip.packed + struct.pack("!I3xB", len(body), 58)
    data = pseudo + body
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    body = body[:2] + struct.pack("!H", (~total) & 0xFFFF) + body[4:]
    header = struct.pack("!IHBB", 6 << 28, len(body), 58, 255)
    return (
        target_mac
        + local_mac
        + b"\x86\xdd"
        + header
        + gateway_ip.packed
        + target_ip.packed
        + body
    )


def forward_frame(frame, local_mac, target_mac, gateway_mac, target_ip, local_ips):
    if (
        len(frame) < 34
        or frame[:6] != local_mac
        or frame[6:12] != target_mac
        or frame[12:14] != b"\x08\x00"
    ):
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    if (
        ip[0] >> 4 != 4
        or ihl < 20
        or total < ihl
        or len(ip) < total
        or ip[12:16] != target_ip.packed
        or ip[16:20] in local_ips
    ):
        return None
    return gateway_mac + local_mac + frame[12:14] + ip[:total]


def forward_ipv6(frame, local_mac, target_mac, gateway_mac, local_ips):
    if (
        len(frame) < 54
        or frame[:6] != local_mac
        or frame[6:12] != target_mac
        or frame[12:14] != b"\x86\xdd"
    ):
        return None
    ip = frame[14:]
    size = 40 + int.from_bytes(ip[4:6], "big")
    if ip[0] >> 4 != 6 or size > len(ip) or size == 40:
        return None
    source = ipaddress.IPv6Address(ip[8:24])
    destination = ipaddress.IPv6Address(ip[24:40])
    if (
        source.is_unspecified
        or source.is_multicast
        or destination.is_link_local
        or destination.is_multicast
        or destination.is_unspecified
        or destination.packed in local_ips
    ):
        return None
    return gateway_mac + local_mac + frame[12:14] + ip[:size]


class BpfInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class BpfProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint), ("insns", ctypes.POINTER(BpfInsn))]


class Timeval(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]


class PacketHeader(ctypes.Structure):
    _fields_ = [
        ("timestamp", Timeval),
        ("captured", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
    ]


class Pcap:
    def __init__(self, interface, target_mac=None, local_mac=None):
        name = ctypes.util.find_library("pcap")
        if not name:
            raise RuntimeError("libpcap is unavailable")
        self.lib = ctypes.CDLL(name)
        lib = self.lib
        lib.pcap_create.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.pcap_create.restype = ctypes.c_void_p
        for method in (
            "pcap_set_snaplen",
            "pcap_set_promisc",
            "pcap_set_timeout",
            "pcap_set_immediate_mode",
            "pcap_setnonblock",
        ):
            getattr(lib, method).restype = ctypes.c_int
        lib.pcap_set_snaplen.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pcap_set_promisc.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pcap_set_timeout.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pcap_set_immediate_mode.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.pcap_activate.argtypes = [ctypes.c_void_p]
        lib.pcap_activate.restype = ctypes.c_int
        lib.pcap_datalink.argtypes = [ctypes.c_void_p]
        lib.pcap_datalink.restype = ctypes.c_int
        lib.pcap_setnonblock.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
        lib.pcap_compile.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(BpfProgram),
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        lib.pcap_compile.restype = ctypes.c_int
        lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram)]
        lib.pcap_setfilter.restype = ctypes.c_int
        lib.pcap_freecode.argtypes = [ctypes.POINTER(BpfProgram)]
        lib.pcap_next_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(PacketHeader)),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ]
        lib.pcap_next_ex.restype = ctypes.c_int
        lib.pcap_inject.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        lib.pcap_inject.restype = ctypes.c_int
        lib.pcap_geterr.argtypes = [ctypes.c_void_p]
        lib.pcap_geterr.restype = ctypes.c_char_p
        lib.pcap_close.argtypes = [ctypes.c_void_p]
        error = ctypes.create_string_buffer(256)
        self.handle = lib.pcap_create(interface.encode("ascii"), error)
        if not self.handle:
            raise RuntimeError(
                error.value.decode(errors="replace")
                or "Could not open network interface"
            )
        try:
            if any(
                call(self.handle, value) != 0
                for call, value in [
                    (lib.pcap_set_snaplen, MAX_FRAME),
                    (lib.pcap_set_promisc, 0),
                    (lib.pcap_set_timeout, 50),
                    (lib.pcap_set_immediate_mode, 1),
                ]
            ):
                raise RuntimeError("Could not configure packet capture")
            if (
                lib.pcap_activate(self.handle) != 0
                or lib.pcap_datalink(self.handle) != 1
            ):
                raise RuntimeError(
                    "This interface does not support Ethernet capture and injection"
                )
            if lib.pcap_setnonblock(self.handle, 1, error) != 0:
                raise RuntimeError("Could not enable nonblocking capture")
            expression = (
                f"ether src {target_mac} and ether dst {local_mac} and (ip or ip6)"
                if target_mac is not None
                else "len = 0"
            ).encode("ascii")
            program = BpfProgram()
            if (
                lib.pcap_compile(
                    self.handle, ctypes.byref(program), expression, 1, 0xFFFFFFFF
                )
                != 0
            ):
                raise RuntimeError("Could not compile the target packet filter")
            try:
                if lib.pcap_setfilter(self.handle, ctypes.byref(program)) != 0:
                    raise RuntimeError("Could not install the target packet filter")
            finally:
                lib.pcap_freecode(ctypes.byref(program))
        except Exception:
            self.close()
            raise

    def read(self):
        header = ctypes.POINTER(PacketHeader)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        result = self.lib.pcap_next_ex(
            self.handle, ctypes.byref(header), ctypes.byref(data)
        )
        if result == 0:
            return None
        if result != 1:
            raise RuntimeError("Packet capture stopped unexpectedly")
        if (
            header.contents.captured != header.contents.length
            or header.contents.captured > MAX_FRAME
        ):
            raise RuntimeError("Captured packet was truncated")
        return ctypes.string_at(data, header.contents.captured)

    def send(self, data):
        buffer = ctypes.create_string_buffer(data)
        sent = self.lib.pcap_inject(self.handle, buffer, len(data))
        if sent != len(data):
            reason = self.lib.pcap_geterr(self.handle)
            raise RuntimeError(
                "Packet injection failed: "
                + (reason.decode(errors="replace") if reason else "unknown error")
            )

    def close(self):
        if getattr(self, "handle", None):
            self.lib.pcap_close(self.handle)
            self.handle = None


def read_command(*command):
    return subprocess.check_output(
        command, text=True, stderr=subprocess.DEVNULL, timeout=4
    )


def preflight(config):
    if os.geteuid() != 0:
        raise RuntimeError(
            "Administrator access is required to open the packet interface"
        )
    interface = config["interface"]
    if not isinstance(interface, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,14}", interface
    ):
        raise ValueError("Invalid network interface")
    target_ip = ipaddress.IPv4Address(config["target_ip"])
    gateway_ip = ipaddress.IPv4Address(config["gateway_ip"])
    if not target_ip.is_private or not gateway_ip.is_private or target_ip == gateway_ip:
        raise ValueError("Target and gateway must be distinct private IPv4 addresses")
    target_mac = mac_bytes(config["target_mac"])
    gateway_mac = mac_bytes(config["gateway_mac"])
    local_mac = mac_bytes(config["local_mac"])
    if len({target_mac, gateway_mac, local_mac}) != 3:
        raise ValueError("Target, gateway and local hardware addresses must differ")
    ipv6 = config["ipv6"]
    if ipv6 is not None:
        if not isinstance(ipv6, dict) or set(ipv6) != {
            "target_ip",
            "gateway_ip",
            "gateway_mac",
        }:
            raise ValueError("Invalid IPv6 relay configuration")
        target6 = ipaddress.IPv6Address(ipv6["target_ip"])
        gateway6 = ipaddress.IPv6Address(ipv6["gateway_ip"])
        gateway6_mac = mac_bytes(ipv6["gateway_mac"])
        if (
            not target6.is_link_local
            or not gateway6.is_link_local
            or target6 == gateway6
            or gateway6_mac in (target_mac, local_mac)
        ):
            raise ValueError("IPv6 target and gateway must be distinct local neighbors")
    delay = config["delay_ms"]
    duration = config["duration_s"]
    if (
        type(delay) is not int
        or type(duration) is not int
        or not 1 <= delay <= 2000
        or not 5 <= duration <= 600
    ):
        raise ValueError("Delay or duration is outside supported limits")
    expires_at = config["expires_at"]
    if type(expires_at) is not int or not time.time() < expires_at <= time.time() + 300:
        raise RuntimeError("This relay request expired; prepare a new one in Lantern")
    if sys.platform == "darwin":
        if read_command("sysctl", "-n", "net.inet.ip.forwarding").strip() != "0":
            raise RuntimeError(
                "IP forwarding is already enabled; the relay will not change global network settings"
            )
        route = read_command("route", "-n", "get", str(gateway_ip))
        target_route = read_command("route", "-n", "get", str(target_ip))
        info = read_command("ifconfig", interface)
        if (
            f"interface: {interface}" not in route
            or f"interface: {interface}" not in target_route
            or "status: active" not in info
        ):
            raise RuntimeError(
                "The target and gateway are not on the active selected interface"
            )
        found = re.search(
            r"(?m)^\s*ether\s+((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", info
        )
        local_ips = {
            ipaddress.IPv4Address(x).packed
            for x in re.findall(r"(?m)^\s*inet\s+(\d+\.\d+\.\d+\.\d+)", info)
        }
        local_ips.update(
            ipaddress.IPv6Address(x.split("%")[0]).packed
            for x in re.findall(r"(?m)^\s*inet6\s+(\S+)", info)
        )
        if not found or mac_bytes(found.group(1)) != local_mac or not local_ips:
            raise RuntimeError("Local interface identity changed")
        for address, expected in [(target_ip, target_mac), (gateway_ip, gateway_mac)]:
            neighbor = read_command("arp", "-n", str(address))
            found = re.search(r"(?i)(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2}", neighbor)
            actual = (
                ":".join(x.zfill(2) for x in found.group().split(":")) if found else ""
            )
            if not found or mac_bytes(actual) != expected:
                raise RuntimeError(
                    "A local neighbor no longer matches the selected target or gateway"
                )
        if ipv6 is not None:
            if read_command("sysctl", "-n", "net.inet6.ip6.forwarding").strip() != "0":
                raise RuntimeError(
                    "IPv6 forwarding is enabled; Lantern will not change global network settings"
                )
            route6 = read_command("route", "-n", "get", "-inet6", "default")
            gateway_line = re.search(r"(?m)^\s*gateway:\s*(\S+)", route6)
            if (
                f"interface: {interface}" not in route6
                or not gateway_line
                or ipaddress.IPv6Address(gateway_line.group(1).split("%")[0])
                != gateway6
            ):
                raise RuntimeError("The IPv6 default gateway changed")
            neighbors6 = read_command("ndp", "-an")
            for address, expected in ((target6, target_mac), (gateway6, gateway6_mac)):
                matched = False
                for line in neighbors6.splitlines():
                    parts = line.split()
                    if len(parts) < 3 or parts[2] != interface:
                        continue
                    try:
                        found_ip = ipaddress.IPv6Address(parts[0].split("%")[0])
                        found_mac = mac_bytes(
                            ":".join(x.zfill(2) for x in parts[1].split(":"))
                        )
                    except ValueError:
                        continue
                    matched |= found_ip == address and found_mac == expected
                if not matched:
                    raise RuntimeError(
                        "An IPv6 neighbor no longer matches the target or gateway"
                    )
    elif sys.platform.startswith("linux"):
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "0":
            raise RuntimeError(
                "IP forwarding is already enabled; the relay will not change global network settings"
            )
        link = json.loads(read_command("ip", "-j", "link", "show", interface))[0]
        addresses = json.loads(
            read_command("ip", "-j", "addr", "show", "dev", interface)
        )[0]["addr_info"]
        local_ips = {
            ipaddress.IPv4Address(a["local"]).packed
            for a in addresses
            if a["family"] == "inet"
        }
        local_ips.update(
            ipaddress.IPv6Address(a["local"]).packed
            for a in addresses
            if a["family"] == "inet6"
        )
        if mac_bytes(link["address"]) != local_mac or not local_ips:
            raise RuntimeError("Local interface identity changed")
        for address, expected in [(target_ip, target_mac), (gateway_ip, gateway_mac)]:
            route = json.loads(read_command("ip", "-j", "route", "get", str(address)))[
                0
            ]
            neighbors = json.loads(
                read_command(
                    "ip", "-j", "neigh", "show", "to", str(address), "dev", interface
                )
            )
            if (
                route.get("dev") != interface
                or route.get("gateway")
                or not any(
                    mac_bytes(n.get("lladdr", "")) == expected
                    for n in neighbors
                    if n.get("lladdr")
                )
            ):
                raise RuntimeError(
                    "A route or neighbor no longer matches the selected target or gateway"
                )
        if ipv6 is not None:
            if (
                Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip()
                != "0"
            ):
                raise RuntimeError(
                    "IPv6 forwarding is enabled; Lantern will not change global network settings"
                )
            for address, expected in ((target6, target_mac), (gateway6, gateway6_mac)):
                neighbors = json.loads(
                    read_command(
                        "ip",
                        "-j",
                        "-6",
                        "neigh",
                        "show",
                        "to",
                        str(address),
                        "dev",
                        interface,
                    )
                )
                if not any(
                    mac_bytes(n["lladdr"]) == expected
                    for n in neighbors
                    if n.get("lladdr")
                ):
                    raise RuntimeError(
                        "An IPv6 neighbor no longer matches the target or gateway"
                    )
    else:
        raise RuntimeError("The packet relay currently supports macOS and Linux")
    return target_ip, gateway_ip, target_mac, gateway_mac, local_mac, local_ips


def write_status(directory, owner, payload):
    name = "status-" + secrets.token_hex(12) + ".tmp"
    temporary = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    os.fchown(temporary, owner, -1)
    with os.fdopen(temporary, "w") as handle:
        json.dump(payload, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.rename(name, "status.json", src_dir_fd=directory, dst_dir_fd=directory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    args = parser.parse_args()
    request = Path(args.request)
    if request.name != "request.json":
        raise ValueError("Invalid request path")
    directory = os.open(request.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = None
    capture = None
    control = None
    restore = None
    redirected = False
    recovered = False
    owns_request = False
    failure = None
    try:
        info = os.fstat(directory)
        owner = int(os.environ.get("SUDO_UID", os.getuid()))
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != owner
            or info.st_mode & 0o077
        ):
            raise RuntimeError(
                "Request directory must be private and owned by the requesting user"
            )
        fd = os.open("request.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        file_info = os.fstat(fd)
        if (
            not stat.S_ISREG(file_info.st_mode)
            or file_info.st_uid != owner
            or file_info.st_mode & 0o077
        ):
            raise RuntimeError(
                "Request must be a private file owned by the requesting user"
            )
        with os.fdopen(fd) as handle:
            config = json.load(handle)
        if set(config) != {
            "interface",
            "target_ip",
            "target_mac",
            "gateway_ip",
            "gateway_mac",
            "local_mac",
            "delay_ms",
            "duration_s",
            "expires_at",
            "ipv6",
        }:
            raise ValueError("Unexpected relay request fields")
        try:
            os.stat("stop", dir_fd=directory, follow_symlinks=False)
            raise RuntimeError("This relay request was canceled")
        except FileNotFoundError:
            pass
        try:
            started = os.open(
                "started",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
        except FileExistsError:
            raise RuntimeError(
                "This relay request has already been used; prepare a new one"
            )
        os.fchown(started, owner, -1)
        os.close(started)
        owns_request = True
        target_ip, gateway_ip, target_mac, gateway_mac, local_mac, local_ips = (
            preflight(config)
        )
        lockfd = os.open(
            "/tmp/lantern-relay.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        if os.fstat(lockfd).st_uid != 0 or not stat.S_ISREG(os.fstat(lockfd).st_mode):
            raise RuntimeError("Relay lock is not owned by the administrator")
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        restore = [
            arp_frame(
                local_mac, target_mac, target_ip, gateway_mac, gateway_ip, restore=True
            )
        ]
        poison = [
            arp_frame(
                local_mac, target_mac, target_ip, gateway_mac, gateway_ip, restore=False
            )
        ]
        if config["ipv6"] is not None:
            v6 = config["ipv6"]
            params = (
                local_mac,
                target_mac,
                ipaddress.IPv6Address(v6["target_ip"]),
                mac_bytes(v6["gateway_mac"]),
                ipaddress.IPv6Address(v6["gateway_ip"]),
            )
            restore.append(neighbor_frame(*params, restore=True))
            poison.append(neighbor_frame(*params, restore=False))
        capture = Pcap(config["interface"], config["target_mac"], config["local_mac"])
        # Test the injection path with a legitimate restoration before redirecting anything.
        for packet in restore:
            capture.send(packet)
        control_read, control_write = os.pipe()
        ready_read, ready_write = os.pipe()
        parent_pid = os.getpid()
        child = os.fork()
        if child == 0:
            os.close(control_write)
            os.close(ready_read)
            for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
                signal.signal(getattr(signal, name), signal.SIG_IGN)
            try:
                capture.close()
                watchdog = Pcap(config["interface"])
                os.write(ready_write, b"R")
                deadline = time.monotonic()
                if select.select([control_read], [], [], 6)[0]:
                    encoded = os.read(control_read, 8)
                    if len(encoded) == 8:
                        deadline = struct.unpack("!d", encoded)[0]
                while time.monotonic() < deadline:
                    ready, _, _ = select.select(
                        [control_read],
                        [],
                        [],
                        min(0.2, max(0, deadline - time.monotonic())),
                    )
                    if ready:
                        os.read(control_read, 1)
                        break
                # Cover neighbor-cache lockout even when the relay dies just
                # after changing the entry; the watchdog remains independent.
                for _ in range(15):
                    for packet in restore:
                        watchdog.send(packet)
                    time.sleep(0.2)
                watchdog.close()
                if os.getppid() != parent_pid:
                    write_status(
                        directory,
                        owner,
                        {
                            "state": "watchdog_restored",
                            "message": "The relay exited; recovery frames were sent. Verify the device can reach the internet.",
                        },
                    )
                os.write(ready_write, b"D")
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(control_read)
        os.close(ready_write)
        control = control_write
        if (
            not select.select([ready_read], [], [], 5)[0]
            or os.read(ready_read, 1) != b"R"
        ):
            raise RuntimeError(
                "Recovery watchdog did not start; no redirection was sent"
            )
        interrupted = [False]

        def stop(_signal, _frame):
            interrupted[0] = True

        for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"):
            signal.signal(getattr(signal, name), stop)
        queue = deque()
        queued_bytes = 0
        forwarded = 0
        forwarded_ipv4 = 0
        forwarded_ipv6 = 0
        dropped = 0
        held_ms = 0.0
        next_arp = 0.0
        next_status = 0.0
        next_watchdog = 0.0
        started = time.monotonic()
        deadline = started + config["duration_s"]
        os.write(control, struct.pack("!d", deadline))
        write_status(
            directory,
            owner,
            {
                "state": "running",
                "forwarded": 0,
                "dropped": 0,
                "message": "Applying a temporary IP delay.",
            },
        )
        while time.monotonic() < deadline and not interrupted[0]:
            now = time.monotonic()
            if now >= deadline:
                break
            if now >= next_watchdog:
                exited, _ = os.waitpid(child, os.WNOHANG)
                if exited:
                    child = None
                    raise RuntimeError(
                        "Recovery watchdog exited unexpectedly; restoring the gateway entry"
                    )
                next_watchdog = now + 1
            try:
                os.stat("stop", dir_fd=directory, follow_symlinks=False)
                interrupted[0] = True
                break
            except FileNotFoundError:
                pass
            if now >= next_status:
                write_status(
                    directory,
                    owner,
                    {
                        "state": "running",
                        "forwarded": forwarded,
                        "forwarded_ipv4": forwarded_ipv4,
                        "forwarded_ipv6": forwarded_ipv6,
                        "dropped": dropped,
                        "avg_hold_ms": round(held_ms / forwarded, 1)
                        if forwarded
                        else None,
                        "remaining_s": max(0, int(deadline - now)),
                        "message": "Relaying target traffic with added delay.",
                    },
                )
                next_status = now + 1
            if now >= next_arp:
                redirected = True
                for packet in poison:
                    capture.send(packet)
                next_arp = now + 0.1
            while queue and queue[0][0] <= now:
                _, enqueued, packet = queue.popleft()
                queued_bytes -= len(packet)
                capture.send(packet)
                if packet[12:14] == b"\x86\xdd":
                    forwarded_ipv6 += 1
                else:
                    forwarded_ipv4 += 1
                held_ms += (time.monotonic() - enqueued) * 1000
                forwarded += 1
            frame = capture.read()
            if frame is not None:
                packet = forward_frame(
                    frame, local_mac, target_mac, gateway_mac, target_ip, local_ips
                )
                if packet is None and config["ipv6"] is not None:
                    packet = forward_ipv6(
                        frame,
                        local_mac,
                        target_mac,
                        mac_bytes(config["ipv6"]["gateway_mac"]),
                        local_ips,
                    )
                if packet:
                    if queued_bytes + len(packet) > MAX_QUEUED_BYTES:
                        dropped += 1
                    else:
                        enqueued = time.monotonic()
                        queue.append(
                            (enqueued + config["delay_ms"] / 1000, enqueued, packet)
                        )
                        queued_bytes += len(packet)
            else:
                time.sleep(0.001)
            if not forwarded and time.monotonic() - started > 8:
                raise RuntimeError(
                    "No target traffic was observed; stopping and restoring its gateway entries"
                )
        while queue:
            _, enqueued, packet = queue.popleft()
            capture.send(packet)
            if packet[12:14] == b"\x86\xdd":
                forwarded_ipv6 += 1
            else:
                forwarded_ipv4 += 1
            held_ms += (time.monotonic() - enqueued) * 1000
            forwarded += 1
        os.close(control)
        control = None
        status = None
        wait_until = time.monotonic() + 8
        while time.monotonic() < wait_until:
            exited, result = os.waitpid(child, os.WNOHANG)
            if exited:
                status = result
                child = None
                break
            time.sleep(0.05)
        if status != 0:
            raise RuntimeError(
                "The recovery watchdog could not confirm sending restoration frames"
            )
        recovered = True
        message = (
            "Relay ended and gateway restoration frames were sent. Verify the target can reach the internet."
            if forwarded
            else "No target packets were observed. The delay was not verified; gateway restoration frames were sent."
        )
        write_status(
            directory,
            owner,
            {
                "state": "stopped" if interrupted[0] else "completed",
                "forwarded": forwarded,
                "forwarded_ipv4": forwarded_ipv4,
                "forwarded_ipv6": forwarded_ipv6,
                "dropped": dropped,
                "avg_hold_ms": round(held_ms / forwarded, 1) if forwarded else None,
                "message": message,
            },
        )
    except BaseException as error:
        failure = str(error)
        try:
            if owns_request:
                write_status(
                    directory,
                    owner,
                    {
                        "state": "restoring" if redirected else "failed",
                        "message": failure
                        + (
                            " Recovery is in progress."
                            if redirected
                            else " No redirection was started."
                        ),
                    },
                )
        except Exception:
            pass
        raise
    finally:
        if control is not None:
            try:
                os.close(control)
            except OSError:
                pass
        if child is not None:
            try:
                wait_until = time.monotonic() + 8
                while time.monotonic() < wait_until:
                    exited, result = os.waitpid(child, os.WNOHANG)
                    if exited:
                        recovered = result == 0
                        child = None
                        break
                    time.sleep(0.05)
                if child is not None:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
            except (ChildProcessError, ProcessLookupError):
                pass
        if redirected and not recovered and capture is not None and restore is not None:
            sent = 0
            for _ in range(15):
                try:
                    for packet in restore:
                        capture.send(packet)
                    sent += 1
                except Exception:
                    break
                time.sleep(0.2)
            recovered = sent == 15
        if failure and redirected and owns_request:
            try:
                write_status(
                    directory,
                    owner,
                    {
                        "state": "failed_restored"
                        if recovered
                        else "failed_or_unknown",
                        "message": failure
                        + (
                            ". Recovery frames were sent; verify device connectivity."
                            if recovered
                            else ". Recovery is unconfirmed; reconnect the device’s Wi-Fi if needed."
                        ),
                    },
                )
            except Exception:
                pass
        if capture is not None:
            capture.close()
        os.close(directory)


if __name__ == "__main__":
    main()
