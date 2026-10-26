"""Exercise the compiled service without contacting a gateway or changing a network."""
import http.client
import json
import re
import socket
import subprocess
import sys
import unittest


class ServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.process = subprocess.Popen(
            [sys.argv[1], "--no-open"], stdout=subprocess.PIPE, text=True
        )
        line = cls.process.stdout.readline()
        match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        if not match:
            cls.process.terminate()
            raise RuntimeError(f"Server did not announce a port: {line}")
        cls.port = int(match[1])
        cls.authority = f"127.0.0.1:{cls.port}"
        connection = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        html = response.read().decode()
        cls.token = re.search(r'name="lantern-token" content="([^"]+)"', html)[1]
        connection.close()

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.process.stdout.close()

    def request(self, path, method="GET", payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        merged = {"X-Lantern-Token": self.token, "Content-Type": "application/json"}
        if headers:
            merged.update(headers)
        connection.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=merged)
        response = connection.getresponse()
        status, body, response_headers = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return status, body, response_headers

    def test_origin_host_and_token_boundaries(self):
        self.assertEqual(self.request("/api/state", headers={"X-Lantern-Token": "bad"})[0], 401)
        self.assertEqual(self.request("/api/state", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("/", headers={"Host": "evil.example"})[0], 403)
        status, body, headers = self.request("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["gateway"], None)
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertEqual(headers["cache-control"], "no-store")

    def test_validation_and_no_implicit_gateway(self):
        status, body, _ = self.request("/api/router", "POST", {"kind": "openwrt", "host": "8.8.8.8", "user": "root"})
        self.assertEqual(status, 400)
        self.assertIn("private", json.loads(body)["error"])
        self.assertEqual(self.request("/api/device", "POST", {"mac": "02:aa:bb:cc:dd:ee", "action": "block"})[0], 400)
        self.assertEqual(self.request("/api/profiles", "POST", {"name": "x", "down_kbps": 0, "up_kbps": 80})[0], 400)
        self.assertEqual(self.request("/api/device/identify", "POST", {"mac": "02:aa:bb:cc:dd:ee"})[0], 400)
        self.assertEqual(self.request("/api/device/ping", "POST", {"mac": "02:aa:bb:cc:dd:ee"})[0], 400)
        self.assertEqual(self.request("/api/device/ping", "POST", {"mac": "02:aa:bb:cc:dd:ee", "ip": "8.8.8.8"})[0], 422)
        self.assertEqual(self.request("/api/router/ssh/probe", "POST", {"kind":"movistar", "host":"8.8.8.8"})[0],400)
        self.assertEqual(self.request("/api/router/cli/status", "POST")[0],400)
        self.assertEqual(self.request("/api/access", "POST")[0],400)
        self.assertEqual(self.request("/api/limits", "POST")[0],400)
        self.assertEqual(self.request("/api/network/traffic", "POST")[0],400)
        self.assertEqual(self.request("/api/device/limit", "POST", {"mac":"02:aa:bb:cc:dd:ee","up_kbps":63,"down_kbps":1000})[0],400)

    def test_profile_lifecycle_uses_real_handler_responses(self):
        status, body, _ = self.request("/api/profiles", "POST", {"name": "Test browser", "down_kbps": 800, "up_kbps": 80})
        self.assertEqual(status, 200)
        profile = json.loads(body)["profile"]
        with socket.create_connection(("127.0.0.1", profile["port"]), timeout=3) as client:
            client.sendall(bytes([5, 1, 0]))
            self.assertEqual(client.recv(2), bytes([5, 0]))
            # UDP ASSOCIATE is explicitly unsupported, not silently forwarded.
            client.sendall(bytes([5, 3, 0, 1, 127, 0, 0, 1, 0, 80]))
            self.assertEqual(client.recv(10)[1], 7)
        path = f'/api/profiles/{profile["id"]}'
        self.assertEqual(self.request(path, "PUT", {"name": "Renamed", "down_kbps": 160, "up_kbps": 80})[0], 200)
        state = json.loads(self.request("/api/state")[1])
        found = next(p for p in state["profiles"] if p["id"] == profile["id"])
        self.assertEqual(found["down_kbps"], 160)
        self.assertEqual(found["name"], "Renamed")
        self.assertEqual(self.request(path, "DELETE")[0], 200)
        self.assertEqual(self.request(path, "DELETE")[0], 400)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
