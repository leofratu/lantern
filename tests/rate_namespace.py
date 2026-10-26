"""Exercise real netdev rate policies and packet drops in an isolated bridge.

Only SSH transport is substituted. No physical interface, router, or host
firewall is touched. Run with Python 3 and a compiled Lantern executable.
"""
import http.client
import errno
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    namespace = os.readlink('/proc/self/ns/net')
    parent = os.environ.get('LANTERN_PARENT_NETNS')
    if parent is None:
        subprocess.run(['unshare', '-Urn', sys.executable, __file__, sys.argv[1]], env=dict(os.environ, LANTERN_PARENT_NETNS=namespace), check=True)
        return
    if namespace == parent:
        raise SystemExit('Refusing the host network namespace')
    binary = str(Path(sys.argv[1]).resolve())
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'br-lan', 'type', 'bridge')
    run('ip', 'link', 'add', 'lan-port', 'type', 'veth', 'peer', 'name', 'client-port')
    run('ip', 'link', 'set', 'lan-port', 'master', 'br-lan')
    for device in ['br-lan', 'lan-port', 'client-port']:
        run('ip', 'link', 'set', device, 'up')
    run('ip', 'addr', 'add', '192.168.66.1/24', 'dev', 'br-lan')
    mac = '02:aa:bb:cc:dd:ee'
    other = '02:aa:bb:cc:dd:ef'
    run('ip', 'link', 'set', 'client-port', 'address', mac)
    for ip, address in [('192.168.66.2', mac), ('192.168.66.3', other)]:
        run('ip', 'neigh', 'add', ip, 'lladdr', address, 'nud', 'permanent', 'dev', 'br-lan')
    run('nft', 'add', 'table', 'inet', 'unrelated_test')
    gateway = json.loads(run('ip', '-j', 'link', 'show', 'br-lan'))[0]['address']
    with tempfile.TemporaryDirectory(prefix='lantern-rate-') as directory:
        transport = Path(directory) / 'ssh'
        transport.write_text('#!/bin/sh\nfor arg do script=$arg; done\nexec /bin/sh -c "$script"\n')
        transport.chmod(0o700)
        process = subprocess.Popen([binary, '--no-open'], stdout=subprocess.PIPE, text=True, env=dict(os.environ, PATH=f'{directory}:{os.environ["PATH"]}'))
        try:
            port = int(re.search(r'http://127\.0\.0\.1:(\d+)', process.stdout.readline())[1])
            def request(path, data=None, token=None):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
                connection.request('POST' if data is not None else 'GET', path, json.dumps(data) if data is not None else None, {'Content-Type':'application/json', 'X-Lantern-Token':token or ''})
                response = connection.getresponse()
                code, body = response.status, response.read().decode()
                connection.close()
                return code, body
            token = re.search(r'name="lantern-token" content="([^"]+)"', request('/')[1])[1]
            def api(path, data=None, expected=200):
                code, body = request('/api/'+path, data, token)
                assert code == expected, (code, body)
                return json.loads(body)
            api('router', {'kind':'openwrt','host':'192.168.66.1','user':'root'})
            limit = {'mac':mac,'up_kbps':1000,'down_kbps':2000}
            assert api('device/limit',limit)['outcome'] == 'rate_policy_verified'
            api('device/limit',limit)
            actual = api('limits',{})['limits']
            assert len(actual) == 1 and actual[0]['interface'] == 'br-lan'
            assert (actual[0]['up_kbps'],actual[0]['down_kbps']) == (1000,2000)

            def frames(interface, source, target):
                payload = bytes.fromhex(target.replace(':','')) + bytes.fromhex(source.replace(':','')) + b'\x88\xb5' + b'LANTERN-ISOLATED-TEST'.ljust(1000,b'x')
                with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as sender:
                    sender.bind((interface,0))
                    for _ in range(3000):
                        try:
                            sender.send(payload)
                        except OSError as error:
                            # A netdev egress DROP is surfaced to AF_PACKET senders
                            # as ENOBUFS. Actual nft counters below must prove drops.
                            if error.errno != errno.ENOBUFS:
                                raise
                return len(payload)*3000
            uploaded = frames('client-port',mac,gateway)
            downloaded = frames('br-lan',gateway,mac)
            observed = api('limits',{})['limits'][0]
            assert 1_000_000 < observed['up_dropped_bytes'] < uploaded, observed
            assert 1_000_000 < observed['down_dropped_bytes'] < downloaded, observed
            # Traffic for a different MAC must not consume this device's budget.
            frames('client-port',other,gateway)
            frames('br-lan',gateway,other)
            again = api('limits',{})['limits'][0]
            assert again['up_dropped_bytes'] == observed['up_dropped_bytes']
            assert again['down_dropped_bytes'] == observed['down_dropped_bytes']
            api('device/limit',{'mac':other,'up_kbps':1024,'down_kbps':2048})
            assert len(api('limits',{})['limits']) == 2
            # Removing a vanished device preserves the other policy.
            run('ip','neigh','del','192.168.66.2','dev','br-lan')
            api('refresh',{})
            api('device/limit',{'mac':mac,'up_kbps':0,'down_kbps':0})
            api('device/limit',{'mac':mac,'up_kbps':0,'down_kbps':0})
            assert [entry['mac'] for entry in api('limits',{})['limits']] == [other]
            run('nft','list','table','inet','unrelated_test')
            # Refuse offloaded paths without changing the installed policy.
            uci = Path(directory)/'uci'
            uci.write_text('#!/bin/sh\nprintf "1\\n"\n')
            uci.chmod(0o700)
            error = api('device/limit',{'mac':other,'up_kbps':2000,'down_kbps':3000},expected=400)
            assert 'offloading' in error['error']
            assert api('limits',{})['limits'][0]['up_kbps'] == 1024
            uci.unlink()
            rules = json.loads(run('nft','-j','list','table','netdev','lantern_rate_v1'))['nftables']
            rule = next(item['rule'] for item in rules if 'rule' in item)
            run('nft','replace','rule','netdev','lantern_rate_v1',rule['chain'],'handle',str(rule['handle']),'ether','saddr',other,'counter','accept','comment',f'"{rule["comment"]}"')
            assert 'unverified' in api('limits',{},expected=400)['error']
            run('nft','delete','table','netdev','lantern_rate_v1')
            run('nft','add','table','netdev','lantern_rate_v1')
            assert 'ownership' in api('limits',{},expected=400)['error']
            print('PASS: bridge ingress upload and egress download packet drops, distinct MAC budgets, real rate readback, idempotency, binary units, vanished-device removal, offload refusal, unrelated-table preservation, altered-rule and ownership rejection')
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdout.close()


if __name__ == '__main__':
    main()
