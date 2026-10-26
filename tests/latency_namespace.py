"""Verify device delay using real traffic in isolated network and mount namespaces."""
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def main():
    if 'LANTERN_PARENT_NETNS' not in os.environ:
        subprocess.run(['unshare', '-Urnm', sys.executable, __file__, sys.argv[1]],
                       env=dict(os.environ, LANTERN_PARENT_NETNS=os.readlink('/proc/self/ns/net')), check=True)
        return
    assert os.readlink('/proc/self/ns/net') != os.environ['LANTERN_PARENT_NETNS']
    binary = str(Path(sys.argv[1]).resolve())
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', 'tmpfs', '/tmp')
    children = []
    process = None
    try:
        run('ip', 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', 'br-lan', 'type', 'bridge')
        run('ip', 'link', 'set', 'br-lan', 'up')
        run('ip', 'addr', 'add', '192.168.66.1/24', 'dev', 'br-lan')
        macs = ['02:aa:bb:cc:dd:ee', '02:aa:bb:cc:dd:ef']
        for index, mac in enumerate(macs):
            child = subprocess.Popen(['unshare', '-n', 'sleep', '180'])
            children.append(child)
            run('ip', 'link', 'add', f'lan{index}', 'type', 'veth', 'peer', 'name', f'client{index}')
            run('ip', 'link', 'set', f'lan{index}', 'master', 'br-lan')
            run('ip', 'link', 'set', f'lan{index}', 'up')
            run('ip', 'link', 'set', f'client{index}', 'netns', str(child.pid))
            def inside(*args): return run('nsenter', '-t', str(child.pid), '-n', *args)
            inside('ip', 'link', 'set', 'lo', 'up')
            inside('ip', 'link', 'set', f'client{index}', 'address', mac)
            inside('ip', 'link', 'set', f'client{index}', 'up')
            inside('ip', 'addr', 'add', f'192.168.66.{index + 2}/24', 'dev', f'client{index}')
            run('ping', '-n', '-c', '1', '-W', '2', f'192.168.66.{index + 2}')
            run('ip', 'neigh', 'replace', f'192.168.66.{index + 2}', 'lladdr', mac, 'nud', 'permanent', 'dev', 'br-lan')
        run('nft', 'add', 'table', 'inet', 'unrelated_test')
        with tempfile.TemporaryDirectory(prefix='lantern-latency-') as directory:
            transport = Path(directory) / 'ssh'
            transport.write_text('#!/bin/sh\nfor arg do script=$arg; done\nexec /bin/sh -c "$script"\n')
            transport.chmod(0o700)
            process = subprocess.Popen([binary, '--no-open'], stdout=subprocess.PIPE, text=True,
                                       env=dict(os.environ, PATH=f'{directory}:{os.environ["PATH"]}'))
            port = int(re.search(r'http://127\.0\.0\.1:(\d+)', process.stdout.readline())[1])
            def request(path, data=None, token=''):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
                connection.request('POST' if data is not None else 'GET', path, json.dumps(data) if data is not None else None, {'Content-Type': 'application/json', 'X-Lantern-Token': token})
                response = connection.getresponse()
                code, body = response.status, response.read().decode()
                connection.close()
                return code, body
            token = re.search(r'name="lantern-token" content="([^"]+)"', request('/')[1])[1]
            def api(path, data, expected=200):
                code, body = request('/api/' + path, data, token)
                assert code == expected, (code, body)
                return json.loads(body)
            def ping(index):
                output = run('ping', '-n', '-c', '2', '-W', '2', f'192.168.66.{index + 2}')
                return float(re.search(r'= [\d.]+/([\d.]+)/', output)[1])
            api('router', {'kind':'openwrt','host':'192.168.66.1','user':'root'})
            api('device/latency', {'mac':macs[0], 'delay_ms':120, 'jitter_ms':0})
            assert ping(0) >= 90 and ping(1) < 60
            policies = api('latencies', {})['policies']
            assert len(policies) == 1 and policies[0]['delay_ms'] == 120 and policies[0]['packets'] > 0
            api('device/latency', {'mac':macs[0], 'delay_ms':200, 'jitter_ms':20})
            assert ping(0) >= 150
            api('device/latency', {'mac':macs[1], 'delay_ms':100, 'jitter_ms':0})
            assert len(api('latencies', {})['policies']) == 2
            run('tc', 'filter', 'add', 'dev', 'br-lan', 'parent', 'ca71:', 'protocol', 'all', 'pref', '999', 'flower', 'dst_mac', macs[1], 'classid', 'ca71:1')
            assert 'Unrecognized latency filter' in api('latencies', {}, 400)['error']
            run('tc', 'filter', 'del', 'dev', 'br-lan', 'parent', 'ca71:', 'protocol', 'all', 'pref', '999')
            api('device/latency', {'mac':macs[0], 'delay_ms':0, 'jitter_ms':0})
            assert ping(0) < 60 and ping(1) >= 75
            api('device/latency', {'mac':macs[1], 'delay_ms':0, 'jitter_ms':0})
            assert not api('latencies', {})['policies']
            assert json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', 'br-lan'))[0]['kind'] == 'noqueue'
            run('nft', 'list', 'table', 'inet', 'unrelated_test')
            run('tc', 'qdisc', 'add', 'dev', 'br-lan', 'root', 'fq_codel')
            assert 'already has a root queue' in api('device/latency', {'mac':macs[0], 'delay_ms':100, 'jitter_ms':0}, 400)['error']
            assert json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', 'br-lan'))[0]['kind'] == 'fq_codel'
            print('PASS: targeted real ping delay, unaffected device, jitter update, independent policies, removal, root queue preservation')
    finally:
        if process:
            process.terminate()
            process.wait(timeout=5)
        for child in children:
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    main()
