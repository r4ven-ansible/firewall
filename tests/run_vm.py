#!/usr/bin/env python3
"""Destructive, isolated VM integration tests. Only run on a disposable Debian VM."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--host', default='192.168.122.241')
p.add_argument('--user', default='lans')
p.add_argument('--reboot', action='store_true')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
logs = Path(tempfile.mkdtemp(prefix='firewall-vm-'))
remote = '/root/' + logs.name
unit = logs.name
results = []
seq = 0
base_ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2']
master = ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=600', '-o', f'ControlPath={logs}/ssh']
env = dict(os.environ, ANSIBLE_CONFIG=str(logs / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(root.parent), ANSIBLE_NOCOLOR='1', ANSIBLE_HOST_KEY_CHECKING='True')

def run(cmd, timeout=180, check=True, stdin=None):
    global seq
    seq += 1
    name = logs / f'{seq:03}.log'
    try:
        r = subprocess.run(cmd, input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, env=env, cwd=logs)
    except subprocess.TimeoutExpired as e:
        name.write_text(shlex.join(cmd) + '\nTIMEOUT\n' + (e.stdout or b'').decode())
        raise
    name.write_text(shlex.join(cmd) + '\n' + (('STDIN:\n' + stdin + '\nOUTPUT:\n') if stdin else '') + r.stdout)
    if check and r.returncode:
        raise RuntimeError(f'rc={r.returncode}; {name}: {r.stdout[-1800:]}')
    return r

def ssh(script, **kw):
    return run(base_ssh + master + [f'{a.user}@{a.host}', 'sudo -n sh -s'], stdin=script, **kw)

def record(name, fn):
    try:
        fn()
        results.append({'test': name, 'status': 'PASS'})
    except Exception as e:
        results.append({'test': name, 'status': 'FAIL', 'detail': str(e)})
    print(json.dumps(results[-1], ensure_ascii=False), flush=True)
    (logs / 'results.json').write_text(json.dumps(results, indent=2, ensure_ascii=False))

def require(x, msg):
    if not x:
        raise AssertionError(msg)

spoof = {k: None for k in ['drop_wan_spoofed_lan_ipv4', 'drop_wan_spoofed_lan_ipv6', 'fwd_drop_wan_spoofed_lan_ipv4', 'fwd_drop_wan_spoofed_lan_ipv6']}
base = dict(firewall_enabled=True, nft_flush_ruleset=True, nft_remove_other_firewall=False, nft_restart_docker=False, nft_apt_update_cache=False, nft_lan4_networks=['10.0.0.0/8', '172.16.0.0/12'], nft_trusted_ips=['203.0.113.123'], nft_rollback_timeout=20, nft_ssh_check_timeout=7, nft_backup_keep=3, nft_rules_extra=spoof)
# Suppress flood only between scenarios; its actual original rule is tested separately.
base['nft_rules_extra'] = dict(spoof, wan_ssh_flood_ipv4=None, wan_ssh_flood_ipv6=None)
(logs / 'inventory').write_text(f'vm ansible_host={a.host} ansible_user={a.user} ansible_python_interpreter=/usr/bin/python3\n')
(logs / 'ansible.cfg').write_text('[defaults]\nretry_files_enabled=False\n[ssh_connection]\nssh_args=' + shlex.join(base_ssh[1:] + master) + '\n')
(logs / 'play.yml').write_text(json.dumps([dict(hosts='vm', become=True, gather_facts=True, vars_files=[str(root / 'examples/inventory/group_vars/all/firewall.yml')], roles=[str(root)])]))

def play(extra=None, flags=(), expected=0, timeout=140):
    v = dict(base)
    if extra:
        v.update(extra)
    vars_path = logs / f'{seq + 1:03}-vars.json'
    vars_path.write_text(json.dumps(v))
    r = run(['ansible-playbook', '-i', str(logs / 'inventory'), str(logs / 'play.yml'), '-e', '@' + str(vars_path), *flags], timeout=timeout, check=False)
    require((r.returncode == 0) if expected == 0 else (r.returncode != 0), f'Unexpected Ansible rc={r.returncode}: {r.stdout[-2000:]}')
    return r

def state():
    return ssh("sha256sum /etc/nftables.conf; systemctl is-enabled nftables; systemctl is-active nftables; /usr/sbin/nft -s list ruleset; find /root/nft_backup -type f -printf '%f %s %T@\\n' 2>/dev/null | sort", check=False).stdout

def probe(port, udp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            if udp:
                s.sendto(b'test', (a.host, port))
                return s.recv(100) == b'test'
            s.connect((a.host, port))
            return True
        except OSError:
            return False

restore = f'''#!/bin/sh
set -eu
cd {remote}
if ! test -x /usr/sbin/nft; then DEBIAN_FRONTEND=noninteractive apt-get install -y nftables; fi
systemctl unmask nftables.service || true
systemctl unmask --runtime nftables.service || true
systemctl disable nftables.service || true
systemctl disable --runtime nftables.service || true
if test -e config-present; then rm -f /etc/nftables.conf; cp -a config /etc/nftables.conf; else rm -f /etc/nftables.conf; fi
rm -rf /root/nft_backup
if test -e history-present; then cp -a history /root/nft_backup; fi
case "$(cat active)" in active) systemctl start nftables;; *) systemctl stop nftables || true;; esac
/usr/sbin/nft -f runtime
case "$(cat enabled)" in enabled) systemctl enable nftables;; enabled-runtime) systemctl enable --runtime nftables;; esac
case "$(cat mask)" in masked) systemctl mask nftables;; masked-runtime) systemctl mask --runtime nftables;; esac
touch restored
'''
print(f'Logs: {logs}; emergency snapshot: {remote}', flush=True)
ssh(f'''set -eu
umask 077
mkdir {remote}
cd {remote}
test -x /usr/sbin/nft
printf 'flush ruleset\\n' > runtime
/usr/sbin/nft list ruleset >> runtime
/usr/sbin/nft -s list ruleset > runtime-static
if test -e /etc/nftables.conf || test -L /etc/nftables.conf; then cp -a /etc/nftables.conf config; touch config-present; fi
if test -e /root/nft_backup; then cp -a /root/nft_backup history; touch history-present; fi
systemctl is-active nftables > active || true
systemctl is-enabled nftables > mask || true
cp mask enabled
if find /etc/systemd/system -type l -path '*.wants/nftables.service' | grep -q .; then echo enabled > enabled; fi
cat > restore <<'RESTORE'
{restore}
RESTORE
chmod 700 restore
systemd-run --unit={unit} --on-active=25m {remote}/restore
''')

def arm():
    ssh(f'systemctl stop {unit}.timer {unit}.service || true; systemd-run --unit={unit} --on-active=180s {remote}/restore')

try:
    arm()
    # History is isolated after preserving the original, to make rotation deterministic.
    ssh('rm -rf /root/nft_backup')
    def positive(extra=None):
        def artifacts():
            return ssh("systemctl list-units --all --plain --no-legend --state=active,activating 'nft-rollback-*.timer'; find /tmp -maxdepth 1 -type d -name 'nft-transaction-*' -printf '%p\\n' | sort").stdout.splitlines()
        before = set(artifacts())
        r = play(extra, flags=('-t', 'nft_apply'))
        require(not (set(artifacts()) - before), 'successful apply leaked active rollback timer or transaction directory')
        return r
    record('baseline apply and timer cleanup', positive)
    def idem(extra=None):
        before = state()
        r = play(extra, flags=('-t', 'nft_apply'))
        require('changed=0' in r.stdout, 'not idempotent')
        require(state() == before, 'state/history changed')
    record('backup/idempotence', idem)
    def checkdiff():
        before = state()
        r = play({'nft_allowed_ports': ['18080/tcp', '18081/udp']}, flags=('-t', 'nft_apply', '--check', '--diff'))
        require('18080' in r.stdout and '18081' in r.stdout and '---' in r.stdout, 'missing diff')
        require(state() == before, 'check mutated state')
    record('tagged check diff', checkdiff)
    def syntax():
        before = state()
        play({'nft_rules_extra': dict(base['nft_rules_extra'], invalid=dict(order=1, family='inet', table='filter', chain='input', expr='THIS IS NOT NFT SYNTAX'))}, expected=1)
        require(state() == before, 'syntax failure mutated state')
    record('syntax failure', syntax)
    # This scenario preserves established management but rejects new SSH.
    def newssh():
        before = ssh('sha256sum /etc/nftables.conf; /usr/sbin/nft -s list ruleset; systemctl is-enabled nftables').stdout
        play({'nft_rules_extra': dict(base['nft_rules_extra'], wan_allow_ssh=None), 'nft_rollback_timeout': 60}, expected=1)
        after = ssh('sha256sum /etc/nftables.conf; /usr/sbin/nft -s list ruleset; systemctl is-enabled nftables').stdout
        require(before == after, 'immediate rollback did not restore config/runtime/service')
        require(ssh("grep -l rolled-back /tmp/nft-transaction-*/state").stdout.strip(), 'no rolled-back transaction')
    record('new SSH immediate rollback', newssh)
    def blocked():
        arm()
        before = ssh('sha256sum /etc/nftables.conf; /usr/sbin/nft -s list ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout
        # Drop at input order 1, before established; timeout exceeds rollback to exercise false success race.
        drop = dict(order=1, family='inet', table='filter', chain='input', match={'tcp': {'dport': 22}}, action='drop', comment='TEST full SSH block')
        play({'nft_rules_extra': dict(base['nft_rules_extra'], full_block=drop), 'nft_ssh_check_timeout': 40, 'nft_rollback_timeout': 15}, expected=1, timeout=110)
        # systemd-run timers have default coalescing, so OnActiveSec is not a deadline.
        deadline = time.monotonic() + 100
        while True:
            restored = ssh('sha256sum /etc/nftables.conf; /usr/sbin/nft -s list ruleset; systemctl is-enabled nftables; systemctl is-active nftables', check=False, timeout=15)
            if restored.returncode == 0 or time.monotonic() >= deadline:
                break
            time.sleep(3)
        require(restored.returncode == 0, 'SSH not restored within bounded rollback wait')
        require(before == restored.stdout, 'full block rollback state mismatch')
        evidence = ssh("journalctl --since '-3 minutes' --no-pager -o short-monotonic -u 'nft-rollback-*'; for d in /tmp/nft-transaction-*; do test -f \"$d/candidate\" && grep -q 'TEST full SSH block' \"$d/candidate\" && cat \"$d/state\"; done", check=False).stdout
        require('rolled-back' in evidence and '.service - [systemd-run]' in evidence and 'Deactivated successfully' in evidence, 'no independent timer evidence')
    record('full SSH block / timer / nonzero rc / enabled unmasked', blocked)
    def timer_race():
        arm()
        before = ssh('sha256sum /etc/nftables.conf; /usr/sbin/nft -s list ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout
        import threading
        ready = threading.Event()
        def delayed_listener():
            time.sleep(110)
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', 18199))
                s.listen()
                s.settimeout(35)
                ready.set()
                try:
                    c, _ = s.accept()
                    c.close()
                except OSError:
                    pass
        thread = threading.Thread(target=delayed_listener, daemon=True)
        thread.start()
        r = play({'nft_allowed_ports': ['18100'], 'nft_rollback_timeout': 5, 'nft_ssh_check_timeout': 140, 'nft_ssh_check_host': '127.0.0.1', 'nft_ssh_check_port': 18199}, expected=1, timeout=200)
        thread.join(timeout=35)
        require(ready.is_set(), 'delayed probe listener unavailable')
        commit_output = r.stdout.split('TASK [firewall : Commit only if rollback has not started]')[-1].split('TASK [')[0]
        require('fatal:' in commit_output and 'non-zero return code' in commit_output, 'did not exercise post-timer commit failure')
        require(before == ssh('sha256sum /etc/nftables.conf; /usr/sbin/nft -s list ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout, 'timer race restoration mismatch')
    record('timer wins despite successful SSH / no false success', timer_race)
    arm()
    def extras():
        ex = dict(base['nft_rules_extra'], wan_allow_ssh={'comment': 'TEST changed SSH'}, test_add=dict(order=114, family='inet', table='filter', chain='input_wan', match={'tcp': {'dport': 18082}}, action='accept', comment='TEST added'))
        positive({'nft_rules_extra': ex, 'nft_allowed_ports': ['22/tcp', '18080/tcp', '18081/udp']})
        text = ssh('cat /etc/nftables.conf').stdout
        require('TEST changed SSH' in text and 'TEST added' in text and 'Drop spoofed' not in text, 'add/change/null not rendered')
        require('tcp dport { 22,' not in text, 'SSH not excluded from generic ports')
    record('extra add/change/null and allowed ports', extras)
    def wan():
        listener = '''import socket,threading,time
listeners=[]
for port in (18080,18082,18083):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen(100);listeners.append(s)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',18081))
while True:
 d,a=s.recvfrom(1024);s.sendto(d,a)
'''
        ssh(f"cat > {remote}/listen.py <<'PY'\n{listener}\nPY\nsystemd-run --unit={unit}-listener /usr/bin/python3 {remote}/listen.py")
        time.sleep(2)
        require(probe(18080) and probe(18082) and probe(18081, True) and not probe(18083), 'WAN positive/negative TCP/UDP probe failed')
    record('WAN TCP/UDP live probes', wan)
    def history():
        for ports in (['18084'], ['18085'], ['18086'], ['18087']):
            # Old source mtime must not make a newly created history entry look old.
            snapshot = ssh('set -eu; touch -d 2000-01-01 /etc/nftables.conf; sha256sum /etc/nftables.conf; date +%s').stdout.splitlines()
            digest = snapshot[0].split()[0]
            started = int(snapshot[1])
            positive({'nft_allowed_ports': ports})
            backup = f'/root/nft_backup/nftables.conf_{digest}'
            saved = ssh(f'set -eu; sha256sum {backup}; stat -c %Y {backup}').stdout.splitlines()
            require(saved[0].split()[0] == digest and int(saved[1]) >= started, 'backup content or creation mtime mismatch')
        rows = ssh("find /root/nft_backup -type f -printf '%f %m\\n'").stdout.splitlines()
        require(len(rows) == 3 and all(r.endswith('600') for r in rows), 'history rotation/mode mismatch')
        idem({'nft_allowed_ports': ports})
    record('history rotation and repeat idempotence', history)
    def flood():
        play({'nft_ssh_check_enabled': False, 'nft_rules_extra': spoof}, flags=('-t', 'nft_apply'))
        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            hits = list(pool.map(lambda _: probe(22), range(60)))
        require(any(hits) and not all(hits), f'no measurable limit: {sum(hits)}/60')
        require('192.168.' in ssh('/usr/sbin/nft list set inet filter ssh_flood4').stdout, 'source missing in dynamic set')
        positive()
    record('SSH flood rate limit (persistent management)', flood)
    def absent():
        arm()
        # Cache reinstall artifact first, no purge: retain package-owned configuration.
        ssh(f'cd {remote}; apt-get download nftables >/dev/null', timeout=90)
        ssh('dpkg --remove nftables', timeout=90)
        try:
            absent_before = ssh('test ! -e /usr/sbin/nft; test ! -e /usr/lib/systemd/system/nftables.service; sha256sum /etc/nftables.conf; systemctl daemon-reload; systemctl show nftables -p LoadState').stdout
            require('LoadState=not-found' in absent_before, 'service still installed')
            r = play({'nft_allowed_ports': ['18090']}, flags=('--check', '--diff'))
            require('nftables is not installed' in r.stdout, 'missing limited-check warning')
            after = ssh('test ! -e /usr/sbin/nft; test ! -e /usr/lib/systemd/system/nftables.service; sha256sum /etc/nftables.conf; systemctl show nftables -p LoadState').stdout
            require(after == absent_before, 'absent check mutated package/config/service')
        finally:
            ssh('DEBIAN_FRONTEND=noninteractive apt-get install -y nftables; systemctl daemon-reload', timeout=120)
    record('check without installed nftables and service', absent)
    def timers_clean():
        active = ssh("systemctl list-units --all --plain --no-legend --state=active,activating 'nft-rollback-*.timer' 'nft-rollback-*.service'").stdout.strip()
        require(not active, f'rollback units still active: {active}')
    record('rollback timer/service cleanup before reboot', timers_clean)
    if a.reboot:
        def reboot():
            positive({'nft_allowed_ports': ['18101']})
            before = ssh('cat /proc/sys/kernel/random/boot_id; sha256sum /etc/nftables.conf').stdout.splitlines()
            # Independent safety survives reboot via a persistent on-boot timer.
            ssh(f"printf '[Unit]\\nDescription=Firewall test emergency restore\\n[Service]\\nType=oneshot\\nExecStart={remote}/restore\\n' > /etc/systemd/system/{unit}-boot.service\nprintf '[Timer]\\nOnBootSec=180\\n[Install]\\nWantedBy=timers.target\\n' > /etc/systemd/system/{unit}-boot.timer\nsystemctl daemon-reload; systemctl enable {unit}-boot.timer; systemctl reboot", check=False)
            time.sleep(15)
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                r = ssh('cat /proc/sys/kernel/random/boot_id; sha256sum /etc/nftables.conf; systemctl is-enabled nftables; systemctl is-active nftables; /usr/sbin/nft list table inet filter', check=False, timeout=15)
                if r.returncode == 0:
                    break
                time.sleep(4)
            require(r.returncode == 0 and before[0] not in r.stdout and before[1] in r.stdout and 'enabled\nactive' in r.stdout, 'reboot persistence failed')
        record('reboot persistence', reboot)
finally:
    def cleanup():
        ssh(f'{remote}/restore', timeout=180)
        ssh(f"set -eu; systemctl stop {unit}.timer {unit}.service {unit}-listener.service {unit}-boot.timer || true; systemctl disable {unit}-boot.timer || true; rm -f /etc/systemd/system/{unit}-boot.timer /etc/systemd/system/{unit}-boot.service; systemctl daemon-reload; cd {remote}; cmp config /etc/nftables.conf; /usr/sbin/nft -s list ruleset > final-runtime; cmp runtime-static final-runtime; test \"$(systemctl is-enabled nftables)\" = \"$(cat mask)\"; test \"$(systemctl is-active nftables)\" = \"$(cat active)\"; if test -e history-present; then diff -r history /root/nft_backup; else test ! -e /root/nft_backup; fi", timeout=60)
    record('restore original config/runtime/service/history', cleanup)
print(f'Results: {logs}/results.json', flush=True)
raise SystemExit(int(any(r['status'] == 'FAIL' for r in results)))
