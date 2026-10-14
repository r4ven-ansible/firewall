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
import threading
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--host', default='192.168.122.241')
p.add_argument('--user', default='lans')
p.add_argument('--reboot', action='store_true')
p.add_argument('--bastion', help='host to test ProxyJump/delegated reachability through (needs the same credentials)')
p.add_argument('--docker', action='store_true', help='also cover coexistence with an already installed Docker')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
state_dir = '/var/lib/nftables-firewall'
logs = Path(tempfile.mkdtemp(prefix='firewall-vm-'))
remote = '/root/' + logs.name
unit = logs.name
results = []
seq = 0
seq_lock = threading.Lock()
base_ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2']
master = ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=600', '-o', f'ControlPath={logs}/ssh']
env = dict(os.environ, ANSIBLE_CONFIG=str(logs / 'ansible.cfg'), ANSIBLE_ROLES_PATH=str(root.parent), ANSIBLE_NOCOLOR='1', ANSIBLE_HOST_KEY_CHECKING='True')

def run(cmd, timeout=180, check=True, stdin=None):
    global seq
    with seq_lock:
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

privileged = 'sh -s' if a.user == 'root' else 'sudo -n sh -s'


def ssh(script, **kw):
    return run(base_ssh + master + [f'{a.user}@{a.host}', privileged], stdin=script, **kw)

def reserve_port():
    # Bound but not listening: a probe gets refused until the scenario calls
    # listen(), and the number cannot clash with another run on this host.
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 0))
    return sock, sock.getsockname()[1]


def ssh_fresh():
    return run(base_ssh + ['-o', 'ControlPath=none', f'{a.user}@{a.host}', 'true'], check=False, timeout=40)


def wait_ssh(seconds=660):
    deadline = time.monotonic() + seconds
    while True:
        if ssh_fresh().returncode == 0:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(15)


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

# The WAN spoof guards stay enabled and nft_lan4_networks keeps 192.168.0.0/16
# from the shipped baseline: the management source of this VM is inside it, so
# every scenario doubles as a regression test for the lockout that used to make
# a first rollout roll back.
base = dict(firewall_enabled=True, nft_flush_ruleset=True, nft_remove_other_firewall=False, nft_restart_docker=False, nft_apt_update_cache=False, nft_trusted_ips=['203.0.113.123'], nft_rollback_timeout=40, nft_ssh_check_timeout=10, nft_backup_keep=3)
# Suppress flood only between scenarios; its actual original rule is tested separately.
base['nft_rules_extra'] = dict(wan_ssh_flood_ipv4=None, wan_ssh_flood_ipv6=None)
# In the baseline the controller is an on-link neighbour of this VM, so it is
# classified as LAN. Scenarios that assert WAN-side behaviour (port policy, flood
# limits, WAN SSH denial) have to move it outside the LAN classification first.
wan_view = {'nft_lan4_networks': ['10.0.0.0/8', '172.16.0.0/12']}
# Both the management allow rule and the on-link spoof exceptions independently
# prevent the lockout this role was fixed for; reproducing it needs both off.
# The guard only bites a source the baseline calls private, so the controller's
# real source address is added to @lan4 for that scenario: on a public-WAN host
# it is not inside 192.168.0.0/16 and nothing would be dropped otherwise.
mgmt_source = run(base_ssh + master + [f'{a.user}@{a.host}', 'printf %s "${SSH_CLIENT%% *}"']).stdout.strip()
unprotected = {'nft_mgmt_allow_enabled': False, 'nft_wan_local4_networks': [],
               'nft_lan4_networks': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', f'{mgmt_source}/32']}
(logs / 'inventory').write_text(f'vm ansible_host={a.host} ansible_user={a.user} ansible_python_interpreter=/usr/bin/python3\n')
(logs / 'ansible.cfg').write_text('[defaults]\nretry_files_enabled=False\n[ssh_connection]\nssh_args=' + shlex.join(base_ssh[1:] + master) + '\n')
(logs / 'play.yml').write_text(json.dumps([dict(hosts='vm', become=a.user != 'root', gather_facts=True, vars_files=[str(root / 'examples/inventory/group_vars/all/firewall.yml')], roles=[str(root)])]))

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
    return ssh("sha256sum /etc/nftables.conf; systemctl is-enabled nftables; systemctl is-active nftables; /root/fw-ruleset; find /root/nft_backup -type f -printf '%f %s %T@\\n' 2>/dev/null | sort", check=False).stdout

def probe(port, udp=False, attempts=1):
    # UDP has no retransmission, and a public target makes a single lost
    # datagram look like a closed port.
    for attempt in range(attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
            s.settimeout(2)
            try:
                if udp:
                    s.sendto(b'test', (a.host, port))
                    if s.recv(100) == b'test':
                        return True
                else:
                    s.connect((a.host, port))
                    return True
            except OSError:
                pass
        if attempt + 1 < attempts:
            time.sleep(1)
    return False

def disarm_all():
    # Failure paths leave the armed net and snapshots for investigation; a stale
    # on-boot unit would otherwise restore an old snapshot at the next boot.
    ssh(f'''set -u
for d in {state_dir}/nft-transaction-*; do
    if test -x "$d/transaction"; then "$d/transaction" disarm || true; fi
    rm -rf "$d"
done
systemctl daemon-reload''', check=False)


def wait_restored(before, seconds=100):
    # systemd-run timers coalesce, so OnActiveSec is not a deadline.
    deadline = time.monotonic() + seconds
    while True:
        now = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables', check=False, timeout=15)
        if (now.returncode == 0 and now.stdout == before) or time.monotonic() >= deadline:
            return now
        time.sleep(3)


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
# Dynamic set contents move on their own: the suite's own SSH connections feed
# the controller's address into the flood set, which would make every state
# comparison unstable. Comparisons go through a dump with those blocks removed.
ssh(f'''set -eu
umask 077
mkdir {remote}
cd {remote}
test -x /usr/sbin/nft
cat > /root/fw-ruleset <<'FILTER'
#!/bin/sh
/usr/sbin/nft -s list ruleset | sed '/^\\tset ssh_flood[46] {{$/,/^\\t}}$/d'
FILTER
cat > /root/fw-managed <<'MANAGED'
#!/bin/sh
for table in "inet filter" "inet nat"; do
    /usr/sbin/nft -s list table $table 2>/dev/null | sed '/^\\tset ssh_flood[46] {{$/,/^\\t}}$/d'
done
MANAGED
chmod 700 /root/fw-ruleset /root/fw-managed
printf 'flush ruleset\\n' > runtime
/usr/sbin/nft list ruleset >> runtime
/root/fw-ruleset > runtime-static
/root/fw-managed > managed-static
/usr/sbin/nft list tables | sort > tables-static
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
            return ssh(f"systemctl list-units --all --plain --no-legend --state=active,activating 'nft-rollback-*.timer'; systemctl list-unit-files --plain --no-legend 'nft-rollback-*-boot.timer'; find {state_dir} -maxdepth 1 -type d -name 'nft-transaction-*' -printf '%p\\n' 2>/dev/null | sort").stdout.splitlines()
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
        before = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables').stdout
        play(dict(wan_view, nft_rules_extra=dict(base['nft_rules_extra'], wan_allow_ssh=None), nft_rollback_timeout=60, nft_mgmt_allow_enabled=False), expected=1)
        after = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables').stdout
        require(before == after, 'immediate rollback did not restore config/runtime/service')
        require(ssh(f"grep -l rolled-back {state_dir}/nft-transaction-*/state").stdout.strip(), 'no rolled-back transaction')
        # The failure path leaves the armed net for investigation; the suite
        # must clear it so a later reboot does not restore a stale snapshot.
        require(ssh("systemctl list-unit-files --plain --no-legend 'nft-rollback-*-boot.timer'").stdout.strip(), 'no persistent on-boot rollback unit was armed')
        disarm_all()
    record('new SSH immediate rollback', newssh)
    def blocked():
        arm()
        before = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout
        # Drop at input order 1, before established; timeout exceeds rollback to exercise false success race.
        drop = dict(order=1, family='inet', table='filter', chain='input', match={'tcp': {'dport': 22}}, action='drop', comment='TEST full SSH block')
        play({'nft_rules_extra': dict(base['nft_rules_extra'], full_block=drop), 'nft_ssh_check_timeout': 40, 'nft_rollback_timeout': 15, 'nft_timeout_assert_enabled': False, 'nft_mgmt_allow_enabled': False}, expected=1, timeout=110)
        # systemd-run timers have default coalescing, so OnActiveSec is not a deadline.
        deadline = time.monotonic() + 100
        while True:
            restored = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables', check=False, timeout=15)
            if restored.returncode == 0 or time.monotonic() >= deadline:
                break
            time.sleep(3)
        require(restored.returncode == 0, 'SSH not restored within bounded rollback wait')
        require(before == restored.stdout, 'full block rollback state mismatch')
        evidence = ssh(f"journalctl --since '-3 minutes' --no-pager -o short-monotonic -u 'nft-rollback-*'; for d in {state_dir}/nft-transaction-*; do test -f \"$d/candidate\" && grep -q 'TEST full SSH block' \"$d/candidate\" && cat \"$d/state\"; done", check=False).stdout
        require('rolled-back' in evidence and '.service - [systemd-run]' in evidence and 'Deactivated successfully' in evidence, 'no independent timer evidence')
        disarm_all()
    record('full SSH block / timer / nonzero rc / enabled unmasked', blocked)
    def timer_race():
        arm()
        before = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout
        ready = threading.Event()
        held, race_port = reserve_port()

        def delayed_listener():
            time.sleep(110)
            with held as s:
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
        # With AccuracySec=1s the timer is punctual, so the timeout has to be
        # long enough for apply to win and short enough to beat the probe.
        r = play({'nft_allowed_ports': ['18100'], 'nft_rollback_timeout': 25, 'nft_ssh_check_timeout': 140, 'nft_ssh_check_tcp': True, 'nft_ssh_check_connection': False, 'nft_ssh_check_host': '127.0.0.1', 'nft_ssh_check_port': race_port, 'nft_timeout_assert_enabled': False}, expected=1, timeout=200)
        thread.join(timeout=35)
        require(ready.is_set(), 'delayed probe listener unavailable')
        # The generated playbook references the role by path, so the task name
        # carries that prefix; match on the suffix only.
        commit_output = r.stdout.split(': Commit only if rollback has not started]')[-1].split('TASK [')[0]
        require('fatal:' in commit_output and 'non-zero return code' in commit_output, 'did not exercise post-timer commit failure')
        require(before == ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout, 'timer race restoration mismatch')
        disarm_all()
    record('timer wins despite successful SSH / no false success', timer_race)
    arm()
    def extras():
        ex = dict(base['nft_rules_extra'], wan_allow_ssh={'comment': 'TEST changed SSH'})
        # The added rule arrives through nft_rules_host, the host-level merge
        # level that replaces the deprecated global hash_behaviour = merge.
        host_rules = dict(test_add=dict(order=114, family='inet', table='filter', chain='input_wan', match={'tcp': {'dport': 18082}}, action='accept', comment='TEST added'))
        positive(dict(wan_view, nft_rules_extra=ex, nft_rules_host=host_rules, nft_allowed_ports=['22/tcp', '18080/tcp', '18081/udp']))
        text = ssh('cat /etc/nftables.conf').stdout
        require('TEST changed SSH' in text and 'TEST added' in text, 'add/change/null not rendered')
        require(text.count('Drop spoofed') == 4, 'baseline spoof guards are not rendered')
        rules = [line for line in text.splitlines() if line.startswith('add rule inet filter input ')]
        require('Keep the active management path reachable' in rules[0], f'management rule is not first: {rules[0]}')
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
        results = {
            'tcp 18080 (nft_allowed_ports)': probe(18080, attempts=3),
            'tcp 18082 (nft_rules_host)': probe(18082, attempts=3),
            'udp 18081 echo': probe(18081, udp=True, attempts=5),
            'tcp 18083 must be denied': not probe(18083),
        }
        require(all(results.values()), 'WAN probes: ' + ', '.join(f'{name}={ok}' for name, ok in results.items()))
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
        # mgmt_allow_current accepts ahead of the flood rules by design, so the
        # limit is only observable with that protection off.
        play(dict(wan_view, nft_ssh_check_enabled=False, nft_rules_extra={}, nft_mgmt_allow_enabled=False), flags=('-t', 'nft_apply'))
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            hits = list(pool.map(lambda _: probe(22), range(40)))
        require(any(hits) and not all(hits), f'no measurable limit: {sum(hits)}/40')
        require(mgmt_source in ssh('/usr/sbin/nft list set inet filter ssh_flood4').stdout, 'source missing in dynamic set')
        # Clear the per-source budget, then drain the sshd penalty the admitted
        # (unauthenticated) probes earned, before the next scenario needs a new
        # connection.
        ssh('/usr/sbin/nft flush set inet filter ssh_flood4; /usr/sbin/nft flush set inet filter ssh_flood6', check=False)
        require(wait_ssh(), 'sshd still refuses new connections after the burst')
        positive()
    record('SSH flood rate limit (persistent management)', flood)
    def absent():
        # The flood scenario leaves the controller penalised by sshd, and this
        # one must not start package surgery on a connection that may still be
        # refused halfway through.
        require(wait_ssh(), 'sshd still refuses new connections before the package scenario')
        arm()
        # Cache reinstall artifact first, no purge: retain package-owned configuration.
        ssh(f'cd {remote}; apt-get download nftables >/dev/null', timeout=180)
        ssh('dpkg --remove nftables', timeout=180)
        try:
            absent_before = ssh('test ! -e /usr/sbin/nft; test ! -e /usr/lib/systemd/system/nftables.service; sha256sum /etc/nftables.conf; systemctl daemon-reload; systemctl show nftables -p LoadState').stdout
            require('LoadState=not-found' in absent_before, 'service still installed')
            r = play({'nft_allowed_ports': ['18090']}, flags=('--check', '--diff'))
            require('nftables is not installed' in r.stdout, 'missing limited-check warning')
            after = ssh('test ! -e /usr/sbin/nft; test ! -e /usr/lib/systemd/system/nftables.service; sha256sum /etc/nftables.conf; systemctl show nftables -p LoadState').stdout
            require(after == absent_before, 'absent check mutated package/config/service')
        finally:
            wait_ssh()
            ssh('DEBIAN_FRONTEND=noninteractive apt-get install -y nftables; systemctl daemon-reload', timeout=120)
    record('check without installed nftables and service', absent)
    # The incident this role was fixed for: the shipped guards drop the private
    # management source, and without the management rule only the timer saves the
    # host. Proves both that the guard is lethal unprotected and that the
    # protection is what makes the baseline safe.
    def lockout_regression():
        arm()
        before = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout
        play(dict(unprotected, nft_rollback_timeout=15, nft_allowed_ports=['18103']), expected=1, timeout=150)
        require(wait_restored(before).stdout == before, 'unprotected baseline lockout was not restored')
        # Established sessions survive the guards, so the rescue path may win
        # here instead of the timer; either way a transaction must record it.
        require(ssh(f"grep -l rolled-back {state_dir}/nft-transaction-*/state", check=False).stdout.strip(), 'no rolled-back transaction')
        disarm_all()
    record('baseline lockout without management protection rolls back', lockout_regression)

    # The rollback net must not depend on the reachability checks: disabling them
    # used to disarm the timer and leave an unreachable host unrecoverable.
    def rollback_without_checks():
        arm()
        before = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables').stdout
        drop = dict(order=1, family='inet', table='filter', chain='input', match={'tcp': {'dport': 22}}, action='drop', comment='TEST block with checks disabled')
        play({'nft_rules_extra': dict(base['nft_rules_extra'], full_block=drop), 'nft_mgmt_allow_enabled': False, 'nft_ssh_check_enabled': False, 'nft_rollback_timeout': 15, 'nft_timeout_assert_enabled': False}, expected=1, timeout=150)
        require(wait_restored(before).stdout == before, 'timer did not restore with checks disabled')
        disarm_all()
    record('rollback armed with reachability checks disabled', rollback_without_checks)

    # A manual flush leaves the config file untouched, which used to report
    # changed=0 and leave the host without rules.
    def drift_reapply():
        positive({'nft_allowed_ports': ['18104']})
        ssh('/usr/sbin/nft flush ruleset')
        r = play({'nft_allowed_ports': ['18104']}, flags=('-t', 'nft_apply'))
        require('changed=0' not in r.stdout, 'runtime drift did not trigger a reapply')
        require('18104' in ssh('/root/fw-ruleset').stdout, 'ruleset not restored after drift')
        idem({'nft_allowed_ports': ['18104']})
    record('runtime drift is detected and reapplied', drift_reapply)

    # ssh_port that does not match the live sshd listener renders SSH rules for a
    # port nobody connects to; the preflight assert catches it before any change.
    def port_mismatch():
        before = state()
        r = play({'ssh_port': 2222}, flags=('-t', 'nft_apply'), expected=1)
        require('served on port' in r.stdout, 'no ssh_port preflight assert')
        require(state() == before, 'preflight assert mutated state')
    record('ssh_port mismatch refused before apply', port_mismatch)

    # Ansible re-runs a task after an SSH blip. Invoking the installed script a
    # second time is exactly what that retry does: prepare must not re-snapshot
    # the already applied rules (it would record them as the original state) and
    # commit must not fail on a transaction it already committed. The play is
    # held between apply and commit by a probe whose listener appears later, so
    # the duplicate invocations land inside the real window.
    def retry_idempotence():
        ready = threading.Event()
        held, retry_port = reserve_port()

        def delayed_listener():
            time.sleep(70)
            with held as sock:
                sock.listen()
                sock.settimeout(120)
                ready.set()
                try:
                    conn, _ = sock.accept()
                    conn.close()
                except OSError:
                    pass

        listener = threading.Thread(target=delayed_listener, daemon=True)
        listener.start()
        outcome = {}

        def runner():
            try:
                outcome['result'] = play({'nft_allowed_ports': ['18112'], 'nft_ssh_check_host': '127.0.0.1',
                                          'nft_ssh_check_port': retry_port, 'nft_ssh_check_timeout': 180,
                                          'nft_rollback_timeout': 600, 'nft_ssh_check_connection': False},
                                         timeout=300)
            except BaseException as error:  # reported in the main thread
                outcome['error'] = error

        play_thread = threading.Thread(target=runner, daemon=True)
        play_thread.start()
        armed = ''
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            probe = ssh(f"ls -d {state_dir}/nft-transaction-*/armed 2>/dev/null | head -1; grep -c 18112 /etc/nftables.conf 2>/dev/null || echo 0", check=False).stdout.split()
            if len(probe) == 2 and probe[0].endswith('/armed') and probe[1] != '0':
                armed = probe[0]
                break
            time.sleep(2)
        require(armed, 'transaction window never opened')
        txn = armed.rsplit('/', 1)[0]
        snapshot = ssh(f"cd {txn}; sha256sum runtime; cat state; stat -c %Y runtime").stdout
        ssh(f'{txn}/transaction prepare')
        require(ssh(f"cd {txn}; sha256sum runtime; cat state; stat -c %Y runtime").stdout == snapshot,
                'a retried prepare re-snapshotted an armed transaction')
        ssh(f'{txn}/transaction commit')
        require(ssh(f'cat {txn}/state').stdout.strip() == 'committed', 'commit did not mark the state')
        ssh(f'{txn}/transaction commit')
        require(ssh(f'cat {txn}/state').stdout.strip() == 'committed', 'a retried commit changed the state')
        require(ready.wait(timeout=180), 'delayed probe listener unavailable')
        play_thread.join(timeout=240)
        require('error' not in outcome, f"play raised: {outcome.get('error')}")
        require(outcome.get('result') is not None, 'play did not finish')
        require('18112' in ssh('/root/fw-ruleset').stdout, 'rules missing after duplicated invocations')
        require(not ssh(f'ls -d {txn} 2>/dev/null', check=False).stdout.strip(), 'committed transaction not removed')
        idem({'nft_allowed_ports': ['18112']})
    record('retried prepare and commit stay idempotent', retry_idempotence)

    # The documented bastion setup: the control node reaches the target only
    # through a jump host, so the TCP probe from here is meaningless and the
    # README tells operators to use the connection probe or delegate the TCP one
    # to the jump host. Both paths are exercised here for real.
    def bastion():
        inventory = logs / 'inventory-bastion'
        inventory.write_text(
            f'vm ansible_host={a.host} ansible_user={a.user} ansible_python_interpreter=/usr/bin/python3 '
            f"ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new -o ProxyJump={a.user}@{a.bastion}'\n"
            f'bastion ansible_host={a.bastion} ansible_user={a.user} ansible_python_interpreter=/usr/bin/python3\n')
        play_file = logs / 'play-bastion.yml'
        play_file.write_text(json.dumps([dict(hosts='vm', become=a.user != 'root', gather_facts=True,
                                              vars_files=[str(root / 'examples/inventory/group_vars/all/firewall.yml')],
                                              roles=[str(root)])]))

        def through_bastion(extra, expected=0):
            variables = dict(base)
            variables.update(extra)
            vars_path = logs / f'{seq + 1:03}-bastion-vars.json'
            vars_path.write_text(json.dumps(variables))
            r = run(['ansible-playbook', '-i', str(inventory), str(play_file), '-e', '@' + str(vars_path),
                     '-t', 'nft_apply'], timeout=200, check=False)
            require((r.returncode == 0) if expected == 0 else (r.returncode != 0),
                    f'Unexpected Ansible rc={r.returncode}: {r.stdout[-2000:]}')
            return r

        # The connection probe follows ProxyJump, so it proves the real path.
        through_bastion({'nft_allowed_ports': ['18115'], 'nft_ssh_check_connection': True,
                         'nft_ssh_check_tcp': False, 'nft_rollback_timeout': 120})
        require('18115' in ssh('/root/fw-ruleset').stdout, 'apply through the jump host did not land')
        # The TCP probe delegated to the jump host, which does have direct access.
        through_bastion({'nft_allowed_ports': ['18116'], 'nft_ssh_check_connection': False,
                         'nft_ssh_check_tcp': True, 'nft_ssh_check_delegate': 'bastion',
                         'nft_rollback_timeout': 120})
        require('18116' in ssh('/root/fw-ruleset').stdout, 'delegated probe apply did not land')
        require(not ssh(f"find {state_dir} -maxdepth 1 -type d -name 'nft-transaction-*' -printf '%p\\n' 2>/dev/null", check=False).stdout.strip(),
                'bastion runs leaked a transaction directory')
        positive()
    if a.bastion:
        record('apply through a jump host, connection probe and delegated TCP probe', bastion)

    # Docker keeps its own tables; the role must not take them down, and the
    # documented flush_ruleset + restart_docker combination must put them back.
    def docker():
        # Earlier scenarios apply with nft_flush_ruleset=True, which takes
        # Docker's chains down with everything else. Restarting Docker is the
        # documented recovery and the precondition for this scenario.
        ssh('docker rm -f fwtest >/dev/null 2>&1 || true; systemctl restart docker', timeout=120)
        time.sleep(5)
        # A restart policy is required: restarting the daemon stops containers
        # that have none, and nft_restart_docker restarts the daemon.
        ssh('docker run -d --name fwtest --restart unless-stopped -p 18120:80 busybox httpd -f -p 80', timeout=180)
        time.sleep(3)
        require(probe(18120), 'published container port unreachable before the role ran')
        tables_before = ssh("/usr/sbin/nft list tables | grep -v 'inet filter' | grep -v 'inet nat' | sort").stdout
        require(tables_before.strip(), 'Docker created no tables of its own')
        # Default: per-table replacement leaves foreign tables alone.
        positive({'nft_flush_ruleset': False, 'nft_allowed_ports': ['18121']})
        require(ssh("/usr/sbin/nft list tables | grep -v 'inet filter' | grep -v 'inet nat' | sort").stdout == tables_before,
                "the role's apply removed Docker's tables")
        require(probe(18120), 'published container port unreachable after a non-flushing apply')
        # flush_ruleset wipes every table, including Docker's; the documented
        # answer is nft_restart_docker, which must bring them back.
        play({'nft_flush_ruleset': True, 'nft_restart_docker': True, 'nft_allowed_ports': ['18122']}, timeout=200)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not probe(18120):
            time.sleep(3)
        require(probe(18120), f"nft_restart_docker did not restore the published port after a full flush; container: {ssh('docker inspect fwtest --format Running={{.State.Running}}', check=False).stdout.strip()}")
        require(ssh("/usr/sbin/nft list tables | grep -v 'inet filter' | grep -v 'inet nat' | sort").stdout.strip(),
                "Docker's tables are missing after the restart")
        # Foreign tables must not look like drift on the next run.
        idem({'nft_flush_ruleset': True, 'nft_restart_docker': True, 'nft_allowed_ports': ['18122']})
        # Back to no published ports, so the final restoration check compares
        # like with like.
        ssh('docker rm -f fwtest >/dev/null 2>&1 || true; systemctl restart docker', timeout=120)
        time.sleep(5)
        positive()
    if a.docker:
        record('coexistence with Docker tables and published ports', docker)

    # A reachability timeout that outlives the rollback timer would roll back a
    # healthy host mid-check; the guard refuses it before anything changes.
    # The reset-and-reconnect probe is off by default; this is the only scenario
    # that exercises it, including that it does not break a healthy apply.
    def connection_probe():
        # This scenario deliberately drops the persistent connection and
        # reconnects, so it needs a source that sshd is not currently
        # penalising and a timeout that fits a public network.
        require(wait_ssh(), 'sshd still refuses new connections before the connection probe')
        try:
            positive({'nft_allowed_ports': ['18105'], 'nft_ssh_check_connection': True,
                      'nft_ssh_check_tcp': False, 'nft_ssh_check_timeout': 30,
                      'nft_rollback_timeout': 120})
        except Exception:
            # Evidence for why a fresh connection did not come up: the live
            # policy for port 22 and what sshd thought of us.
            evidence = ssh("/root/fw-ruleset | grep -nE 'dport 22|ssh_flood|management path' ; journalctl -u ssh -u sshd --since '-2 minutes' --no-pager | tail -15", check=False).stdout
            raise AssertionError(f'connection probe failed; port 22 policy and sshd log:\n{evidence}')
        require('18105' in ssh('/root/fw-ruleset').stdout, 'connection probe path did not apply')
        disarm_all()
    record('reachability probe over the Ansible connection path', connection_probe)

    # An armed neighbour transaction must stop a new one: its timer would undo
    # the new commit, and its snapshot would be the wrong original state. A
    # finished neighbour must instead be collected silently.
    def overlapping_transactions():
        # A leftover armed transaction from an earlier failure would be refused
        # for the right reason and hide what this scenario actually tests.
        disarm_all()
        before = state()
        ssh(f"set -eu; mkdir -p {state_dir}/nft-transaction-fake; printf 'rollback-failed\\n' > {state_dir}/nft-transaction-fake/state")
        try:
            r = play({'nft_allowed_ports': ['18106']}, flags=('-t', 'nft_apply'), expected=1)
            require('is still' in r.stdout and 'nft-transaction-fake' in r.stdout, 'armed neighbour did not stop the transaction')
            require(state() == before, 'refused transaction mutated state')
        finally:
            ssh(f'rm -rf {state_dir}/nft-transaction-fake')
        ssh(f"set -eu; mkdir -p {state_dir}/nft-transaction-done; printf 'rolled-back\\n' > {state_dir}/nft-transaction-done/state")
        positive({'nft_allowed_ports': ['18106']})
        require(not ssh(f'ls -d {state_dir}/nft-transaction-done 2>/dev/null', check=False).stdout.strip(), 'finished neighbour was not collected')
    record('overlapping transactions refused, finished ones collected', overlapping_transactions)

    def timeout_guard():
        before = state()
        r = play({'nft_ssh_check_timeout': 30, 'nft_rollback_timeout': 20}, flags=('-t', 'nft_apply'), expected=1)
        require('leaves no room before' in r.stdout, 'no rollback timeout guard assert')
        require(state() == before, 'timeout guard mutated state')
    record('reachability timeout past the rollback timer refused', timeout_guard)

    def timers_clean():
        active = ssh("systemctl list-units --all --plain --no-legend --state=active,activating 'nft-rollback-*.timer' 'nft-rollback-*.service'").stdout.strip()
        require(not active, f'rollback units still active: {active}')
        boot = ssh("systemctl list-unit-files --plain --no-legend 'nft-rollback-*-boot.timer'", check=False).stdout.strip()
        require(not boot, f'persistent on-boot rollback units left behind: {boot}')
        leftover = ssh(f"find {state_dir} -maxdepth 1 -type d -name 'nft-transaction-*' -printf '%p\\n' 2>/dev/null", check=False).stdout.strip()
        require(not leftover, f'transaction directories left behind: {leftover}')
    record('rollback timer/service cleanup before reboot', timers_clean)
    if a.reboot:
        # A reboot between apply and commit is the one case transient timers
        # cannot cover: they do not survive it, the service is still masked and
        # no rules are loaded. Only the persistent on-boot unit recovers that.
        def reboot_in_window():
            # Captured with the exact command wait_restored compares against.
            before = ssh('sha256sum /etc/nftables.conf; /root/fw-ruleset; systemctl is-enabled nftables; systemctl is-active nftables', check=False).stdout
            boot_id = ssh('cat /proc/sys/kernel/random/boot_id').stdout.strip()
            held, dead_port = reserve_port()
            outcome = {}

            def runner():
                try:
                    # No listener on the probe port, so the play waits between
                    # apply and commit while the host reboots underneath it.
                    outcome['result'] = play({'nft_allowed_ports': ['18114'], 'nft_ssh_check_host': '127.0.0.1',
                                              'nft_ssh_check_port': dead_port, 'nft_ssh_check_timeout': 120,
                                              'nft_rollback_timeout': 600, 'nft_rollback_on_boot_delay': 45,
                                              'nft_ssh_check_connection': False},
                                             expected=1, timeout=300)
                except BaseException as error:
                    outcome['error'] = error

            play_thread = threading.Thread(target=runner, daemon=True)
            play_thread.start()
            armed = ''
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                probe = ssh(f"ls -d {state_dir}/nft-transaction-*/armed 2>/dev/null | head -1; grep -c 18114 /etc/nftables.conf 2>/dev/null || echo 0", check=False).stdout.split()
                if len(probe) == 2 and probe[0].endswith('/armed') and probe[1] != '0':
                    armed = probe[0]
                    break
                time.sleep(2)
            require(armed, 'transaction window never opened')
            txn = armed.rsplit('/', 1)[0]
            units = ssh("systemctl list-unit-files --plain --no-legend 'nft-rollback-*-boot.timer'").stdout
            require('enabled' in units, f'no enabled on-boot rollback unit while armed: {units}')
            require('masked' in ssh('systemctl is-enabled nftables', check=False).stdout, 'service not masked inside the window')
            ssh('systemctl reboot', check=False, timeout=30)
            play_thread.join(timeout=300)
            time.sleep(20)
            # Catch the exposed window first: rules gone, service still masked.
            deadline = time.monotonic() + 120
            exposed = ''
            while time.monotonic() < deadline:
                probe = ssh('cat /proc/sys/kernel/random/boot_id; systemctl is-enabled nftables; /usr/sbin/nft list table inet filter >/dev/null 2>&1 && echo loaded || echo empty', check=False, timeout=20)
                if probe.returncode == 0 and boot_id not in probe.stdout:
                    exposed = probe.stdout
                    break
                time.sleep(3)
            require(exposed, 'host did not come back after the in-window reboot')
            # Then the on-boot unit must restore the pre-transaction state.
            restored = wait_restored(before, seconds=180)
            require(restored.stdout == before, f'on-boot rollback did not restore the snapshot: {restored.stdout}')
            require('rolled-back' in ssh(f'cat {txn}/state', check=False).stdout, 'on-boot rollback did not mark the state')
            # The unit removes itself after a successful restore, so journalctl
            # can no longer resolve it by name; grep the boot journal instead.
            evidence = ssh("journalctl -b --no-pager | grep -F 'nft-rollback' | tail -5", check=False).stdout
            require('nft-rollback' in evidence, f'no on-boot rollback evidence in the journal: {evidence}')
            require(not ssh("systemctl list-unit-files --plain --no-legend 'nft-rollback-*-boot.timer'", check=False).stdout.strip(),
                    'on-boot unit did not remove itself after a successful restore')
            held.close()
            disarm_all()
            arm()
        record('reboot inside the transaction window is recovered on boot', reboot_in_window)

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
        wait_ssh()
        disarm_all()
        ssh(f'{remote}/restore', timeout=180)
        # A host without a pre-existing /etc/nftables.conf must end up without
        # one, and the role's state directory is part of what has to be gone.
        ssh(f"set -eu; systemctl stop {unit}.timer {unit}.service {unit}-listener.service {unit}-boot.timer || true; systemctl disable {unit}-boot.timer || true; rm -f /etc/systemd/system/{unit}-boot.timer /etc/systemd/system/{unit}-boot.service; rm -rf {state_dir}; systemctl daemon-reload; cd {remote}; if test -e config-present; then cmp config /etc/nftables.conf; else test ! -e /etc/nftables.conf; fi; /root/fw-managed > final-managed; cmp managed-static final-managed; /usr/sbin/nft list tables | sort > final-tables; cmp tables-static final-tables; test \"$(systemctl is-enabled nftables)\" = \"$(cat mask)\"; test \"$(systemctl is-active nftables)\" = \"$(cat active)\"; if test -e history-present; then diff -r history /root/nft_backup; else test ! -e /root/nft_backup; fi; rm -f /root/fw-ruleset /root/fw-managed", timeout=60)
    record('restore original config/runtime/service/history', cleanup)
print(f'Results: {logs}/results.json', flush=True)
raise SystemExit(int(any(r['status'] == 'FAIL' for r in results)))
