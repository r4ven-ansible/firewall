# firewall

Manage an nftables firewall using the role's `nft_*` DSL.

## Installation and repository layout

This is a standalone Ansible role: `tasks/`, `defaults/`, `templates/` and
`meta/` are at the repository root. The launch project in the parent directory
is preserved independently. No external roles or collections are required.
Ansible Core 2.17 is the tested minimum; `requirements.txt` selects 2.19 for a
new development environment. `firewall_supported_distributions` accepts Debian,
LMDE and Ubuntu; Debian 13 is the platform the integration suite runs on.

### Local installation (no publication required)

From the role repository root:

```sh
mkdir -p dist
tar --exclude=./dist --exclude=./.git --exclude=./.venv --exclude=./.ansible --exclude=__pycache__ -czf dist/firewall.tar.gz .
ansible-galaxy role install -r requirements-local.yml --roles-path ./dist/roles
```

The installed role can be used as `firewall` with that roles path.

### Git distribution

After creating and pushing your own Git repository, consumers can use this
`requirements.yml` template (replace the URL and use an existing release tag):

```yaml
---
roles:
  - name: firewall
    src: https://github.com/OWNER/ansible-role-firewall.git
    scm: git
    version: "1.0.0"
```

```sh
ansible-galaxy role install -r requirements.yml -p ./roles
```

Git installation does not require publication in the Galaxy catalog. For
installation as `<namespace>.firewall`, import the repository into Galaxy
under your actual account namespace. This repository has not been published;
no release tags or remote URLs are assumed to exist.

### Run the bundled example

```sh
cd examples
ansible-inventory --graph
ansible-playbook playbooks/firewall.yml --syntax-check
ansible-playbook playbooks/firewall.yml -l crow.r4ven.me --check --diff
```

Before connecting, replace the documentation address/user in
`examples/inventory/hosts.yml`, review the base policy and enable
`firewall_enabled` in host vars. The example is disabled by default.
`examples/ansible.cfg` preserves YAML-formatted output and dictionary merging;
run commands from `examples` so Ansible loads it. If `ANSIBLE_CONFIG` is already
set, point it explicitly at this configuration. See the safety notes below
before using a private WAN or changing SSH access.

## Main Variables

```yaml
firewall_enabled: false          # the role does nothing until this is true
nft_config_path: /etc/nftables.conf
nft_bin: /usr/sbin/nft
nft_validate_cmd: "{{ nft_bin }} -c -f %s"
nft_tables: []
nft_sets: []
nft_maps: []
nft_flowtables: []
nft_chains: []
nft_rules: {}
nft_rules_extra: {}             # group or host level additions and overrides
nft_rules_host: {}              # host level, merged last
nft_allowed_ports: []           # "80/tcp", "443/udp"; rendered into input_wan
nft_allowed_ports_exclude_ssh: true
```

Packages, foreign firewalls and the full-flush mode:

```yaml
nft_packages: [nftables]
nft_apt_update_cache: true
nft_apt_cache_valid_time: 3600
nft_remove_other_firewall: false # stop/disable ufw, firewalld, iptables,
                                 # netfilter-persistent and purge ufw/firewalld
nft_flush_ruleset: false         # prepend "flush ruleset": takes down every
                                 # table, including a container runtime's
nft_restart_docker: false        # required with nft_flush_ruleset on a Docker host
```

## Apply safety

`tasks/firewall.yml` builds the rules and imports `tasks/apply.yml` for
transactional application. It first compares the rendered configuration without
writing the destination. On a change, the candidate is staged in a private
transaction directory and validated with `nft -c -f` **before** replacing
`nft_config_path` or changing the runtime rules.

The transaction snapshots the live nft ruleset (not just the potentially stale
config), the original config including symlinks or its absence, and the original
service enabled/runtime-enabled and masked/runtime-masked state, and whether the
unit was active — a rollback that restores only enablement would leave the unit
inactive while the rules are live, which is a different state from the one it
replaced. With the SSH
check enabled, an independent transient systemd timer restores these snapshots
even if Ansible loses connectivity. Rescue attempts immediate restoration when
the host remains reachable; failures are reported and transaction snapshots and
any armed timer are left for investigation.

Each transaction has a unique rollback unit name derived from `nft_rollback_unit`.
Apply, rollback, arm, disarm and commit share a `flock` lock and a state marker:
commit requires `pending`, so a timer that has already started rollback cannot be
mistaken for a successful apply even if a delayed probe subsequently succeeds, and
it reports the lost connection instead of a bare non-zero exit. `prepare` and
`commit` are idempotent, so an Ansible SSH retry of the same task cannot turn a
healthy transaction into a failure. Successful commit enables/unmasks nftables,
disarms the rollback units, records the drift baseline and removes the transaction
directory.

Snapshots live in `nft_state_dir` (not `/tmp`, which may be tmpfs) and the window
is additionally covered by a persistent `OnBootSec` unit: a reboot between apply
and commit would otherwise leave a host with no rules and a masked
nftables.service, and transient timers do not survive a reboot. Both the transient
timer and the on-boot unit are removed on commit; after a failed transaction they
are deliberately left armed, and
`<nft_state_dir>/nft-transaction-*/transaction disarm` clears them once the state
is understood.

The rollback net is armed independently of the reachability checks
(`nft_rollback_enabled`): disabling the checks for a bastion setup must not leave a
bad ruleset unrecoverable.

This is a safety net, not an absolute guarantee. The probes check reachability, not
every management path; rollback still depends on a working host, systemd, nft and
snapshots. Keep out-of-band access and test first.

```yaml
nft_rollback_enabled: true
nft_rollback_unit: nft-rollback
nft_rollback_timeout: 120
nft_rollback_accuracy: 1s        # systemd coalesces timers without this
nft_rollback_on_boot: true
nft_rollback_on_boot_delay: 60
nft_state_dir: /var/lib/nftables-firewall
nft_ssh_check_enabled: true
nft_ssh_check_connection: false  # probe over Ansible's own connection path
nft_ssh_check_tcp: true          # extra TCP probe from the delegate
nft_ssh_check_delegate: localhost
nft_ssh_check_host: "{{ ansible_host | default(inventory_hostname) }}"
nft_ssh_check_port: "{{ ssh_port | default(22) }}"
nft_ssh_check_timeout: 30
nft_timeout_assert_enabled: true # refuse a check timeout past the rollback timer
nft_backup_keep: 10              # unique previous configs retained in history
```

The connection probe resets the persistent connection first and then reconnects
the way Ansible itself does, so ProxyJump/bastion, authentication and nonstandard
ports are all covered. It is **off by default** because the reset also discards
the established session: a ruleset that blocks only *new* connections would then
wait for the rollback timer instead of being restored immediately by the rescue
path. Turn it on when the control node cannot see the real management path, and
treat the timer as the recovery mechanism there.

The TCP probe is the default: a third-party opinion from
`nft_ssh_check_delegate` that still detects a broken new-connection path while
leaving the established session — and therefore the immediate rescue rollback —
intact. With a bastion either point the delegate at a host with direct access:

```yaml
nft_ssh_check_delegate: bastion
```

or drop just the TCP probe and keep everything else:

```yaml
nft_ssh_check_tcp: false
```

### Keepalives are part of the safety net

Set them in the control node's `ansible.cfg` (`examples/ansible.cfg` ships them):

```ini
[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s -o ServerAliveInterval=5 -o ServerAliveCountMax=3 -o ConnectTimeout=10
```

Without keepalives a ruleset that blackholes the control connection does not fail
the task: Ansible blocks on the dead TCP session, the rollback timer restores the
host underneath it, the session resumes on a later retransmission and every
subsequent probe passes on an already rolled back host. The transaction still
refuses to commit, but the reported cause is far less obvious than a dropped
connection.

## Management lockout protection

The role reads the live management connection from `$SSH_CONNECTION` on the target
and keeps it explicitly accepted ahead of every other rule in `nft_mgmt_chain`, so
no rule combination in the inventory can drop the connection that is applying the
rules. It also refuses to continue when the rendered policy cannot protect that
path:

- the interface carrying the management source must be resolvable (`ip route get`)
  or pinned in `nft_mgmt_interface`;
- `nft_mgmt_chain` must exist in `nft_chains`;
- the management rule must have the lowest `order` in that chain;
- the sources must be plain addresses or CIDRs of one family, never a default
  route, so a wildcard can never end up in a rule that accepts first;
- `ssh_port` must match the port the live session is served on, otherwise the
  rendered SSH rules protect a port nobody connects to;
- the reachability timeouts, summed over the enabled probes, must leave room
  before the rollback timer.

The rule matches the live session's own port, the detected (or pinned) source
and — unless `nft_mgmt_match_interface: false` — the interface the reverse route
points at.

```yaml
nft_mgmt_allow_enabled: true
nft_mgmt_sources: []            # empty: autodetect the live source address
nft_mgmt_interface: ""          # empty: resolve with "ip route get"
nft_mgmt_rule_name: mgmt_allow_current
nft_mgmt_order: 1
nft_mgmt_family: inet
nft_mgmt_table: filter
nft_mgmt_chain: input
nft_mgmt_assert_ssh_port: true
```

The rule is written to `nft_config_path` like any other rule, which is what
keeps the host reachable after a reboot, and that has a price worth stating:
SSH from that source bypasses the policy's own SSH restrictions (per-source rate
limiting, trusted-only access); a shared or dynamic source (NAT gateway,
bastion, CI runner) extends that bypass to everyone behind it and to whoever
holds the address next; and runs from different control nodes rewrite the rule
and report a change every time. Pin `nft_mgmt_sources` to a stable admin range,
or disable the rule and rely on the rollback timer, when that matters more than
availability. The rule is merged before `nft_rules_extra`/`nft_rules_host`, so an
explicit override or `null` there still wins; `nft_mgmt_allow_enabled: false`
removes it entirely, which is what the integration tests do to exercise lockouts
on purpose.

### Overlapping transactions

A transaction refuses to prepare while another one in the same `nft_state_dir`
is still `pending` or `rollback-failed`: the older timer would otherwise undo
the newer commit, and the newer snapshot would record the older transaction's
rules as the original state. Finished neighbours (`committed`, `rolled-back`, or
an empty directory) are cleaned up automatically, so a failed run needs no
manual work before the next one — a stuck one does, and the error names the
directory and the command.

After a reboot inside the window, the on-boot unit restores the snapshot
`nft_rollback_on_boot_delay` seconds into the boot: the host has no firewall
until then, and the restored snapshot starts with `flush ruleset`, so tables
created by anything else in that window (a container runtime, for example) go
with it. A failed on-boot restore stays armed for the next boot instead of
removing itself.

## Runtime drift

The role is not only config-file driven. After each commit it records a
fingerprint of the managed tables in `nft_state_dir/applied.fingerprint`
(counters, handles and dynamic set contents are scrubbed, unmanaged tables such as
a container runtime's are ignored). When the live ruleset no longer matches that
fingerprint — a manual `nft flush ruleset`, a hand-written `nft -f`, a service that
never loaded the rules — the transaction runs again even though the rendered
configuration is unchanged. `nft_drift_check_enabled: false` turns the comparison
off and `nft_force_apply: true` applies unconditionally.

The baseline is recorded after the service start, so it is the state the host
will boot with, and only when this run owns that state (it applied the rules, or
there was no usable baseline yet). On the first run after upgrading the role the
current live ruleset therefore becomes the baseline. Tables the role does not
manage, dynamic set contents and any failure of the helper stay outside the
comparison, and the role says so in its output rather than pretending the check
is a security control.

## History and check mode

On a configuration content change, the previous config is saved to
`nft_backup_path` (default `/root/nft_backup`) as `<config basename>_<sha256>` with
mode `0600`. Existing hashes are deduplicated without refreshing their mtimes;
new entries use the time of backup creation. After a successful change,
`nft_backup_keep` retains the newest unique previous configs by mtime, not the
last N apply attempts. An identical reapply creates no transaction or backup and
has `changed=0` when the service is already enabled/unmasked.

`--check --diff` does not install packages or apply runtime rules. When nft is
absent, it can only compare the rendered config: it cannot validate nft syntax,
package installation, runtime or service behavior. Even with nft installed,
syntax validation and a diff are not proof of post-apply connectivity.
`-t nft_apply` includes rule preparation and transactional apply but skips package
installation, so nftables must already be installed.

## Inventory policy caveats

The role combines `nft_rules`, the management rule, generated port rules,
`nft_rules_extra` and `nft_rules_host` recursively, in that order, then removes
rules set to `null`. Use `nft_rules_host` for host-level additions and removals:
group vars keep `nft_rules_extra`, the host adds `nft_rules_host`, and no global
`hash_behaviour = merge` (deprecated in ansible-core, and no longer set in
`examples/ansible.cfg`) is needed. If you do define the same dictionary at two
inventory levels, set `[defaults] hash_behaviour = merge` yourself, because with
the default `replace` the host dictionary replaces the group one before the
role's `combine` runs. Lists are replaced, not appended.

In the repository baseline, the WAN private-source spoof guards run **after**
`allow_established` and `drop_invalid`, and before everything else. That order is
the point: a resolver, default gateway or NTP server on a private uplink is a
legitimate peer for traffic this host started, so dropping those replies breaks
the host itself (DNS stops resolving, `apt` hangs), while new and untracked
traffic from private sources is still dropped as spoofed. What must survive
beyond conntrack is accepted *ahead* of the guards: the management rule
(order 1), IPv6 neighbour discovery (5) and DHCP client replies (6, 7).

Together that is what makes the baseline safe to roll out on a host whose
management address is private — it used to drop even the established admin
session and roll back — without trusting anything else on the segment.

The residual risk of that order is a forged packet matching a live conntrack
entry: for TCP it needs the ephemeral port and a sequence inside the window, for
UDP it is the same off-path race a public resolver already faces, and the one
`related` message with real consequences is an ICMP redirect from a spoofed
on-link gateway. The baseline drops redirects outright (order 11, 12); also set
`net.ipv4.conf.all.accept_redirects=0` and `net.ipv6.conf.all.accept_redirects=0`
in sysctl, which this role deliberately does not manage. Connection tracking
helpers (FTP, SIP) would create the same kind of expected-flow exemption; the
role does not enable any.

The guards also honour exception sets, which are **empty by default**: exempting
a private source from the guard also routes it into `input_lan`, whose baseline
`input_lan_allow_all` accepts everything, so filling them trusts the whole
on-link segment. Do that only for a segment you actually trust; the role derives
ready values from facts (`nft_wan_local4` as networks, `nft_wan_local6` as the
interface's individual addresses, not subnets):

```yaml
nft_wan_local4_networks: "{{ nft_wan_local4 }}"
nft_wan_local6_networks: []
```

They are evaluated per run, so a host that changes subnet (new lease, migration)
keeps the committed set until the role runs again.

DHCP client rules are bound to `nft_wan_interface`, and the DHCPv6 one also
requires a link-local source. A host that leases an address on another interface
needs its own rule through `nft_rules_host`.

If a topology deliberately requires no spoof guards at all, the overrides are:

```yaml
nft_rules_host:
  drop_wan_spoofed_lan_ipv4: null
  drop_wan_spoofed_lan_ipv6: null
  fwd_drop_wan_spoofed_lan_ipv4: null
  fwd_drop_wan_spoofed_lan_ipv6: null
```

Removing guards alone may route a private source into `input_lan`, whose baseline
`input_lan_allow_all` accepts everything, bypassing WAN port/flood checks. WAN
tests must also exclude the management source subnet from `nft_lan4_networks`
(`lan4`), keep it outside trusted sources, or deliberately change routing/policy.

A nonstandard `ssh_port` must match the actual sshd listener and `ansible_port`;
the firewall does not configure sshd. Generic allowed TCP ports exclude only the
exact configured SSH port by default, not all possible SSH ports or port ranges.
Keep `nft_ssh_check_port` consistent with the real listener as well.

## Verified behavior

The destructive suite was run on three targets on 2026-10-14, all green: a
Debian 13 VM with `--reboot` (**22 PASS, 0 FAIL**), and two rented public hosts
— Debian 13 and Ubuntu 26.04 — with `--reboot --docker --bastion` pointing at
each other (**26 PASS, 0 FAIL** each). Original config, runtime, service state,
table inventory and history were restored on every target. It covers the baseline applying
with the shipped spoof guards enabled on a host whose management source is
private, both SSH rollback paths (immediate rescue and independent timer), the
timer/commit race, the lockout reproduced with both protections disabled,
rollback armed while the reachability checks are off, runtime drift detection,
overlapping transactions, both preflight asserts, live WAN probes, SSH flood
limiting, package removal under check mode, and reboot persistence. See
[tests/README.md](tests/README.md) for the scenario table, the earlier rounds
and what they found.

The public hosts add what a single VM cannot: a public-WAN management source,
a second distribution and nft version, a real `ProxyJump` path with a delegated
probe, coexistence with a running Docker container's published port, and a
reboot inside the transaction window over the internet.

Not covered: routable IPv6 (every target had link-local only), a multi-homed or
forwarding host, nft older than 1.1.3, IPv6 flood behavior, precise rate-limit
refill timing, denied UDP, and every possible initial masked/runtime service
state.

## Rule DSL

Rules are sorted by `order` and rendered as `add rule <family> <table> <chain> ...`.
Most common nftables match groups are supported directly:

```yaml
nft_rules:
  allow_web:
    order: 120
    family: inet
    table: filter
    chain: input_wan
    match:
      meta:
        l4proto: tcp
      tcp:
        dport: [80, 443]
      ct:
        state: new
    counter: true
    action: accept
    comment: "Allow HTTP(S)"
```

```yaml
nat_dnat_komodo_dns:
  order: 404
  family: inet
  table: nat
  chain: prerouting
  match:
    ip:
      daddr: 10.10.10.15
    meta:
      l4proto: [tcp, udp]
    th:
      dport: 53
  counter: false
  action:
    redirect: ":553"
  comment: "DNAT 10.10.10.15:53/tcp to local service"
```

NAT in the `inet` family needs an explicit address family unless the rule
already matches on `ip`/`ip6`:

```yaml
action:
  dnat:
    ip: "192.168.1.10:443"   # renders "dnat ip to ..."
action:
  snat:
    ip6: "fd00::1"           # renders "snat ip6 to ..."
```

For uncommon nftables expressions, use `match.raw`, rule-level `expr`, or
`action.raw`:

```yaml
nft_rules:
  anti_spoof:
    order: 70
    family: inet
    table: filter
    chain: input
    expr: 'fib saddr . iif oif missing'
    action: drop
```

Per-source rate limiting via a dynamic set (see `ssh_flood4` in
`examples/inventory/group_vars/all/firewall.yml`):

```yaml
nft_sets:
  - { family: inet, table: filter, name: ssh_flood4,
      type: ipv4_addr, flags: dynamic, size: 65536, timeout: 10m }

nft_rules:
  ssh_flood:
    order: 108
    family: inet
    table: filter
    chain: input_wan
    match:
      tcp: { dport: 22 }
      ct: { state: new }
      raw: 'add @ssh_flood4 { ip saddr limit rate over 20/minute }'
    action: { jump: log_drop }
```

## Flowtables

```yaml
nft_flowtables:
  - family: inet
    table: filter
    name: ft
    hook: ingress      # default
    priority: 0        # default
    devices: [eth0, eth1]
    counter: false

nft_rules:
  offload_established:
    order: 204
    family: inet
    table: filter
    chain: forward
    match:
      ct: { state: established }
      meta: { l4proto: [tcp, udp] }
    action: { flow: ft }
```

## Tags

- `firewall`
- `firewall_checks`
- `nftables`
- `nft_packages`
- `nft_backup`
- `nft_rules`
- `nft_config`
- `nft_apply`
