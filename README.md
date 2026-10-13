# firewall

Manage an nftables firewall using the role's `nft_*` DSL.

## Installation and repository layout

This is a standalone Ansible role: `tasks/`, `defaults/`, `templates/` and
`meta/` are at the repository root. The launch project in the parent directory
is preserved independently. No external roles or collections are required.
Ansible Core 2.17 is the tested minimum; `requirements.txt` selects 2.19 for a
new development environment. Debian 13 is the integration-tested platform.

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
ansible-playbook playbooks/firewall.yml -l firewall_example --check --diff
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
firewall_enabled: false
nft_config_path: /etc/nftables.conf
nft_tables: []
nft_sets: []
nft_maps: []
nft_flowtables: []
nft_chains: []
nft_rules: {}
nft_rules_extra: {}
```

## Apply safety

`tasks/firewall.yml` builds the rules and imports `tasks/apply.yml` for
transactional application. It first compares the rendered configuration without
writing the destination. On a change, the candidate is staged in a private
transaction directory and validated with `nft -c -f` **before** replacing
`nft_config_path` or changing the runtime rules.

The transaction snapshots the live nft ruleset (not just the potentially stale
config), the original config including symlinks or its absence, and the original
service enabled/runtime-enabled and masked/runtime-masked state. With the SSH
check enabled, an independent transient systemd timer restores these snapshots
even if Ansible loses connectivity. Rescue attempts immediate restoration when
the host remains reachable; failures are reported and transaction snapshots and
any armed timer are left for investigation.

Each transaction has a unique rollback unit name derived from `nft_rollback_unit`.
Apply, rollback and commit share a `flock` lock and a state marker: commit requires
`pending`, so a timer that has already started rollback cannot be mistaken for a
successful apply even if a delayed TCP probe subsequently succeeds. Successful
commit enables/unmasks nftables, stops only the rollback timer, and removes the
transaction directory.

This is a safety net, not an absolute guarantee. The SSH probe checks TCP
reachability, not authentication or all management paths. systemd timer coalescing
means the timeout is not a strict execution deadline; rollback still depends on a
working host, systemd, nft and snapshots. Keep out-of-band access and test first.

```yaml
nft_rollback_unit: nft-rollback
nft_rollback_timeout: 120
nft_ssh_check_enabled: true
nft_ssh_check_delegate: localhost
nft_ssh_check_host: "{{ ansible_host | default(inventory_hostname) }}"
nft_ssh_check_port: "{{ ssh_port | default(22) }}"
nft_ssh_check_timeout: 30
nft_backup_keep: 10   # unique previous configs retained in history
```

With ProxyJump/bastion setups the control node has no direct route to
the target, so the default check would always fail and roll back. Either
delegate the check to a host that does have direct access (it must be in
the inventory):

```yaml
nft_ssh_check_delegate: bastion
```

or disable the check — the rollback timer is then not armed at all
(otherwise it would always fire), keeping only validation and the
immediate rollback attempts on apply errors while Ansible can reach the host:

```yaml
nft_ssh_check_enabled: false
```

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

The role combines `nft_rules`, generated port rules and `nft_rules_extra`
recursively, then removes rules set to `null`. If `nft_rules_extra` is defined in
both group and host vars, the examples require `[defaults] hash_behaviour = merge`
in `ansible.cfg`. With the default `replace`, the host dictionary replaces the
group dictionary (including group DNAT rules) before the role's `combine` runs.
Alternatively, keep extra rules at one inventory level. Lists are replaced, not
appended.

In the repository baseline, WAN private-source spoof guards run **before**
trusted and established accepts. A private management source arriving on the WAN
interface can therefore lose even established SSH access. Do not automatically
disable protection; first check the intended interface, source networks and route.
If the topology deliberately requires disabling these guards, the actual overrides
are:

```yaml
nft_rules_extra:
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

The observed Debian 13 VM run on `lans@192.168.122.241` on 2026-10-13 used
the original project runner before standalone packaging: **15 PASS, 0 FAIL**, with the
original config/runtime/service/history restored. See [tests/README.md](tests/README.md)
for artifacts and exact scenarios: tagged apply/idempotence/check diff, invalid
syntax, immediate and independent-timer SSH rollback, timer/commit race, extra
rules, live WAN TCP allow/deny and UDP echo, SHA256 history/retention, IPv4 SSH
burst, real nftables package removal/check/reinstall, cleanup and reboot.

IPv6 flood behavior, precise rate-limit refill timing and denied UDP were not
separately tested; neither were all possible initial masked/runtime service states.

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
