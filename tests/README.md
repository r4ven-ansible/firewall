# Destructive firewall VM integration tests

Run only on an authorized disposable Debian VM with passwordless sudo and an already accepted SSH host key:

```sh
python3 tests/run_vm.py --host 192.168.122.241 --user lans --reboot
```

The runner uses Python's standard library and the controller's `ansible-playbook`. It creates its own inventory, playbook, Ansible configuration, SSH ControlMaster socket and logs in `/tmp/firewall-vm-*`. It does **not** load the repository inventory, host vars, or secrets. The playbook explicitly loads only `examples/inventory/group_vars/all/firewall.yml` via `vars_files`. Connection variables come from the generated single-host inventory.

The shipped baseline runs as published: all four input/forward spoof guards stay enabled and `nft_lan4_networks` keeps `192.168.0.0/16`, which contains this VM's management source. Every scenario therefore doubles as a regression test for the lockout that used to make a first rollout roll back. Trusted is `203.0.113.123`. Original SSH flood rules are enabled only in the flood scenario; other scenarios remove them to avoid consuming management connection budget.

Two overrides exist because the baseline classifies an on-link private source as a LAN neighbour, not as WAN:

- `wan_view` (`nft_lan4_networks` without `192.168.0.0/16`) is used by the scenarios that assert WAN-side behaviour: WAN port policy and live probes, per-source SSH flood limits, and denial of new WAN SSH.
- `unprotected` (`nft_mgmt_allow_enabled: false` plus empty `nft_wan_local4_networks`) reproduces the original incident. Both the management allow rule and the on-link spoof exceptions prevent it independently, so both have to be off for the host to lock itself out.

## Safety and artifacts

Before changing the VM, a private `/root/firewall-vm-*` directory snapshots the original config (including symlink), nft runtime, service enablement/mask/active state, and `/root/nft_backup` history. A separate systemd emergency restore timer is armed before destructive scenarios. Reboot additionally has an enabled persistent `OnBootSec=180` emergency restore timer. Final restoration compares config, static runtime, service states and original history. Snapshots/logs remain available for investigation; transient test listener and persistent emergency units are removed. Failed role transaction snapshots are left intact by the role and may disappear on reboot.

Emergency manual restore, substituting the directory printed by the runner:

```sh
ssh lans@192.168.122.241 'sudo -n /root/firewall-vm-RUN_ID/restore'
```

The suite is destructive: flushes the ruleset, replaces `/etc/nftables.conf`, temporarily replaces history, removes/reinstalls `nftables`, optionally reboots, and briefly blocks **all** SSH traffic including established sessions. Do not run alongside other firewall changes. The default target is the authorized test VM, not production.

## Integration run after the safety rework (2026-10-14)

```sh
python3 tests/run_vm.py --host 192.168.122.241 --user lans --reboot
```

Target: `lans@192.168.122.241`, Debian 13 (`debian13-nft`). Logs:
`/tmp/firewall-vm-42siz41l`; machine-readable results:
`/tmp/firewall-vm-42siz41l/results.json`; original VM snapshot:
`/root/firewall-vm-42siz41l`. Runner exit status **0** (**22 PASS, 0 FAIL**),
original config absence, runtime, service state and history restored.

| Scenario | Result |
|---|---|
| Baseline apply with the shipped spoof guards enabled and `192.168.0.0/16` in `nft_lan4_networks`, timer/transaction/boot-unit cleanup | PASS |
| Identical tagged reapply: `changed=0`, config/runtime/history untouched | PASS |
| `-t nft_apply --check --diff`: expected TCP/UDP diff, unchanged state | PASS |
| Invalid nft syntax: nonzero rc, unchanged state | PASS |
| Deny new SSH while established management survives: immediate rescue rollback | PASS |
| Drop all SSH including established: nonzero rc, independent timer restores config/runtime/enabled unmasked service | PASS |
| Timer wins while a delayed probe later succeeds: commit refuses and names the lost connection instead of failing blankly | PASS |
| Extra add/change/null, `nft_rules_host`, allowed ports, management rule rendered first, all four guards present | PASS |
| WAN live TCP allow/deny and UDP echo probes | PASS |
| Four changed configs: content hash, backup mtime, retention, mode 0600, repeat idempotence | PASS |
| Real SSH burst: per-source limit measurable with the management rule off, source in the dynamic set | PASS |
| Real `dpkg --remove nftables`: `LoadState=not-found`, full `--check --diff` changes nothing, apt reinstall | PASS |
| Baseline guards with both protections off: lockout reproduced and rolled back | PASS |
| Reachability checks disabled: rollback still armed and restores | PASS |
| Manual `nft flush ruleset`: drift detected, reapplied, reported as changed, idempotent afterwards | PASS |
| `ssh_port` not matching the live sshd listener: refused before any change | PASS |
| Reachability probe over Ansible's own connection path (reset + reconnect) | PASS |
| Armed neighbour transaction refuses a new one; finished neighbours collected | PASS |
| Reachability timeout past the rollback timer: refused before any change | PASS |
| No active rollback timer, boot unit or transaction directory before reboot | PASS |
| Changed apply, then reboot: boot ID changes, same config hash, nftables enabled/active, filter table loaded | PASS |
| Final original config/runtime/service/history restoration | PASS |

Four earlier rounds of this suite found, in order: the WAN-side scenarios had to
stop assuming the controller is a WAN source (it is an on-link neighbour in the
baseline); OpenSSH 9.8+ `PerSourcePenalties` blocks the controller after an
unauthenticated burst and poisons later scenarios unless drained; a drift reapply
reported `changed=0` because every transaction task is `changed_when: false`; a
fail_msg sentence was broken apart by YAML folding and an unparenthesised
`ternary` sum; and — found by the package scenario hanging on `apt` — the spoof
guards sitting before `allow_established` drop reply traffic from a resolver or
gateway on a private uplink. The first two were fixed in the runner, the rest in
the role.

## Earlier integration run, before the safety rework (2026-10-13)

The table below is the run of the previous role version, kept for comparison. It predates the management allow rule, the independent rollback arming, the persistent on-boot restore, drift detection and the preflight asserts, and it ran with the four spoof guards neutralised by `null`. See the section after it for the current run.

Equivalent command in this layout:

```sh
python3 tests/run_vm.py --reboot
```

Target: `lans@192.168.122.241`, Debian 13. Logs: `/tmp/firewall-vm-1s2zk6kl`; machine-readable results: `/tmp/firewall-vm-1s2zk6kl/results.json`; original VM snapshot: `/root/firewall-vm-1s2zk6kl`. Each Ansible invocation retains a separate numbered vars JSON beside its command/output log.

| Scenario | Result |
|---|---|
| Baseline changed apply with `-t nft_apply`, enabled role SSH safeguard, and timer/transaction cleanup | PASS |
| Backup/history unchanged on identical tagged reapply (`changed=0`) | PASS |
| `-t nft_apply --check --diff`: expected TCP/UDP diff, unchanged state | PASS |
| Invalid nft syntax: nonzero Ansible rc, unchanged state | PASS |
| Deny new SSH while established management remains: immediate rollback restores config/runtime/service | PASS |
| Drop all SSH before established: nonzero Ansible rc, rescue unreachable, independent timer restores config/runtime/enabled active unmasked service | PASS |
| Timer wins, delayed controller probe subsequently succeeds: commit fails instead of false success, prior state restored | PASS |
| Extra add/change/null; four spoof rules absent; SSH excluded from generic WAN ports | PASS |
| WAN live TCP allow/deny and UDP echo probes | PASS |
| Four changed configurations with enabled SSH safeguard: content hash, newly created backup mtime despite source mtime 2000-01-01, retention 3, mode 0600, repeat idempotence | PASS |
| Real SSH connection burst: some admitted, some blocked, source appears in dynamic set; persistent management remains usable | PASS |
| Real `dpkg --remove nftables`: binary and unit absent, `LoadState=not-found`; full `--check --diff` makes no config/package/service changes; apt reinstall | PASS |
| Before reboot, no active/activating role rollback timer or service remains | PASS |
| Changed apply with enabled SSH safeguard, then reboot: boot ID changes, same config hash, nftables enabled/active, filter table loaded | PASS |
| Final original config/runtime/service/history restoration | PASS |

Overall runner exit status: **0** (**15 PASS, 0 FAIL**). The role was not modified by the test runner work.

The first repeat (`/tmp/firewall-vm-yg1m5rno`) ended early because the test checked SSH restoration before the coalesced systemd timer fired. Journal inspection confirmed later independent rollback; final restoration succeeded. The runner now polls SSH for at most 100 seconds after the nonzero Ansible result, rather than assuming the configured timer timeout is a strict deadline. The table above describes the subsequent complete run.

## Verified user fixes and timer cleanup

The user changed role cleanup to stop only the rollback `.timer`, and changed history copying from `cp -p` to `cp` so mtime represents history creation. Both changes passed the complete VM run; the previous post-commit rc=5 failure did not recur.

For baseline, extra rules, every history change, flood cleanup, and reboot setup, `positive()` checks that successful tagged apply leaves no new active/activating rollback timer and no new `/tmp/nft-transaction-*` directory. Old failed-transaction snapshots are not mistaken for successful-apply leaks. A separate pre-reboot assertion verifies no active/activating `nft-rollback-*.timer` or `.service` remains. These checks run before reboot, so reboot cannot conceal a cleanup leak.

Backup validation sets the source config mtime to 2000-01-01, records its hash and VM time, then verifies the content-addressed history entry has matching content and an mtime at or after the apply start. Identical reapply leaves config/runtime/history, including history mtimes, unchanged.

## Scope and limitations

- The management allow rule, the on-link spoof exceptions, independent rollback arming, drift detection, the preflight asserts and `nft_rules_host` each have a scenario. Reported as untested: idempotence of `prepare`/`commit` under a real Ansible SSH retry (the retry is hard to provoke deterministically; the subcommands were reviewed and exercised by hand), and an actual reboot *inside* the transaction window. For the latter the suite verifies the mechanism instead: the persistent `nft-rollback-*-boot` units exist while a failed transaction stays armed, are gone after commit, and no unit or transaction directory is left behind before the reboot scenario.

- Baseline, extra rules/WAN setup, history rotation/idempotence, flood cleanup, and changed reboot setup use the enabled role SSH safeguard. Only installation of the actual flood rules uses `nft_ssh_check_enabled: false`, keeping the independent emergency timer and established ControlMaster management; after the burst, limits are removed with role SSH-check enabled. Both real SSH rollback scenarios and the timer race also use the role safeguard.
- Timer race uses a delayed local TCP listener as the reachability target to deterministically hold `wait_for` until rollback executes. Full real SSH loss is a separate scenario. systemd timer coalescing means the configured timeout is not a strict execution deadline; the race allows 110 seconds before listener availability.
- Flood test verifies aggregate admission/rejection and the actual per-source dynamic set for IPv4, not fairness across multiple sources, precise 20/minute refill timing, or IPv6 behavior.
- WAN probes use a real TCP listener on allowed and denied ports and a UDP echo server. Denied UDP is not tested separately. No external public network is involved.
- Reboot checks loaded table and service/config persistence; it does not compare every dynamic nft counter/set entry across boots.
- Package removal is real, not a fake `nft_bin`. No purge is used. Package download/install needs apt availability; the reinstall can update package version if repository versions change. Active runtime during the absent-package check is not separately inspected while the nft executable is unavailable.
- Original history is restored, including metadata copied with `cp -a`; the tests verify rotation/idempotence but do not exercise every content-addressed deduplication cycle or every possible initial masked-runtime/service state.
- Emergency restoration may retry package installation if nft is missing. It therefore depends on apt availability in that particular failure mode; the normal firewall rollback uses the already-installed executable.
