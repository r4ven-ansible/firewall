# Destructive firewall VM integration tests

Run only on an authorized disposable Debian VM with passwordless sudo and an already accepted SSH host key:

```sh
python3 tests/run_vm.py --host 192.168.122.241 --user lans --reboot
```

The runner uses Python's standard library and the controller's `ansible-playbook`. It creates its own inventory, playbook, Ansible configuration, SSH ControlMaster socket and logs in `/tmp/firewall-vm-*`. It does **not** load the repository inventory, host vars, or secrets. The playbook explicitly loads only `examples/inventory/group_vars/all/firewall.yml` via `vars_files`. Connection variables come from the generated single-host inventory.

Overrides make the controller a WAN source: `192.168.0.0/16` is excluded from `nft_lan4_networks`, trusted is `203.0.113.123`, and all four input/forward spoof rules are removed with `null`. Original SSH flood rules are enabled only in the flood scenario; other scenarios remove them to avoid consuming management connection budget.

## Safety and artifacts

Before changing the VM, a private `/root/firewall-vm-*` directory snapshots the original config (including symlink), nft runtime, service enablement/mask/active state, and `/root/nft_backup` history. A separate systemd emergency restore timer is armed before destructive scenarios. Reboot additionally has an enabled persistent `OnBootSec=180` emergency restore timer. Final restoration compares config, static runtime, service states and original history. Snapshots/logs remain available for investigation; transient test listener and persistent emergency units are removed. Failed role transaction snapshots are left intact by the role and may disappear on reboot.

Emergency manual restore, substituting the directory printed by the runner:

```sh
ssh lans@192.168.122.241 'sudo -n /root/firewall-vm-RUN_ID/restore'
```

The suite is destructive: flushes the ruleset, replaces `/etc/nftables.conf`, temporarily replaces history, removes/reinstalls `nftables`, optionally reboots, and briefly blocks **all** SSH traffic including established sessions. Do not run alongside other firewall changes. The default target is the authorized test VM, not production.

## Previous integration run before standalone packaging (2026-10-13)

The following run used the original project layout. After packaging, the runner paths were adapted; the destructive VM suite has not been rerun in this repository.

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

- Baseline, extra rules/WAN setup, history rotation/idempotence, flood cleanup, and changed reboot setup use the enabled role SSH safeguard. Only installation of the actual flood rules uses `nft_ssh_check_enabled: false`, keeping the independent emergency timer and established ControlMaster management; after the burst, limits are removed with role SSH-check enabled. Both real SSH rollback scenarios and the timer race also use the role safeguard.
- Timer race uses a delayed local TCP listener as the reachability target to deterministically hold `wait_for` until rollback executes. Full real SSH loss is a separate scenario. systemd timer coalescing means the configured timeout is not a strict execution deadline; the race allows 110 seconds before listener availability.
- Flood test verifies aggregate admission/rejection and the actual per-source dynamic set for IPv4, not fairness across multiple sources, precise 20/minute refill timing, or IPv6 behavior.
- WAN probes use a real TCP listener on allowed and denied ports and a UDP echo server. Denied UDP is not tested separately. No external public network is involved.
- Reboot checks loaded table and service/config persistence; it does not compare every dynamic nft counter/set entry across boots.
- Package removal is real, not a fake `nft_bin`. No purge is used. Package download/install needs apt availability; the reinstall can update package version if repository versions change. Active runtime during the absent-package check is not separately inspected while the nft executable is unavailable.
- Original history is restored, including metadata copied with `cp -a`; the tests verify rotation/idempotence but do not exercise every content-addressed deduplication cycle or every possible initial masked-runtime/service state.
- Emergency restoration may retry package installation if nft is missing. It therefore depends on apt availability in that particular failure mode; the normal firewall rollback uses the already-installed executable.
