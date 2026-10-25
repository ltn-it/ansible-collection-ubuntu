# CIS Ubuntu 24 Role

Thin wrapper around `ansible-lockdown.ubuntu24_cis`.

## Requirements

The execution environment must install `ansible-lockdown.ubuntu24_cis` as a Galaxy role.

## Variables

Set `cis_ubuntu24_profile_tag` to exactly one native upstream profile tag:
`level1-server`, `level1-workstation`, `level2-server`, or
`level2-workstation`. For remediation, set
`cis_ubuntu24_execution_mode: remediate` and invoke Ansible with that same
single `--tags` value. For the independent audit, set
`cis_ubuntu24_execution_mode: audit` and invoke Ansible with exactly
`--tags setup_audit`; the inventory profile remains the authority for
post-processing applicability. The wrapper rejects untagged, broad-tagged,
mixed-profile, and `--skip-tags` runs.

The wrapper requires `ubtu24cis_level_1` and `ubtu24cis_level_2` to match the
declared profile. They shape upstream audit content but do not select
remediation tasks. Audit mode additionally requires `setup_audit`, `run_audit`,
`audit_only`, and `fetch_audit_output` to be true, JSON output, and the pinned
Git audit source. Configure other upstream variables such as
`ubtu24cis_disruption_high` through inventory.

`cis_ubuntu24_exceptions` is the inventory-owned exception registry. Each item
records control IDs, scope, reason, compensating control, effective upstream
variables, and audit visibility. Omitted controls remain exceptions and must
never be reported as passes.

Optional `cis_ubuntu24_apparmor_preserved_profiles` records accepted Ubuntu
package-compatible usernamespace attachment profiles. Each entry contains
exactly `name`, `executable`, `sha256`, `reason`, and `approval_reference`.
The reference must bind an existing accepted intentional exception for control
1.3.1.3 in `cis_ubuntu24_exceptions`; declaring metadata does not grant approval.
This interface supports Level 1 only and requires the conflicting upstream
`ubtu24cis_rule_1_3_1_3: false`. An empty list retains upstream behavior.

Before and after upstream execution, including audit setup, a read-only guard
requires enabled AppArmor and the unprivileged-usernamespace restriction. It
verifies AppArmor package ownership, root-owned non-writable directory
boundaries, root-owned mode-0644 single-link regular files, exact hashes,
attachment declarations and the usernamespace permission. Only declared
profiles may be loaded as unconfined; every other loaded profile must enforce.
Missing profiles, unknown non-enforcing modes, unsafe files, changed packages
or policy drift require review and stop the run. No profile is rewritten,
reloaded or downgraded by this guard. Check mode performs these read-only checks.

Retain the accepted exception and its approval reference in independent audit
evidence; it remains an exception, not a benchmark pass. Kernel container-process
labels, confinement stacking and container/host/network boundaries need their
own acceptance. A loaded-profile count or application startup alone does not
prove them. Re-review the binding after package, profile, runtime or policy
changes. Do not infer installed tool behavior from a newer AppArmor manual:
some installed `aa-enforce` implementations remove the `unconfined` flag.

`cis-ubuntu24-apparmor-inputs-basic` verifies the actual Ansible input and
audit-binding assertions without changing a host. The filesystem guard unit
tests use isolated files and synthetic kernel listings; they do not load policy
or prove live confinement. Fresh-package target verification remains required.

The separate **`apparmor_restore.yml`** entrypoint repairs one previously
rewritten attachment to its exact accepted package-compatible content. It is
never invoked by the ordinary wrapper or audit. Supply
`cis_ubuntu24_apparmor_restoration` with exactly `name`, `machine_id`,
`package_version`, `source`, `previous_sha256`, and `approval_reference`.
The profile name, desired hash and approval must match the existing accepted
preservation policy. `source` is an absolute controller path to an independently
verified manufacturer profile; the role neither downloads nor derives it from
the current file. Target machine ID, exact installed AppArmor package version,
package ownership, previous or desired file hash and all loaded profile modes
must match before any target write. Check mode and audit mode refuse restoration.

Invoke it explicitly with `ansible.builtin.include_role`,
`name: lit.ubuntu.cis_ubuntu24`, and `tasks_from: apparmor_restore.yml`, in a
fact-gathering, privileged Ubuntu 24 play. Keep the accepted Level 1 policy and
visible CIS exception in inventory; a newly entered reference grants no approval.
Use the normal wrapper afterwards for baseline and independent audit acceptance.

The transaction retains a root-only immutable ownership record and original
file under `/var/lib/lit-cis-apparmor/<machine-id>/<name>-<previous-sha256>`.
Redirected, writable, linked, colliding or changed rollback resources fail closed.
The parser validates the candidate before replacement. Only that changed
attachment is reloaded, then the normal full preservation guard and exact
loaded-profile map are checked. Failure restores and verifies the original file
and map when the invocation began with the previous policy. An unchanged repeat
requires the retained rollback but never reinstalls that older policy on failure.
Rollback failure remains a failure requiring investigation. Preserve the snapshot
until change acceptance; the role never deletes it or reconfigures other profiles.
Kernel interruption recovery and package updates still require their normal
operational recovery procedure. The entrypoint has no host-side timeout rollback.

When upstream AIDE remediation uses its default cron scheduler, the wrapper
masks the unused package-provided `dailyaidecheck.service`. This preserves the
cron job while preventing the upstream role from repeatedly attempting to
disable a static systemd unit. Selecting the upstream timer scheduler removes
only that wrapper-owned `/dev/null` mask before the upstream role configures
the timer units.

Optional `cis_ubuntu24_aide_exclusions` entries contain exactly `path` and
`reason`. They declare mutable data directories outside system trees; paths
must be normalized, contain at least three components, and resolve without
symlink redirection. Existing exclusion objects must be directories; files
and special objects are rejected before package changes. An empty list
preserves the existing upstream behavior.
Nonempty exclusions require enabled upstream AIDE and control 6.3.1. Their
preparation rejects check mode: package and parser acceptance require a real
isolated Ubuntu target.

Before installation, the wrapper disables the package's background-init
debconf answer and uses Ansible's temporary `policy_rc_d` protection. It then
verifies the package include and database paths, renders only its root-owned
non-executable `90_lit_mutable_data` fragment, checks the full configuration,
and restores that fragment if validation fails. The root configuration is
never rewritten. For cron scheduling, the package timer is stopped and
disabled; the existing service mask is preserved. Upstream initializes only
after these checks. Document the exact mutable-data scope and reasons in
inventory and prove the included and excluded boundaries independently.
The installation, regular-check and audit-tool protection controls remain
enabled; scoped data policy alone proves none of those controls. An actual
control omission requires its own visible exception. Exclusions replace
neither application backups nor image integrity verification.

The pinned upstream can delete an aged database before initializing again.
With exclusions enabled, an existing database therefore requires a reviewed
`cis_ubuntu24_aide_rebaseline` binding before age-triggered recreation,
explicit recreation, or a policy change. Its exact keys are
`database_sha256`, `exclusions_sha256`, and `approval_reference`. The hashes
bind the observed database and newly rendered exclusion fragment, not the
entire host configuration. Policy changes additionally require upstream
`ubtu24cis_aide_db_recreate: true`. Approval must come from the normal change
process; the wrapper does not grant it. Clear the one-time recreate input
after acceptance. A stale database binding fails before package changes.
Neither the default empty approval nor database age authorizes rebaselining.

The unmanaged `cis-ubuntu24-aide-inputs-basic` scenario tests input and
admission assertions only. Real package post-installation behavior, AIDE
configuration parsing, initialization, included/excluded tamper detection,
scheduler state, rollback, and repeat application require isolated Ubuntu 24
acceptance under the validation repository's execution contract.

Optional `cis_ubuntu24_disabled_filesystem_modules` entries contain exactly
`name` and a single-line `reason`. The empty default changes no module policy.
Inventory must review actual filesystem module metadata and dependencies;
kernel directory names are not module names. Boot and container primitives
are rejected. The native preflight rejects loaded or built-in modules, active
or declared filesystem mounts (including inactive systemd mount files), and
known active or potentially activated filesystem services. Each selection
must resolve to its own module file in the running kernel's filesystem tree
and declare a real `fs-*` alias. These checks supplement the operator's
dependency assessment; they cannot discover arbitrary future application use.

Remediation owns only `/etc/modprobe.d/60-lit-unused-filesystems.conf`. It
requires a safe root-owned directory and refuses foreign, linked or unsafe
existing fragments. Each selected module receives an install blocker and
blacklist. An empty per-module soft dependency prevents kernel-provided soft
dependencies from overriding the install blocker. This affects only the
selected unused module; hard dependencies and unrelated configuration remain
intact. The actual non-loading resolution must contain the blocker and must
not insert the selected module. Listing hard dependencies before the blocker
does not mean the selected filesystem is loadable. Actual kmod configuration
and non-loading resolution are checked;
failed validation restores the exact previous fragment, or removes only the
new fragment. No module is loaded or unloaded, and no initramfs is rewritten.
Audit mode makes no changes. A real isolated apply, negative dependency and
ownership tests, both rollback branches, alias resolution and a second
unchanged apply are required; check mode cannot qualify this integration.
After the upstream role, the wrapper rechecks effective policy. Boot-image
contents, persistence after a controlled reboot and independent benchmark
results require separate acceptance. Preserve required or loaded modules with
their own documented disposition; a discovery warning is not an automatic
authorization to block a filesystem or an audit pass.

The upstream 6.2.4.1 remediation recursively applies a file-only mode to the
audit log directory. When inventory explicitly disables that defective
control while retaining 6.2.4.4, the wrapper preserves `/var/log/audit` as a
traversable mode-0750 directory. Inventory must separately document the
6.2.4.1 exception and its audit-log-file compensating control.
Override `cis_ubuntu24_audit_log_directory` only when auditd uses a different
absolute log directory.

## Dependencies

External Galaxy role: `ansible-lockdown.ubuntu24_cis`.

- Remediation: `ansible-lockdown/UBUNTU24-CIS` release `1.8.0`, commit
  `3a2f05b9a8040eb869fd14fdca882aae4f68733b`, MIT.
- Audit: `ansible-lockdown/UBUNTU24-CIS-Audit` benchmark `v1.0.0`, commit
  `87efcc6d409d1a998a7cb809c5ce5a6afedf84c7`, MIT.

The remediation role is updated through `requirements.yml`. Audit content has
no upstream release, so update its immutable commit and archive checksum
together after reviewing compatibility with the remediation release.

The standard Ansible EE and the Automation runtime admission must select the
same remediation release. Version 1.8.0 continues to use CIS benchmark v1.0.0;
its split audit defaults do not replace the independently pinned audit above.
Changing the dependency does not approve an exception or disable a control.

The auditor runtime is separately fixed to canonical `goss-org/goss` **v0.4.8**,
with the reviewed SHA256 for each target architecture (`x86_64` or `aarch64`)
in `cis_ubuntu24_auditor_dependency`. The wrapper does not inherit a changed
vendor fork, version or download source. A runtime-pin change requires reviewing
both architecture checksums together with benchmark compatibility.

During audit setup, the controller acquires that exact release with TLS and
checksum verification into its private, checksum-addressed
`cis_ubuntu24_auditor_cache_directory`. For offline execution, supply the absolute
controller path `cis_ubuntu24_auditor_source` to those same public release bytes.
The offline input is checked against the fixed architecture checksum, never a
caller-supplied replacement hash. Missing, linked, changed or unsupported inputs
fail before vendor execution. The binary is not executed on the controller.

The admitted input uses the vendor-supported `copy` interface and fixed
`/usr/local/bin/goss` destination. Host facts preserve the version, checksums,
path and transport across vendor variable loading. The target needs no Internet
access for the auditor binary. Audit content still uses its separate reviewed
Git/archive contract; neither transport waives a benchmark control or exception.

## Example Playbook

```yaml
---
- name: Use lit.ubuntu.cis_ubuntu24
  hosts: ubuntu24_cis_targets
  become: true
  vars:
    cis_ubuntu24_profile_tag: level1-server
  roles:
    - role: lit.ubuntu.cis_ubuntu24
```

Invoke the example with `--tags level1-server`.

## License

MIT

## Author

Lightning IT

### Read-only native password-aging evidence

The explicit `password_policy_audit.yml` entrypoint verifies effective
`ubtu24cis_pass_max_days` and `ubtu24cis_pass_warn_age` against global
`login.defs` defaults and every native unlocked password account. Locked
accounts do not require password-aging metadata. No eligible password accounts
is a valid empty account subject, but never excuses invalid global defaults.
Missing, password-free or unknown account status fails closed; incomplete native
metadata stops the audit. Only counts and per-control results are returned, with
no account names, shadow hashes or credential values. The independent consumer
must retain raw producer failures and require the matching supplemental result;
this entrypoint does not remediate accounts or run automatically during CIS apply.

### Independently admitted offline audit transport

Audit mode accepts `audit_content: archive` only with an absolute controller
`audit_conf_source`, absolute target `audit_conf_dest` and independent
`cis_ubuntu24_audit_transport_sha256`. The caller must first stage
`UBUNTU24-CIS-Audit/` under that destination. The wrapper rechecks archive bytes,
canonical target path, root ownership and executable modes, clean Git state,
origin and the unchanged reviewed audit commit before vendor execution. The
transport checksum describes the authenticated delivery archive; it does not
replace `cis_ubuntu24_audit_dependency.archive_sha256` or any source pin.

Archive and destination facts survive vendor variable loading. Scoped module
defaults keep repeated upstream extraction root-owned. Normal Git transport,
profile tags, audit-only selection, independent evidence and exception controls
remain unchanged. Missing digest, changed archive, dirty/foreign checkout or
unsafe ownership fails before the vendor audit. Other transports remain refused.
