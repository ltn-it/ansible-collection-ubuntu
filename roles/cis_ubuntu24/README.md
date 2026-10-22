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

When upstream AIDE remediation uses its default cron scheduler, the wrapper
masks the unused package-provided `dailyaidecheck.service`. This preserves the
cron job while preventing the upstream role from repeatedly attempting to
disable a static systemd unit. Selecting the upstream timer scheduler removes
only that wrapper-owned `/dev/null` mask before the upstream role configures
the timer units.

Optional `cis_ubuntu24_aide_exclusions` entries contain exactly `path` and
`reason`. They declare mutable data directories outside system trees; paths
must be normalized, contain at least three components, and resolve without
symlink redirection. An empty list preserves the existing upstream behavior.
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
after these checks. Exclusions require their own inventory exception and
independent evidence; they are not benchmark passes or a replacement for
application backups and image integrity.

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

The upstream 6.2.4.1 remediation recursively applies a file-only mode to the
audit log directory. When inventory explicitly disables that defective
control while retaining 6.2.4.4, the wrapper preserves `/var/log/audit` as a
traversable mode-0750 directory. Inventory must separately document the
6.2.4.1 exception and its audit-log-file compensating control.
Override `cis_ubuntu24_audit_log_directory` only when auditd uses a different
absolute log directory.

## Dependencies

External Galaxy role: `ansible-lockdown.ubuntu24_cis`.

- Remediation: `ansible-lockdown/UBUNTU24-CIS` release `1.6.0`, commit
  `c893ca6836fb32b1ea067d4a63c341e39693074b`, MIT.
- Audit: `ansible-lockdown/UBUNTU24-CIS-Audit` benchmark `v1.0.0`, commit
  `87efcc6d409d1a998a7cb809c5ce5a6afedf84c7`, MIT.

The remediation role is updated through `requirements.yml`. Audit content has
no upstream release, so update its immutable commit and archive checksum
together after reviewing compatibility with the remediation release.

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
