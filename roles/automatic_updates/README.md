# lit.ubuntu.automatic_updates

Configure weekly automatic OS updates on Ubuntu systems via cron. By default it
runs `apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade` every
Sunday at 06:00 and writes output to `/var/log/apt-auto-weekly.log`.

## Requirements

The cron interface needs `cron` and network access to its configured repositories.
The separate `tasks_from: staged_verify` entrypoint needs Ubuntu APT, `gpgv`,
Python 3 and the independently admitted archive keyring on the managed target.
It verifies existing staged input and does not install those prerequisites.
`staged_capture` requires privileged read access to the admitted target. The
separate unprivileged `staged_acquire` collector needs native matching architecture
and APT version, Python `apt_pkg`, `gpgv`, `apt-helper`, `dpkg-deb`, sufficient
private workspace and access to the admitted credential-free repositories.

## Variables

- `automatic_updates_enabled` (bool, default: `true`): Enable or disable the cron job.
- `automatic_updates_minute` (string, default: `"0"`): Cron minute.
- `automatic_updates_hour` (string, default: `"6"`): Cron hour.
- `automatic_updates_weekday` (string, default: `"0"`): Cron weekday.
- `automatic_updates_user` (string, default: `"root"`): User owning the cron entry.
- `automatic_updates_log_file` (string, default: `"/var/log/apt-auto-weekly.log"`): Log destination.
- `automatic_updates_command` (string): Command to run.
- `automatic_updates_cron_name` (string, default: `"Weekly automatic updates"`): Cron entry name.
- `automatic_updates_initial_update` (bool, default: `true`): Run an initial apt upgrade when the role executes.
- `automatic_updates_manage_cron_package` (bool, default: `true`): Install the cron package when enabled.
- `automatic_updates_cron_package` (string, default: `"cron"`): Package that provides `crontab` on Ubuntu.
- `automatic_updates_crontab_paths` (list): Paths used to detect whether `crontab` is available.
- `automatic_updates_staged_bundle` (absolute directory): Optional, existing
  controller-acquired metadata bundle for `tasks_from: staged_verify`.
- `automatic_updates_staged_request` (absolute file): Independent admitted JSON
  request; never derive its expected manifest hash from untrusted bundle content.
  See [the staged metadata contract](docs/staged-metadata.md).
- `automatic_updates_staged_action` (`none` by default): Explicit `import` or
  `rollback` for metadata-only `tasks_from: staged_transaction`. The separate
  `staged_cache` accepts `import`, `rollback`, `confirm` and `prune` for coupled
  list/archive/generated-cache lifecycle. All actions require root and a real
  apply; none install packages. See [coupled cache recovery](docs/staged-cache.md).
- `automatic_updates_staged_tool_directory`: Protected root-owned libexec directory
  for the inseparable verifier and transaction helpers.
- `automatic_updates_staged_expected_machine_id`: Independently admitted target
  identity for `tasks_from: staged_capture` and `staged_cache`.
- `automatic_updates_staged_capture_directory`: New private target snapshot directory.
- `automatic_updates_staged_controller_directory`: New controller capture directory;
  the acquisition entrypoint consumes this exact authenticated snapshot.
- `automatic_updates_staged_capture_sha256`: Capture digest received through the
  authenticated target channel; required by acquisition.
- `automatic_updates_staged_expected_collector_id`: Independently selected collector
  machine identity, rechecked before private writes.
- `automatic_updates_staged_acquisition_inputs_directory` and
  `automatic_updates_staged_acquisition_directory`: New exclusive unprivileged
  collector input and work directories; never reuse a stopped attempt.
- `automatic_updates_staged_delivery_directory`: New private controller directory
  for the received bundle and receipts, verified against collector SHA256 results.
- `automatic_updates_staged_receive_directory`: New private target reception path
  for `tasks_from: staged_receive`; its parent must already exist.
- `automatic_updates_staged_expected_archive_sha256`: Archive digest from the
  authenticated collector result, independently provided to reception.

See [target capture and signed payload supply](docs/staged-supply.md) for the
schema2 policy/payload contract, prerequisite checks and separate host boundaries.

`staged_verify` is a read-only admission step, including in check mode. Its
`SIGNED_APT_METADATA_VERIFIED_NO_IMPORT` result is not cache-import, package-update
or operating-system acceptance. The cron defaults and initial update behavior
are unchanged. Hardened disconnected targets still need the complete staged
acquisition, verified deb supply and transactional import before an update can
run; this entrypoint must not be used to bypass those requirements. The optional
metadata-only transaction retains a protected rollback journal and exchanges the
lists atomically under POSIX package locks. Its cache freshness originates at
verified acquisition start. It does not provide deb payloads or alter the cron
update policy.

## Dependencies

None.

## Example Playbook

```yaml
---
- name: Use lit.ubuntu.automatic_updates
  hosts: all
  become: true
  roles:
    - role: lit.ubuntu.automatic_updates
```

## License

MIT

## Author

Lightning IT
