# Staged metadata admission

Use `lit.ubuntu.automatic_updates`, `tasks_from: staged_verify`, only for
verification of already staged public Ubuntu APT metadata. It performs no cache
import, package installation, network request or freshness-marker update.

The independently approved request JSON contains:

- `manifest_sha256`: exact acquisition manifest digest from the authenticated
  collector-to-controller channel; never take it from the bundle being checked.
- `machine_id`, `architecture`, `status_sha256`: target identity and installed
  `/var/lib/dpkg/status` digest captured before acquisition. Foreign package
  architectures are currently rejected.
- `sources`: complete map of active source file paths to SHA256, including
  `sources.list` when present and every `.list`/`.sources` sourceparts file.
- `keyring`: object containing independent target keyring `path` and `sha256`.
- `maximum_age_seconds`: positive integer no greater than 3600. Age starts at
  acquisition start, not the time a file is copied or verification runs.
- `repositories`: each object has `uri`, `suite`, `components` and `list_prefix`.
  The controller must capture these from the target's admitted source/config
  and APT URI mapping; this verifier does not infer or authorize repositories.
  Credentials, non-HTTP(S) schemes and duplicate mappings are rejected.

The bundle directory contains `manifest.json` and regular, non-hard-linked
files. No symlink path components or parent traversal are allowed. The manifest
schema is integer `1`; it repeats the request's target, architecture, package
state, sources and repositories, adds `keyring_sha256`, UTC `started_utc` and
`acquired_utc`, and contains these arrays:

- `releases`: `list_prefix`, relative `file`, `target_name`. Each repository
  has exactly one InRelease, mapped to `<list_prefix>_InRelease`.
- `indexes`: `list_prefix`, `component`, `meta_key`, relative `file` and
  `target_name`. `meta_key` is `<component>/binary-<architecture>/Packages`;
  the target name is the APT list name, optionally ending `.lz4`, `.xz` or `.gz`.
- `packages`: must be empty in schema1. [Schema2](staged-supply.md) adds captured
  target policy and signed-index-bound deb verification. The metadata-only
  transaction still refuses payload-bearing bundles until archive-cache import
  is qualified; verification alone never installs packages.

GPGV runs with an empty temporary home, an exact local keyring and a minimal
environment. Verified signed release data supplies suite, architecture,
components, repository Date, optional Valid-Until and SHA256 index hashes.
`apt-helper cat-file` decodes acquired indexes; their decoded size and digest
must equal the signed uncompressed Packages entry. An absent component index
is accepted only when its signed size is zero and its signed digest is SHA256
of the empty string. Merely trusting compressed-file checksums is insufficient.

The result reports the exact manifest, acquisition origin, signatures and
verified counts, always `changed: false`, `apt_state_changed: false`, and
`package_updates_accepted: false`. Rejection exits with status 2 without
importing package data. The caller must retain the failed attempt and correct
or reacquire its inputs rather than relaxing validation or refreshing timestamps.

```yaml
- name: Verify independently admitted staged package metadata
  ansible.builtin.include_role:
    name: lit.ubuntu.automatic_updates
    tasks_from: staged_verify
  vars:
    automatic_updates_staged_bundle: /var/lib/example/staged-apt/bundle
    automatic_updates_staged_request: /var/lib/example/staged-apt/request.json
```

This is one admission component of a staged patch transaction. It does not
authorize a package change, import stale data, provide a rollback, or make an
unreachable repository usable by itself. A later transaction must hold package
locks, retain a protected rollback snapshot, verify required deb payloads,
import only admitted data, preserve the actual acquisition age and run the
unchanged patch and independent-audit controls.

## Metadata-only import and rollback

`tasks_from: staged_transaction` requires explicit `automatic_updates_staged_action:
import` or `rollback` and a real privileged apply. It fails in check mode before
installing helper files. It does not run the role's cron or initial upgrade tasks.

Import revalidates admission under the existing dpkg frontend, dpkg and APT lists
POSIX locks. It refuses nonempty partial-download directories, incompatible
filesystems, insufficient staging capacity and more than two retained snapshots.
It prepares the verified lists with the existing directory ownership and modes,
preserves the lists lock inode, and uses Linux `renameat2(RENAME_EXCHANGE)` for an
atomic directory swap. Unsupported atomic exchange fails closed. It retains
the previous lists and previous optional update-success stamp under the private
root-owned `/var/lib/apt/lit-staged/<manifest_sha256>/` directory.

Freshness derives from acquisition **start**. Import does not create an absent
update-success stamp; when one exists it receives the same acquisition timestamp
as the imported lists. A repeat checks both exact content and expected freshness
metadata and reports no change. It never substitutes the current time.

Import failures after exchange attempt immediate rollback. The durable journal
also supports an explicit host-side rollback after controller interruption,
including an exchange completed before its final receipt write. This entrypoint
does **not** install an automatic rollback timer. Rollback requires unchanged
target and installed package state and refuses to overwrite unexpected later
cache edits. It restores the original files, modes and modification times plus
the previous optional stamp. It cannot roll back an installed package upgrade.
Retain a stopped journal for reconciliation; never delete one merely to retry.

```yaml
- name: Import admitted metadata without installing any package
  ansible.builtin.include_role:
    name: lit.ubuntu.automatic_updates
    tasks_from: staged_transaction
  vars:
    automatic_updates_staged_action: import
    automatic_updates_staged_bundle: /var/lib/example/staged-apt/bundle
    automatic_updates_staged_request: /var/lib/example/staged-apt/request.json
```

Use the same independently admitted request with action `rollback` to restore
that exact metadata snapshot. Rollback does not require the acquisition still
to be fresh; restoring old cache metadata is recovery, not patch acceptance.
Subsequent patch controls still enforce their ordinary freshness requirement.
