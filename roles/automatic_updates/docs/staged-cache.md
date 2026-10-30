# Coupled staged APT caches

The separate `tasks_from: staged_cache` consumes a schema2 bundle already admitted
by [capture, signed acquisition and independent reception](staged-supply.md).
It never installs packages, changes sources, opens network access or changes the
ordinary patch policy. The metadata-only entrypoint retains its narrower contract.

Import requires the independent machine ID and request, live package-state/source/
keyring/policy verification, actual acquisition age below the admitted maximum
(at most 3600 seconds), canonical standard Ubuntu cache paths and enough capacity.
Linux atomic directory exchange must be available. Nonempty partial downloads,
symlinks, unexpected ownership, package lock contention and incompatible layouts
fail closed. Lists and archives may reside on separate filesystems; each private
snapshot is created on its cache's own filesystem.

The helper holds both transaction locks, dpkg frontend/dpkg locks and both APT
cache locks. It prepares signed lists and payloads, retains unrelated cached debs,
preserves cache lock inodes and directory ownership, and snapshots generated binary
caches plus the optional success stamp. It rechecks freshness and mutable state
immediately before exchanging archives and lists. Generated binary caches are
invalidated; list and existing stamp times reflect acquisition start. An absent
stamp remains absent. An identical import verifies the actual state and reports
no change. Ordinary APT reads may regenerate binary caches without invalidating
this repeat or losing the original snapshots.

```yaml
- name: Import independently admitted coupled caches without installing packages
  ansible.builtin.include_role:
    name: lit.ubuntu.automatic_updates
    tasks_from: staged_cache
  vars:
    automatic_updates_staged_action: import
    automatic_updates_staged_expected_machine_id: '{{ approved_machine_id }}'
    automatic_updates_staged_request: /var/lib/example/staged-apt/request.json
    automatic_updates_staged_bundle: /var/lib/example/staged-apt/bundle
```

The returned journal and `local_return_request` identify the private retained
transaction. On exceptions, immediate rollback restores both original directories,
binary caches and optional stamp, including hashes, ownership, modes and modification
times. After a controller interruption, the installed host helper can perform the
same return using that retained request without a controller connection:

```sh
sudo /usr/bin/python3 -I /usr/local/libexec/lit-staged-apt/apt_staged_cache.py \
  --action rollback --request /var/lib/apt/lit-staged-patches/MANIFEST_SHA256/request.json
```

`MANIFEST_SHA256` is the exact returned transaction ID; replace it with that value.
This is an explicit recovery command, not an automatic timer. Before any return
mutation the helper verifies both sides of both exchanges and protected file
snapshots. Unknown later edits stop recovery for reconciliation. Interrupted
preparation can be marked aborted only when all live caches and files remain
exactly original. Rollback cannot undo installed packages and requires unchanged
package state; it does not require the old acquisition still to be fresh.

Run the ordinary reviewed update and its independent checks separately. `confirm`
requires the exact signed package versions installed and a clean `dpkg --audit`.
Confirmation is cache lifecycle evidence, not operating-system or Story acceptance.
`prune` deletes only this transaction's snapshots after confirmed package state,
verified rollback or verified aborted preparation. Active or unexplained attempts
cannot be pruned. Journal and request tombstones remain to prevent replay; repeats
of rollback, confirmation and pruning report no change. No unknown snapshots are
automatically deleted. Use the same role with the selected explicit action and
independent request for these lifecycle operations; the bundle is needed only for
import. Preserve the request and journal until all required acceptance is recorded.
