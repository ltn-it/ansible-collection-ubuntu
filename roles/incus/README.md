# lit.ubuntu.incus

Configure an Ubuntu host as an Incus host for system containers and virtual
machines. For VM workloads, Incus manages the instance lifecycle while QEMU/KVM
provides hardware virtualization.

## Requirements

- Ubuntu target with systemd.
- Root privileges on the target host.

## Variables

See `defaults/main.yml` for the full interface. Key variables:

- `incus_packages` (list): Packages installed for Incus and QEMU support.
- `incus_initialize` (bool, default: `true`): Run `incus admin init --minimal` when Incus is not initialized.
- `incus_manage_root_idmap` (bool, default: `true`): Reconcile the root
  SubUID/SubGID allocation consumed by the Incus daemon before instance work.
- `incus_root_idmap_start` and `incus_root_idmap_count`: Inventory-overridable
  subordinate-ID range; the count must contain at least 10 million IDs.
- `incus_root_subuid_path` and `incus_root_subgid_path`: Overrideable paths,
  primarily for isolated validation scenarios.
- `incus_preseed` (mapping, default: `{}`): Optional desired Incus bootstrap state. When no storage pool exists, the
  complete mapping is passed to `incus admin init --preseed` instead of the minimal initializer. On an already
  initialized host, missing entries from `storage_pools` are created and entries from `networks` are created or
  reconciled, including their configuration.
- `incus_projects` (list, default: `[]`): Projects to create and project configuration keys to reconcile.
- `incus_profiles` (list, default: `[]`): Project-scoped profiles whose description, configuration, and devices are
  reconciled exactly.
- `incus_services` (list): Systemd units to enable and start.
- `incus_users` (list, default: `[]`): Users to add to `incus_user_groups`.
- `incus_user_groups` (list, default: `["incus-admin", "kvm"]`): Runtime groups for Incus users.

Storage, project, and profile discovery failures stop the role before any related mutation. The default minimal
initializer does not expose the Incus API remotely. A remote listener is configured only when the caller explicitly
supplies the relevant server configuration in `incus_preseed`.

### Explicit coordinated runtime-package maintenance entry

`tasks_from: runtime_packages` is a separate, explicitly invoked entry; `main`
never imports it. It installs one fixed Root-owned helper and performs one APT
transaction for the six direct targets `incus`, `incus-base`, `incus-client`,
`podman`, `crun`, and `conmon`. It never calls normal Incus/Podman role tasks,
handlers, daemon initialization, AppArmor reconciliation, or subordinate-ID work.
Package maintainer scripts and triggers can still change services, AppArmor,
sysctl, ID allocations, and shared-host state. This is real maintenance when invoked.

Required inputs are `incus_runtime_packages_request_path` (absolute, Root0600,
single-link regular JSON in a Root0700 directory with safe Root ancestors) and
`incus_runtime_packages_request_sha256`. No URLs, package names, arbitrary APT
arguments, hooks, or maintenance-approval booleans are accepted as role options.
The fixed helper is `/usr/libexec/lightning-it/incus-maintenance/runtime_packages.py`.
An absent helper is installed; an existing different, linked, foreign, or unsafe
helper/parent stops before replacement. Updating a different helper is a separate
reconciliation operation, so a pending APT hook cannot silently change source.

The request has exactly these fields (schema 2); this is an interface description,
not an operational input file or installation authorization:

| Fields | Binding |
| --- | --- |
| `schema`, `hostname`, `machine_id`, `expires_at` | Integer 2; actual host/machine ID; UTC epoch expiry within one hour |
| `candidate_path` | Private exact 32-package candidate JSON |
| `payload_directory`, `archive_directory` | Separate existing Root0700 direct-six directory and private cache containing all 32 APT-named archives |
| `reviewed_simulation_path`, `reviewed_simulation_sha256` | Private original reviewed full APT simulation stdout and SHA256 |
| `dpkg_status_sha256`, `extended_states_sha256` | Full native status and APT automatic-selection bytes |
| `apt_lists_sha256`, `apt_config_sha256` | `tree_hash` fingerprints of `/var/lib/apt/lists` and `/etc/apt` |
| `apt_get_sha256`, `dpkg_deb_sha256`, `apt_config_tool_sha256`, `apt_version` | Exact native fixed-tool identities and APT version |

This source revision accepts the reviewed candidate digest
`1b7c0c2c6baeb0b3130f3156047dcf1f40db59e89345ea593e909472e5ed7500`
only: 32 exact authenticated package/version/architecture/size/SHA identities,
204332636 bytes. Direct Incus versions are `1:7.6-ubuntu24.04-202611021330`,
Podman `4.9.3+ds1-1ubuntu0.2`, crun `1.14.1-1`, conmon `2.1.10+ds1-1build2`.
The native APT source contract is `apt 2.8.4 (amd64)`, binary SHA256
`87279ca48820a0423c2ee8b25dba48af0ad7d9f46c16f1e3cfdc07934dcf5ae1`.
Neither a new repository candidate nor a merely matching version substitutes.
The six direct input filenames are fixed in the helper. All 32 cache filenames
follow APT 2.8.4 package/version/architecture naming, including percent-encoded
epochs, without making network requests.
Every archive must already exist, Root0600/single-link, with exact bytes and
control identity. APT administrative `lock` and empty `partial` are the only
additional private-cache entries; empty administrative list directories may be
owned by Root or the existing `_apt` service account. No payload is admitted there.

The helper binds the complete reviewed Install/Configure plan to the exact
closure members that differ from the fresh hash-bound dpkg snapshot. Already
configured members at the pinned version and architecture require no reinstall.
Both action sets must contain every required change exactly once, with the
actual installed old version; removals, downgrades, architecture changes,
unchanged-package actions and extra/pending package work are rejected. All
32 authenticated payloads remain mandatory, and the final state must prove all
32 exact configured identities. It uses one actual
six-target APT invocation with the private archive cache and `--no-download`,
`--no-remove`, and `--assume-yes`. Simulation uses the same cache but excludes
`--no-download`. The fixed protocol-3 pre-install hook checks all final package
action tuples and archive bytes again while the checked APT branch retains its
frontend lock; the inner dpkg lock is released at that point. Both phases force
normal locking/cache generation and disable APT update; real install also disables
download-only, URI printing, and simulation. Unknown inherited pre-install hooks,
all nonempty Pre-Invoke hooks, and unsupported native shortcuts are denied.
The exact qualified Ubuntu Debconf hook described below is the only supported
nonempty inherited pre-install list, containing exactly one entry.
Read-only effective `apt-config shell` queries must prove empty `RootDir` and
standard native metadata/configuration/executor paths before either APT phase.
Both phases additionally fix those paths in argv; the protocol-3 header must
agree. This includes status/lists/extended states, the parent state/config
paths and their source/preferences/trust/auth subpaths, and `/usr/bin/dpkg`.
Custom `DPkg::Path` and inherited `DPkg::Options` are refused; no request can
redirect dpkg with `--root` or `--admindir`. The query output is parsed as data,
never evaluated as shell code. Filename/directory resolution uses the documented
[`apt-config` `/f` and `/d` modes](https://manpages.ubuntu.com/manpages/noble/de/man8/apt-config.8.html).

The effective root boolean `APT::Update` must be false, as resolved by APT's
`/b` query. An empty root value with inactive update children is supported;
counting or rejecting the entire update subtree would misclassify normal Ubuntu
configuration. Both phases still force that root false. A true root is denied.

### Qualified Ubuntu Debconf compatibility

The fixed public `runtime_packages_debconf.json` asset pins Debconf and
debconf-i18n `1.5.86ubuntu1`, apt-utils `2.8.4ubuntu0.1`, observed dpkg/Perl
versions, five native public files, and the exact 101-file Debconf module tree.
Its SHA256 is `34a91088a7972cdb4eaf59f35f8b3c5b34d40e71b8b4543120d55e71ab72c0d7`.
The normal script/default-config hashes are respectively
`8f389d049e6b15029ca7311cd449861f47b7e3381f4083646b812380f07f28c9`
and `0d0e7109df366b0e963add08e218d62afb516218deeb3b5aa9259b821efb569c`;
the extractor hash is `c6a92a81dc5b26f12a2ae2ce0a6de3b3783d22ca0a8cf5d8c01807f34201f197`.
Public files/modules must remain Root-owned, regular and protected. The qualified
Perl executable has two hardlinks, which are required rather than incorrectly
rejected by the one-link policy for private requests/archives. Public-file reads
use each authenticated exact size, with an absolute 32-MiB ceiling; the general
2-MiB private-input/capture limit is unchanged. These observations
do not independently establish every interpreter/stdlib dependency's provenance.

The exact inherited literal `/usr/sbin/dpkg-preconfigure --apt || true` may run
once, after the first transaction guard. Its known failure behavior is preserved;
success through `|| true` is not proof that preconfiguration succeeded. Protocol 3
and InfoFD 0 belong to the guard's unique executable key. The Debconf executable
has a separate, explicitly fixed protocol 1 / InfoFD 0 key: it reads plain archive
filenames on stdin, not protocol-3 metadata. Unknown, duplicate or protocol-drifted
hooks remain unsupported. There is no caller profile selector or approval flag.

The passwd-derived Root home must have **no `.debconfrc` entry**, including a
dangling symlink. Setting `HOME` does not change this lookup. The exact default
Debconf configuration and native package versions/files/module inventory are
rechecked before the first guard releases the qualified next hook. The fixed
candidate has no config/templates members in any of its 32 authenticated archives.
This excludes their package preconfiguration script/template branches, not all
Debconf effects: DB load/save/locks, default `/var/cache/debconf` files and tmp.ci
cleanup/creation remain real operating effects. DB values are neither read nor
exported by this helper. Maintenance/backup/restore qualification remains required.

Each request invocation compiles a native effective APT dump into a new private
`.apt-invocation-*` directory next to the request, mode0700 with mode0600 files.
Native configuration can contain credentials: this directory must never enter
uploaded reports or routine artifact collection. The compiler replaces only the
admitted pre-install list **inside that private file**, guard first then the known
Debconf hook once; it never edits global APT files. A private empty parts directory
and empty main file prevent later native configuration reloading. Sources,
preferences, trust and auth paths still resolve to the reviewed standard locations.
Runtime `Binary` and `CommandLine::AsString` values from apt-config are removed;
nonempty future apt-get/extractor/config binary-specific overrides are rejected.
The snapshot is effective configuration, not proof that an original apt-config
subtree never existed; the resulting common profile is independently checked.

The same inode/hash-bound `APT_CONFIG` is passed in the fixed environment to
simulation, real APT and therefore Debconf's extractor. ENV-only apt-config queries
verify child effective paths, disabled cache filenames, common flags and exact hook
order/protocols before effects; parent CLI flags alone are insufficient. Caller
`PERL5*`, `DEBCONF_*`, `DPKG_ROOT` and other overrides are not inherited.
`Simulate=false` is absent from the common file and appears only on real-install
argv, so the real `--simulate` phase remains read-only. Replaced/mutated private
config, unexpected parts/main contents, or repeated guard invocation holds.

Protocol-3 configuration headers are consumed privately and discarded; they are
never logged. The protocol omits pending-operation sentinel items and cannot
describe every maintainer/trigger effect. The helper additionally requires clean
global dpkg state and empty dpkg updates, but arbitrary direct Root writers are
outside normal APT frontend serialization. Existing maintenance isolation remains
necessary. The exact native hook/cache/ordering behavior needs an authorized
rehearsal; source tests do not qualify installation on the shared host.

A Root-private once lock serializes this request only. A durable `INSTALL_INTENT`
precedes any possible real APT start. Any failure or lost controller thereafter
retains that intent and holds; matching installed versions do not resolve it.
No retry, downgrade, repair, automatic rollback, or purge occurs. A completed
receipt plus exact unchanged full status and all 32 configured package identities
allows a no-effect repeated valid request. An unrelated already configured exact
state returns `ALREADY_CONFIGURED_READONLY`, never operating acceptance. The caller
must not evade a retained intent by minting a new request/path. Install output is
retained privately with a per-stream limit and drained; this helper never kills
active dpkg on an invented install timeout. Intent/logs remain for explicit recovery.
If capture writes, reads, or selector setup fail after spawn, the same original
owner stops logging, drains/discards with bounded memory and waits for the actual
original child terminal state before closing its pipes or returning the error.
Partial log writes are completed. Capture failure remains unresolved; it neither
launches a watcher/replacement child nor retries APT. The retained intent binds the
exact private compiled configuration as well as the request and archive identities.

Check mode fails before installing the helper, creating an intent, or launching
APT. Use the separately reviewed read-only preflight/simulation for preview.
Before any real invocation, require current full inventory and foreign-workload
preservation, approved maintenance/startup handling, consistent private backup,
demonstrated compatible isolated restore, exact 32-package impact review, and
fresh same-cache/native-hook rehearsal. These are operating prerequisites, not
facts asserted by a request. No install invocation is documented as approved here;
package state verification does not enable HTTPS, TLS issuance, runners, or VM tests.

## Dependencies

None.

## Example Playbook

```yaml
---
- name: Configure Incus hosts
  hosts: incus_hosts
  become: true
  roles:
    - role: lit.ubuntu.incus
      vars:
        incus_users:
          - litadm
          - github-runner
        incus_preseed:
          storage_pools:
            - name: default
              driver: dir
        incus_projects:
          - name: development
            config:
              features.images: "false"
        incus_profiles:
          - name: workbench
            project: development
            description: Workbench VM defaults
            config:
              limits.cpu: "4"
            devices:
              root:
                type: disk
                path: /
                pool: default
```

## License

MIT

## Author

Lightning IT

The schema-2 maintenance request requires six original direct inputs and all 32
archives under APT 2.8.4 canonical cache filenames. Epochs are encoded (for
example `incus_1%3a7.6-ubuntu24.04-202611021330_amd64.deb`). Both original
inputs and cache copies are separately hash-, inode- and directory-bound; the
final protocol-3 actions must name only the verified cache paths. No download
or additional package is admitted. Schema-1 requests are rejected.
