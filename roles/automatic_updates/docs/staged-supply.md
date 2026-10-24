# Captured target policy and signed payload supply

These explicit entrypoints support disconnected managed Ubuntu systems without
opening their egress or using the collector's unrelated installed packages.
The cron defaults and ordinary initial-update interface remain unchanged.

1. Run `tasks_from: staged_capture` on the independently admitted target with
   privilege. It captures public package status, automatic-package state, all
   source/preference descriptors and selected effective APT policy into a new
   private directory. It does not read APT auth files or store the full effective
   config, which might contain transport credentials; only its digest is kept.
   An authenticated transfer binds every input to the returned capture SHA256.
2. Select an existing compatible collector and verify its authorization, identity,
   current workload, tools and capacity through the consumer's operating contract.
   Run `tasks_from: staged_acquire` as its unprivileged account. The entrypoint
   independently rechecks identity and refuses existing attempt directories.
3. Acquisition uses only the captured target status, extended state and exact
   preference contents. Its APT state/cache/source/preference/auth/log paths are
   private, host hooks are cleared, signature/date validation stays enabled and
   credentialed sources are rejected. It performs no system APT/package changes.
4. The collector simulates the actual `apt-get upgrade --with-new-pkgs` fallback,
   records an URI plan, checks capacity for download/copy/archive, then downloads
   only. Native architecture and APT version must match the target. Memory is
   bounded and priority lowered; the collector watches free space and its own
   process deadline and can stop only its own isolated child process group.
5. GPGV verifies every InRelease using the admitted local keyring; decompressed
   index hashes/sizes must match its signed SHA256 entries. Every downloaded deb
   must match its planned URI/size and a package/version/architecture/filename/
   SHA256 record in those signed indexes. Package identity is read with dpkg-deb;
   no maintainer scripts are executed. A complete downloaded file set is required.
6. The role returns `bundle.tar.gz`, `request.json` and `receipt.json` through the
   authenticated collector channel. Controller read-back checks bind archive and
   request hashes to the actual acquisition result. Failed attempts/logs remain
   retained; an observer timeout is never permission to restart the acquisition.
7. Run `tasks_from: staged_receive` on the independently admitted target, providing
   the archive digest from that authenticated collector result. It validates the
   exact archive/manifest member set before target writes, checks capacity, and
   stages only ordinary flat files with private root ownership. It never uses
   extractall or archive-provided owners, devices, links or parent paths. The
   target independently verifies its live resolver context, repository signatures,
   decoded index hashes and deb payloads before reporting staged data accepted.
   Reception does not import an APT cache or install packages.

The target identity also governs phased updates. The captured explicit
`APT::Machine-ID` override, when present, is preserved; otherwise the collector
uses the target's actual machine-id. It retains Always/Never-Include-Phased-Updates,
Recommends, Suggests and Default-Release. This follows the
[Ubuntu 24.04 APT preference contract](https://manpages.ubuntu.com/manpages/noble/man5/apt_preferences.5.html).
Ignoring this identity or the target's preferences can choose a different update
set even with identical repository indexes.

## Capture and schema2 binding

`capture.json` uses schema2 and binds target identity/architecture, dpkg status,
keyring, original source file hashes, repository order, and `patch_context`:
preferences, optional extended-state hash, selected policy, full effective-config
digest, native APT version and the explicit upgrade mode. `payload_files` maps
the permitted public inputs to snapshot-relative file names/digests. No raw
private transport configuration is part of the capture or delivered bundle.

`staged_verify` accepts schema2 only when its independent request, manifest and
current live target policy agree. In addition to schema1's metadata checks, each
package has `file`, `target_name`, `package`, `version`, `architecture`, `sha256`,
`bytes`, `list_prefix`, `meta_key` and `repository_filename`. It must occur in the
specified already verified signed index and its actual payload digest must match.
Its result is `SIGNED_APT_METADATA_AND_DEBS_VERIFIED_NO_IMPORT`; this never means
updates were installed or the operating system was accepted.

Capture currently supports active binary Deb822 sources with an explicit admitted
Signed-By keyring. Active legacy sources, source credentials, foreign package
architectures and unsupported source options fail closed rather than disappearing
from the resolver. Existing unused legacy comment files are retained/hash-bound.

## Remaining installation boundary

Acquisition and payload verification do not authorize installation. The current
`staged_transaction` entrypoint is **metadata-only** and explicitly rejects
payload-bearing bundles. A complete patch flow still requires qualified
archive-cache transfer/rollback, retained snapshot lifecycle, the unchanged patch
controls, restart/recovery prerequisites and independent operating-system audit.
Do not replace these with a successful download or reset an acquisition timestamp
to make old metadata appear fresh. Freshness always starts at actual acquisition.

Consumer runbooks own real inventory names, paths, collector authorization and
runtime/change approvals. Reusable role documentation contains no private hosts,
credentials or operating evidence.
