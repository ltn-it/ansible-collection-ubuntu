# lit.ubuntu.github_runner

Install and register one or more isolated GitHub Actions self-hosted runners on Ubuntu.

## Requirements

- Ubuntu target with systemd when `github_runner_manage_service` is enabled.
- Root privileges on the target host.
- A short-lived GitHub runner registration token when registering a new runner
  or replacing an existing registration.

### Scoped Incus identity component (local implementation stage)

`files/incus_lease_issuer/identity.py` contains the signature and current native
assignment verifier for the planned scoped issuer. The ordinary task path does
not install or start an issuer. Explicitly protected instances copy a root-private
verifier library for installation checks; they do not start an admission service.
The verifier requires Python with `cryptography`; the component tests
use the collection's pinned Devtools image and runtime-generated synthetic RSA
keys, without credentials or live GitHub calls.

The server-side entry `verify_github_assignment` obtains JWKS and native metadata
directly from fixed GitHub HTTPS endpoints. It joins the signed `check_run_id`
through the job's exact `check_run_url`, completely reads the signed attempt's
job inventory, and rechecks the job, run and protected Main. Job and check IDs
are separate namespaces. API credentials are sent only to the fixed API origin;
redirects, environment proxies and token-provided key URLs are refused.

Root-controlled policy must bind the actual caller and reusable-workflow
commits, repository/owner IDs, allowed actor IDs, runner registration and isolated
service UID. Supply the exact configured OIDC subject, including any immutable
ID prefix and environment; do not reconstruct a branch-only subject. Conditional
claims such as the reusable-workflow SHA must be present. Unsupported claim
shapes deny; genuine token availability and claim visibility still require
native qualification after reviewed caller/callee permissions are delivered.

Admission additionally requires `required_native_job_name` from the root-owned
immutable cell map. The verifier checks that exact name on the job joined by
the signed check ID and again on its fresh native readback. A matching name on
another job does not supply authority. The standalone identity component can
omit this optional field; that mode cannot bind an admitted matrix cell.
Verified identities also record the canonical digest of the complete Root
identity policy. Admission requires that digest; refresh preserves it, and
context signing rejects a changed repository, actor, subject or cell policy
even when its caller/reusable Git SHAs remain the same.

The pure `verify_current_job` helper accepts root-acquired snapshots for component
tests. The admission bridge never exposes those snapshot parameters to
the job. The production-facing entry accepts no caller-provided run, jobs or
JWKS data. Its reader injection is an internal testing dependency only.

A verified identity is not a lease, certificate, engine grant or operating
handoff. The sibling `ledger.py` provides private durable challenge, replay and
effect records. A new empty store needs explicit initialization. Normal opening
requires its original private lock, initialized-store marker and consistent
snapshot; missing or corrupt state is never silently replaced. Snapshot checksums
detect corruption, not tampering by an actor that already has root privileges.
Archived policy bytes retain their canonical digest and immutable references;
archiving a document does not establish actual custodian acceptance.

Challenges bind the trusted worker's UID, registration, PID/start time and boot
ID. A challenge, token ID and native invocation cannot be reused. Privileged
effect intents are committed before the external executor can act. Interrupted
or unknown outcomes require explicit verified readback, never an automatic retry.
Cleanup targets must match verified creations. Closing a record confirms cleanup
only; a failed test remains failed.

`admission.py` joins these components over an already connected Unix stream
socket. Its Root-only factory takes fixed collector/identity policies, an
existing private ledger, exact Root-owned cell bytes and archived custody digest,
and a fixed deadline. Requests contain one bounded length-prefixed JSON frame
for `challenge`, `admit`, `recover` or `refresh`. They cannot supply worker snapshots,
policy, cell paths, resource limits or a deadline. The collector and Root control
files are reacquired around independent native identity verification.

The default credential route carries an ephemeral job API token only as native
metadata transport, requiring the actual reviewed caller/callee `actions: read`
and `id-token: write` permissions. A separate Root token-file mode is explicit;
it does not presume an installed PAT or App capability. Tokens are excluded from
responses, ledger state and public errors. The bridge returns only a challenge
or lease ID/expiry. A trusted Root caller may restrict the accepted operation;
a mismatch is rejected before control-file, Worker or ledger access. It does not
bind a server socket, validate cell semantics,
sign a TLS context, launch an engine or establish operating acceptance.

`policy_registry.py` loads an exact private Root-owned registry and constructs
only the declared policy types. A bounded selector chooses a predeclared cell;
it supplies no policy fields or admission authority. Each cell has an exact
native job name, sealed configuration digest, existing custody archive and fixed
deadline. Loading checks the registry twice and reads existing policy archives
without initializing or modifying the ledger. Unknown keys, acceptance flags,
aliased cells and undeclared selectors deny. Actual custody acceptance and cell
semantics remain separate requirements.

`registry_rpc.py` reads a bounded selector frame followed by the admission frame
on the same connected Unix socket. It returns exactly one bounded reply and
never retries admission after a partial or failed response. It installs no
listener. Its `recover` operation authenticates a new challenge/token against
the exact existing live lease after a lost reply. It returns that lease ID,
preserves effects and the fixed deadline, and never falls back to new admission.
Unknown effects continue to block ordinary work.

`signed_context.py` signs and independently checks the nonrecursive TLS2 binding
projection and four context-file digests using a provisioned Root-private
Ed25519 key with a pinned public key. It rechecks the live ledger, full verified
identity policy, Worker, fixed deadline, cell/custody and controller/EE/engine
digests. Context files remain Root-owned staging data; a qualified nonroot EE
mount mapping is still required. The primitive creates no key or certificate,
opens no endpoint and grants no engine access. Authorization refresh requires
a newly signed assertion without extending the fixed lease deadline.

`context_publisher.py` prepares and verifies a private staging copy, then
atomically replaces only the live `binding.json`. The four TLS files and live
directory remain unchanged. A digest-only receipt follows verification, fsync
and exact-owned staging cleanup. An uncertain replacement or cleanup raises an
unknown outcome without rollback or retry. The complete Root caller must still
serialize refresh/publication/network renewal and journal intent before effects.

`refresh.py` holds the preparation lock across refresh-only native admission,
a per-authorization publication intent, signed context replacement, independent
readback and network renewal. A previous assertion can authenticate immutable
file integrity only while a separately verified current authorization is live.
Running refresh rechecks the original retained engine manifest and immutable
inputs while allowing output contents to change. It does not extend the hard
lease deadline, retry an unknown effect, install a listener or supply dispatcher
integration.

`engine_policy.py` compiles a sealed Root descriptor into fixed Podman arguments
and an immutable manifest. It preserves the declared nonroot sandbox and maps
Root-owned context files through an explicit private user namespace and idmapped
binds. It executes no command. Actual package/image, namespace, ID-range, cgroup,
mount and deadline qualification remains required at the executor.

`engine_executor.py` contains fixed start/status/cancel paths with durable
process/container identity and a real private mount/user-namespace filesystem
probe before spawning. Unsupported capabilities, idmapped filesystems, image,
ID ranges, cgroup or network state deny execution. Late starts require the full
remaining signed runtime budget; a running cell recheck uses its original
admitted budget. Tracking or stopping an engine never proves a successful test.
Native Podman, cleanup/recovery and the complete delivery path remain unqualified.

`incus_job_client.py` is a standalone unprivileged host authentication client.
It reads a fixed Root-owned socket configuration, verifies the connected Root
peer before sending secrets, obtains a fresh nonce-bound GitHub OIDC token and
sends the ephemeral job API token only to that socket. Its HTTPS path uses the
system trust store without proxies or redirects. Tokens stay in host memory;
there is no EE forwarding or automatic request replay. A lost authenticated
response is an unknown outcome. Installation, a workflow CLI and engine RPC
integration remain open.

`network_fence.py` prepares a private namespace with no initial API grant.
Subsequent grant renewal binds the latest complete ledger authorization to both
a relative timeout and an absolute per-packet deadline. Unknown outcomes retain
intent and deny automatic repetition. Root configuration binds the exact private
network-policy path and hash before preparation effects. This component alone
does not qualify the full Legacy egress, alternate host/guest/API paths, backend
stream termination, durable watchdog or owned namespace removal.

`socket_entry.py` consumes an inherited connected Unix socket on fd0, loads the
exact sealed Root configuration/registry, and preserves its peer into the RPC.
It returns success only after a successful reply was fully delivered. Failure
after RPC handoff never causes a second reply. Installation and socket activation
are still separate integration work.

`incus_admin.py` provides Root-only fixed-target Unix GET operations for issuer
preflight and reconciliation. It checks the actual Root peer and stable socket,
bounds HTTP/JSON replies, and refuses redirects, retries and arbitrary routes.
Server inspection excludes configuration secrets. Its version/extension check
does not replace package provenance or actual restricted-client qualification;
there is no mutating API in this component.

Ordinary new actions need both a live fixed lease deadline and a current verified
identity. Refresh consumes a new worker-bound challenge and token for the exact
same native invocation. It never extends the lease/job deadline. Known owned
cleanup remains possible after expiry or cancellation. The bridge acquires
worker identity through the kernel collector, invokes the independent GitHub
verifier, and mediates these internal ledger calls; job-provided Worker,
Identity, policy or observation JSON is not authority.

The future issuer must still enforce actual cell/resource policy and implement
accepted custody, retention, revocation and recovery with real external effects.
Per-listener isolation, the full remote VM lifecycle and genuine Heavy evidence
remain separate required integration tests. No listener, private store, UID,
privilege or live endpoint is provisioned by this component.

### Required runner provenance before issuer activation

The existing installation tasks are not a trusted producer for the proposed
issuer: they recursively give the runner user ownership of the installation,
and registration currently permits automatic updates. No existing installation
is authorized by adding these Python components.

The standard pinned runner service has the process chain
`systemd MainPID (bash/runsvc.sh) -> bundled node/RunnerService.js ->
Runner.Listener -> Runner.Worker -> step descendants`. MainPID, Worker PID and
socket-peer PID are distinct. A root collector must acquire the real socket
credentials, service properties and stable process identities, then verify both
ancestry and exact service cgroup membership. Matching names or a shared UID
cannot establish that provenance.

The new provenance components currently bind the candidate runner version
`2.338.2` and its bundled `node24` service host. This is separate from the
existing role's legacy installation defaults; these components do not silently
upgrade existing listeners. A no-self-update pilot needs a currently eligible
version and a maintained root-owned update procedure, not an old archive that
merely starts successfully.

A future opt-in producer must use verified fresh package bytes and protect the
complete startup/runtime dependency tree, `.path`, `.env`, service configuration
and ancestors. Merely changing ownership of an existing user-writable tree does
not establish trusted bytes. The stock `svc.sh install` changes ownership of
`runsvc.sh`, so the final trust check must follow service installation and precede
a trusted service start. Registration must persist `--disableupdate`; a root-owned
regular version-update path and its required security/version maintenance must
replace self-update. Existing registration needs an explicit diagnosis and
supported convergence, never an implicit `replace` or re-registration.

`kernel.py` acquires Unix peer credentials and bounded process/boot observations
directly from Linux. `worker.py` compares the fixed lineage using internal
snapshots. `service.py` reads one root-selected local systemd service and checks
its provisioned unit hashes. Empty structured environment-file properties need
a positive typed D-Bus read; missing CLI output is not treated as an empty value.
These functions do not form an admission endpoint.

`installation.py` checks a root-provisioned private manifest against actual
files, directories, hashes and stable filesystem identities. The manifest's
package checksum records provisioner provenance; it is not independent proof of
download authenticity. Startup configuration and code remain immutable. The
stock runner also needs writable `_diag` logs, which must be explicitly separated
as untrusted runtime data; a completely sealed runner directory cannot support
normal nonroot startup. Mutable runtime data must never satisfy code integrity.
The stock npm/corepack links are represented explicitly in the manifest. Each
must remain root-owned under sealed parents and point to a listed, hashed regular
file inside the immutable tree. Absolute targets, escapes, link chains and
runtime-directory targets are refused; links are not silently dereferenced.

`collector.py` joins the actual peer, service, process, mount-view and code
observations. Its .NET JIT exception is limited to Listener/Worker and requires
the observed `doublemapper` object to match a retained kernel file descriptor.
Its sparse virtual size is not resident memory or immutable code evidence.
Effective AppArmor, diagnostics, privilege and static dependency checks remain
required. The collector does not install a handler or issue runtime credentials.

The opt-in producer below stages fresh verified packages and rechecks existing
protected installations. Migration of legacy registrations, future-version and
credential-refresh convergence, effective kernel confinement, complete admission
and a genuine registered-service test remain unqualified. Component fixtures do
not establish listener isolation or operating acceptance. Ordinary existing
runner instances keep their current behavior.

### External disposable worker admission (local source)

`files/ephemeral_worker_admission.py` is a read-only building block for the
external trusted VM controller. It is not installed or started by this role.
A root-controlled policy supplies the approved Main and isolated callee commits,
callee file SHA-256 and an actual runner-group ID from native inventory; no ID
may be inferred from an auction offer or group name.

Before allocation, admission reads native repository, protected branch,
ancestry, workflow, run, job and group data. It requires the exact Main release
App, attempt one, immutable callee reference, current queued/unassigned job,
empty group and sole repository grant. A nonsecret ticket binds that job,
request digest, profile and matrix index. Raw job names are represented only by
a SHA-256 digest, so untrusted template text is not carried into a future
privileged Ansible allocation plan. Revalidation rejects drift before an
external effect. Injected API fixtures in unit tests are not native acceptance.

The per-job routing contract is an additional label
`lit-heavy-<native-run-id>-1-<profile>-<native-matrix-index>`, alongside the fixed
seven worker labels, including the required `ciwkr01` placement label. The
workflow must compute the job-specific affinity from native contexts rather
than caller/matrix text. This affinity is not yet wired into the published
workflow candidate; the controller therefore cannot allocate against it yet.

`files/ephemeral_worker_lease.py` supplies a separate root-private controller
fence. Linux `flock` serializes callers; a mode-0600 active record is atomically
replaced and fsynced before an allocation intent can return. A closed or crashed
process and an expired timestamp do not release that record. Only a claim with
no allocation intent can be explicitly abandoned and archived. After intent,
capacity stays held until native cleanup and runner removal are verified.
There is deliberately no generic forced-release operation.

The uninstalled record format is schema 3. Allocation intent persists the
root-selected machine ID, project, exact image fingerprint and profile digest.
`creation_variables` derives stopped `lit.ubuntu.incus_instance` create-only
inputs from that durable intent; operation and ticket-digest markers enter the
initial allocation request. The prequalified controller-owned profile must
provide the root disk, network, limits and bootstrap. This method itself invokes
no role or native effect and never authorizes resubmission after an unknown
allocation result.

`execute_allocation_once` bridges that intent to the trusted installed create-only
role. Under the same global lock it revalidates the native job and locally
qualifies the machine/profile/image scope, then fsyncs
`ALLOCATION_DISPATCH_INTENT` before invoking the provider exactly once. The
provider receives only derived variables: the absolute local Incus binary,
force-local Root execution, an enabled role, cleared inherited config/devices/
limits and inventory output, and one nonempty-image, stopped VM with its initial
owner markers. Job input cannot select a remote endpoint or executor callback.
The native executor remains a Root controller dependency and must return the
actual integer synchronous exit code; booleans and reconstructed status objects
are not accepted. Callbacks run under the lock and must not re-enter the Store.

A successful provider return is durably recorded as `ALLOCATION_EXECUTED` before
native VM identity readback. If only that readback fails, it may be repeated
without another provider invocation. A lost provider reply, process exit,
nonzero/invalid result or incomplete dispatch keeps capacity held and cannot be
resubmitted or adopted through the ordinary bind method. No timeout releases
capacity. A process-exit test exercises this write-ahead boundary using a
synthetic effect marker; it is not a native VM creation proof. The separate
one-shot start component is described below; registration, TLS/custody, retention
and cleanup remain further lifecycle steps.

`bind_allocation` requires a fresh observation from the trusted native adapter:
machine/project/profile digest, exact stopped VM name/type/profile, base-image
fingerprint, both owner markers and native UUID must match. The first UUID is
persisted; replay with that same UUID is read-only and a replacement UUID is
refused. Binding still holds global capacity and authorizes neither start nor
deletion. Job JSON must never be supplied as a native observation.
Unknown older record schemas fail closed; no automatic state migration runs.

`files/ephemeral_worker_incus.py` supplies the GET-only `Inventory` adapter for
that callback. It reads the root-owned machine ID and socket through checked
parents, verifies the connected Unix peer is root, refuses socket replacement,
and has no TCP/proxy fallback. `Inventory` exposes no mutation API; the separate
`CreateOnly` interface below uses the same checked transport. Native profile name/config/devices
are hashed canonically, excluding changing `used_by` membership; the exact VM
image must be x86_64. The profile is read again after the VM observation to
reject concurrent configuration drift. Returned observations omit cloud-init
and unrelated configuration. The controller's policy must supply the qualified
profile/image digests; reading an existing profile is not qualification.

Unix HTTP fixtures exercise the actual local transport and kernel peer checks,
including refusal of bad responses, links, replaced endpoints and drift. Those
fixtures do not prove a real Incus allocation. Socket I/O has an idle timeout
and a response-size cap; this library is not the whole-operation deadline or
independent cleanup watchdog. Actual controller installation, mutation lifecycle
and cleanup release remain integration work.

The directory must already be root-owned and mode 0700. Symlinks, hard links,
public state files, malformed records and a replaced directory are rejected.
The eventual installer must also qualify a persistent backing filesystem; the
library and its process-crash tests do not prove survival across power loss.
This fence is not a shutdown timer or a deployed controller service.

Admission does not itself claim a global lease, fence host runners, create a
VM, register a runner, validate capacity or egress, retain diagnostics, perform
cleanup, send an Atlas alarm or establish operating acceptance. Those remain
required parts of the controller integration, before runtime delivery.

### Opt-in protected runner producer (source implementation)

Each `github_runner_instances` entry defaults to `protected: false`. Existing
entries retain the legacy installer, version and relative work-directory
interface. An opt-in entry requires its own `user` and matching `group`, absolute
`dir`, external `manifest_path`, root-owned `storage_dir`, and separate absolute
`home` and `work_dir` beneath that storage. It also requires explicit `url`,
`runner_group`, `labels`, `operation_reference`, `storage_reference` and
`custodian_reference`. These nonsecret references are configuration inputs;
their presence does not prove acceptance or custody. `service_state` defaults
to `stopped`; starting a protected listener must be explicit.

An opt-in protected entry can set the boolean `ephemeral: true` to request
stock `--ephemeral` registration. The producer requires the returned `.runner`
settings to persist that flag before publishing the installation or installing
its service. Existing registrations cannot switch lifecycle mode. After an
ephemeral service start has been issued, the journal refuses another start
from a stopped state; an unchanged running service is an idempotent readback.
An uncertain start remains blocked by its write-ahead intent.

For Heavy execution, this entry belongs inside a newly allocated disposable
worker VM. An external trusted controller must authorize the exact workflow
and job, establish VM provenance and isolation, register the fresh runner,
retain required diagnostics, and deregister/destroy its owned resources on
completion or failure. The physical provisioning host must not execute the
job. The `ephemeral` flag and local journal alone do not prove that placement,
one-job server behavior, cleanup, or operating acceptance. This role does not
allocate the VM or implement that external controller. The legacy installer
and the separate expected-ID credential replacement component are not this
fresh ephemeral registration path.

The protected path pins runner `2.338.2` and official architecture-specific
SHA-256 digests for Linux arm64/x64. It extracts a fresh root-private package,
preserves the six stock internal JavaScript symlinks, and passes a fresh
registration token through the private `apply-input` stdin envelope, never shell command arguments. The helper sets the stock Runner token environment only for its configuration subprocess.
Configuration runs in the private root staging tree with the stock
`RUNNER_ALLOW_RUNASROOT` configuration override. The installed service always
uses the dedicated unprivileged account; registration does not run a job.
The service account has no supplementary groups, privileged capabilities or
sudo access. After upstream service installation, which changes `runsvc.sh`
ownership, the producer seals the complete immutable inventory, creates the
explicit service-owned private `_diag`, and verifies the external root manifest.

An inherited, source-hash-named AppArmor profile denies process tracing, with
read-only observation permitted only to unconfined root. A dedicated systemd
drop-in requires that profile, `NoNewPrivileges=yes`, empty capability sets and
`DOTNET_EnableDiagnostics=0`. Only this opt-in profile is loaded; no global
ptrace setting or other runner profile is changed. Effective native profile
rules, startup properties and the full job lifecycle still require qualification
on the actual selected target. A kernel label is not an attestation that loaded
policy bytes equal the source-file digest.

The private `<manifest_path>.transaction` records native-effect intent before
registration or service changes. Lost responses retain staging and journal
state and deny automatic replay; operator reconciliation is required. Repeated
convergence of an already protected listener in the desired state performs no
service mutation. The generated `<manifest_path>.collector.json` records exact
installation, unit, drop-in and profile coordinates; its returned digest binds
its final bytes. It grants no issuer, TLS, Incus or Heavy authority.

A fresh target directory and a new dedicated account are required. Existing
legacy registrations without root manifests and registration-time
`disableUpdate: true` fail before service changes; this role does not stop,
replace, unregister or edit them. The current source admits only the exact
current-version protected package. A preserving migration from the existing
legacy registrations, a future-version update transaction, and stock credential
refresh behavior under the sealed configuration remain explicit open integration
requirements. Do not treat this candidate as a completed registered-runtime or
Heavy handoff. No issuer daemon, lease endpoint or privileged job grant is
installed or enabled by this path.

The internal `registration.py` prepares persistent stock-format RSA parameters
and an expected-ID-only credential replacement with separate durable auth and
replacement intents. It has no Add or retry fallback. Actual native target
fences, the stock CLR key-loader proof and integration with legacy migration
remain required. The stock CLI used by the initial fresh path can retry HTTP
internally; its outer journal alone does not prove a single wire request.

`registration_service.generate()` implements the stock Linux `GenerateScripts`
step for the exact current organization-scoped registration. It requires the
Root-fenced expected target, matching completed settings and the byte-pinned
2.338.2 `systemd.svc.sh.template`. It returns the deterministic service name,
display name and script bytes without invoking `config.sh`, writing files or
changing a service. The migration caller must still retain the old unit fence,
reject an existing destination unit, publish and seal the new installation, and
verify the generated unit before starting it. This component does not bypass the
role's existing rejection of legacy registrations.

### Runtimev2 installation preparation (default off)

`github_runner_runtime_v2_install` defaults to `false`. Opting in installs the
private server package, fixed isolated launcher, both public host clients, sealed
anchor and socket/service definitions. It **never starts, enables, stops or
restarts** a socket/service. An active, enabled, unknown or foreign unit/socket,
unclosed lease, changed existing package, or missing required input fails before
copying. Existing legacy/protected runner paths remain separate. Use the named
`runtime_v2` task entry when preparing only the broker files, rather than applying
the runner lifecycle to unrelated instances.

Required inputs are an existing Root0600 Runtimev2 configuration and its SHA256,
the complete as-built private module SHA256 map, both public-client SHA256 pins,
and an existing dedicated protected-runner socket group. The configuration must
already bind the Root registry, initialized ledger, custody-policy archive,
cell/source/engine descriptors, signing key/public pin, server certificate pin,
collector installation/profile/unit files, private-network/host-fence policies
and bounded storage policy. No real values, credentials, registry, ledger or
operating-acceptance marker are generated by this installation path. Policy
references and hashes bind bytes; they do not establish operating acceptance.

The fixed private launcher runs `/usr/bin/python3 -I -B`, inserts only the sealed
`/usr/local/lib/lit-incus-runtime-v2` package path and consumes the connected Unix
socket on fd0. Public clients are installed together under
`/usr/libexec/lightning-it`; their Root0644 configuration fixes
`/run/lightning-it/incus-runtime-v2/socket` and, in bootstrap mode, the independently
verified public signing pin. No private signing bytes are copied or read by the installer. The Root0600 anchor lives at
`/etc/lit/incus-lease-issuer/runtime-v2-anchor.json`. Unit definitions and tmpfiles
configuration preserve these exact paths. A second identical preparation is
idempotent; replacement of a different existing payload/configuration requires
a separately qualified inactive update procedure and is deliberately refused.

This source unit does not bootstrap a native engine, establish host firewall
baseline, migrate any registered runner, authorize a custodian/window/retention,
activate a watchdog, or qualify service hardening/runtime privileges. Actual
protected-runner/registry producers and all native package, kernel, endpoint,
capacity, secret/credential and accepted operating inputs remain prerequisites
to any later activation. The light contract scenario validates default-off and
missing-input behavior only. The unit tests also exercise a freshly copied
private package through the isolated launcher; neither is a native service or
VM acceptance claim. No executable live activation command is provided here.

### Disabled bootstrap and operating observer preparation

`github_runner_runtime_v2_bootstrap: true` selects an existing sealed bootstrap
configuration instead of a static job registry. It requires
`github_runner_runtime_v2_signing_public_key_hex`, obtained through the independent
public-key handoff. The fixed schema-2 Root anchor binds the bootstrap path and
SHA256. This does not create a job, lease, credential or VM. Runtime intake still
requires actual job authentication and a second fresh native authorization before
lease creation; installation cannot manufacture those proofs.

Before the private endpoint listens, the separate Root maintenance producer may
call `host_api_fence.install_bootstrap_baseline(bootstrap_path, expected_sha256)`.
It derives the host policy from that same sealed bootstrap without constructing
a static registry, lease or signer. Bootstrap and host-policy bindings are
rechecked before the deny-only table effect and after native readback. Existing
tables or intent, unknown and verified journals are never adopted or replayed.
This API neither activates a listener nor admits a job; the existing per-job
grant and withdrawal bindings remain mandatory.

`github_runner_runtime_v2_operating_install: true` additionally requires bootstrap
mode and these explicit inputs, all defaulting to empty values:

- `github_runner_runtime_v2_watchdog_configuration_path` and its `_sha256` pin;
- `github_runner_runtime_v2_mail_configuration_path` and its `_sha256` pin;
- `github_runner_runtime_v2_mail_helper_sha256`, exactly the six as-built pure
  helper filenames checked by the role.

The configurations must already be canonical Root0600 files for the actual
machine and current boot. They must share an existing Root0700 private spool;
the watchdog also needs an existing Root0700 bindings directory. Preparation
installs fixed isolated launchers, sealed anchors, and disabled service/timer
pairs named `lit-incus-operating-watchdog` and `lit-incus-operating-mail`.
Every installation refuses active, enabled or foreign versions of these units
before copying. It never starts, enables, stops or restarts them. Helpers live
under `/usr/local/lib/lightning-it/incus-operating-mail-helper`; no legacy worker
store or legacy admission path is constructed.

The mail readback requires an already prepared local-only Postfix installation
with the owned configuration recognized by `lit.ubuntu.local_mail`. That role is
a separate explicit prerequisite; this installer does not install packages or
replace an unknown mail configuration. The readback checks policy and tools but
sends no mail. Actual submission and independent confirmation in the local root
mailbox remain operating acceptance requirements. A sendmail exit code alone is
insufficient. No external recipient or personal acknowledgement is inferred from
`root@localhost` delivery.

Confirmed event/receipt pairs are archived together in a durable Root-private
record before either active-spool file is removed. This record prevents repeat
submission after interruption or repeated watchdog observations. Historical
confirmations do not consume the 256 pending-event limit; each tick processes
at most 256 records. Replacement staging is separate from the active inventory,
so an interrupted cursor or receipt replacement cannot poison every later tick.
The mailbox fixtures use only private temporary paths, including the unchanged
pure configuration and mailbox readers.

The installation tests use actual Root-owned files and isolated fresh Python
imports; systemd observations in those tests are modeled. They do not prove
native timer activation, local Postfix delivery, kernel isolation or a full
operating drill. Activation commands remain withheld until the complete sealed
policy, native capacity and controller inputs have been qualified together.

### Native job intake and failure custody

Bootstrap policy fixes the supplementary repository and Main-push workflow,
immutable validation controller, eligible native actors, runner identity and
workflow content digest. A verified current job supplies its own read token only
in memory. Public validation source reads are explicitly unauthenticated and
must prove the expected public repository identity; a failed authenticated read
is never retried with weaker credentials. Candidate bytes, Source and controller
Git archives are joined to the same actual run before private sealing.

The first connection can prepare only an immutable private run snapshot and job
configuration. Its `intake-ready` response explicitly reports no lease. A second
connection uses a new nonce, fresh OIDC and native assignment verification;
run/job/check identities must match the sealed configuration before preparation
or signing. The deadline is the earlier of the native job's reviewed deadline
and the original fixed Root lease window. Reusing a configuration cannot reset
that deadline, and the same check run cannot acquire a second lease.

Physical execution leaves destruction pending. Its preliminary evidence keeps
literal destruction `pending`, final eligibility false and actual raw test and
capture outcomes. Execution CLI exit zero is not final quality acceptance. Root
independently downloads the actual uploaded provider ZIP and compares every
member with its retained sanitized export before accepting the upload. A private
verification intent precedes filesystem staging; uncertain partial stages hold
and cannot be replayed. No API bearer value or digest, or signed download URL, is stored.

An independent watchdog observes the **original execution job's** actual native
completion. Only successful execution, complete captured evidence and verified
native upload contents permit immediate Root destruction. Failure, cancellation
or expiry stops the owned VM, withdraws its access, and retains its private data
for four hours measured from that native completion. Jobs cannot waive or extend
custody; any separate operator retention decision is bounded by 24 hours.
Known stopped custody retains the full storage reservation. Unknown cleanup or
unavailable original process proof quarantines it and does not release running
capacity.

The watchdog visits bounded fair pages and retires bindings only after checking
the original sealed configuration and closed Root ledger. It uses the producer's
fixed bindings directory; an empty alternative directory is not supervision.
After an operating cell's actual custody expires, normal finalization preserves
Root-verified diagnostic-only evidence before removing its owned resources and
releasing its reservation. That receipt grants neither business-quality PASS nor
permission to shorten retention.
Completed owned image-delete tasks must actually leave the native operations
map before Root records a new project-delete intent. Foreign tasks, failed tasks
and bounded-wait expiry hold cleanup; unknown writes are never retried.

A distinct authenticated observer job reads the original final state without a
new lease or VM effects. Ordinary final quality requires an EdDSA receipt for the
actual closed cleanup, original execution job and exact uploaded artifact. The
public client verifies the independently installed public pin; the Source
consumer must independently verify its own trusted pin and provider artifact.

An ordinary run can still transfer its already sealed, independently validated
diagnostics when finalization reports a safety-maintenance hold. The exact
original-owner failure-retention safeguard remains required, and unknown native
writes stay unknown without retries. This transfer does not grant final quality
or release capacity. Changed runtime trust, a corrupt archive or a partial
protocol stream must continue to deny delivery.

The three closed operating selectors exercise workload failure, broker
cancellation and client-heartbeat loss with the Root supervisor alive. Root must
observe the owned VM running with the exact UUID, image and devices before
writing its readiness acknowledgement. Expiry reports the actual earlier
Root authorization or lease cutoff; it does not manufacture elapsed time. These
expected negative cases publish operating metadata rather than business quality
PASS. Their reviewed limits are a 900-second lease and 600-second engine budget;
ordinary profile budgets remain unchanged. They are admitted only for the
reviewed first Main transition, not on every subsequent Main push.

Operating EE graph **cache children** may be pruned once after proven stopped
custody, original process/cgroup drain, and preserved raw diagnostics. The original
graph directory inode and all runroot, output, context, descriptors, captured
streams, evidence spools, VM disks, project and copied image remain. This is not
`engine-release`, full cleanup, a reduced reservation, or a retry of an unknown
operation.

Owned tree deletion retains every entry's original path, inode, mount and
deadline checks. It persists each emptied child directory before removing its
name, then persists the root before reporting completion; interrupted or failed
batches remain unknown under the original durable intent. Filesystem checks
cache only the process-local native function symbol, never descriptor results
or observations. The existing cleanup deadline is unchanged.

Root-only capacity policy binds separate owned ext4 project-quota proofs for the
32-GiB dir pool and 17-GiB engine filesystem. Admission keeps a one-GiB pool
reserve and checks eight GiB of cold-engine headroom plus a 512-MiB **preadmission**
floor. The existing whole-filesystem hard cap does not guarantee that free floor
against subsequent workload writes. Retained reservations count in full until
cleanup; native physical use is counted once, without treating project logical
usage as physical credit. Unknown volumes, ownership, writers or accounting
remain holds. These inputs and native behavior must be qualified before enabling
the runtime.

The watchdog and mail sender use separate bounded locks. Failed-cell retention
can generate a truthful local notification; this is distinct from a failed
cleanup alarm. Local delivery requires actual mailbox confirmation and never
implies personal acknowledgement. A busy or unavailable supervisor generates a
hold without bypassing its lock, inventing process exit, or granting cleanup.

### Private runtime engine image preparation

Each fresh admitted lease owns a separate private Podman graphroot and runroot.
Root preparation populates that empty store once with the fixed Devtools image
index for Linux amd64, using TLS verification and one owned Podman invocation.
The command uses options supported by Podman 4.9; its registry transport may
retry reads within the same bounded process deadline. Root never replays the
pull invocation or its journal intent. The exact existing
index/child/config checks run before the context is signed; runtime execution
retains `--pull=never`. No job image URL, credentials or host-global cache is used.
Podman pull, inspection and execution use a canonical `repository@digest`
reference. The controller retains the versioned provenance label with that same
digest; neither the image content nor the admitted controller contract changes.
Image transfer and extraction remain inside the existing private storage quota.
Podman 4.9 limits the complete per-lease runroot to 50 bytes. Use a short path
on the same project quota filesystem so temporary data remains within that quota.
The pull has a 120-second maximum and consumes the original initial-transition,
authorization and lease budgets; the complete engine execution budget must still
remain afterward. Image footprint, transfer time and actual native storage/network
behavior require operating qualification before activation.

Possible partial writes, timeouts or failed image readback retain an unknown
`engine-prepare` effect, with no automatic retry or deletion. Root must reconcile
that store before a later pilot lease may provision another image. Successful
ordinary engine shutdown and cleanup remove only the recorded original private
directory trees; prestart failure does not manufacture an engine-exit receipt.

### Offline Root generation publication

`incus_lease_issuer.generation_publisher.RootGenerationPublisher` is the explicit
Root-only preparation entry. Its `main` accepts exactly two operator arguments:
the absolute Root-private request path and its independently reviewed SHA256.
It does not accept job data, URLs, policy overrides or secrets on stdin/argv.
The request schema is closed: schema `1`, a fresh 32-character lowercase hex
`generation_id`, `expected_anchor_sha256` (null only for first publication),
`acquisition`, `collector`, `registry`, `cells`, `preparation` and `runtime`.
Every configuration reference is `{path, sha256}`; at most two explicit cells
belong to the initial pilot. The acquisition request names exact source and
controller repository IDs/commits, the exact producer run/attempt/workflow and
artifact ID/name/digest/size, a private credential file reference, and finite
archive/tree/file/time bounds. Credential bytes never enter generated records.

Publication requires preexisting Root0700
`/var/lib/lightning-it/incus-runtime-generations`, an empty Root0600
`publisher.lock`, the private fixed anchor parent, an initialized Root Ledger
with the required archived custody policy, valid static cell/engine/platform
files, and the existing inactive socket/service definitions. The library must
already be staged from the exact qualified collection package in a trusted
Root-private directory. These are offline provisioning prerequisites; this
entry does not initialize the Ledger, accept custody, install system packages
or bootstrap its own runtime installation. The runtime installer above consumes
the resulting sealed configuration afterwards. Source/package preparation and
native activation are distinct steps.

The publisher authenticates fixed GitHub API requests and the one permitted
archive redirect. It matches every source/controller archive byte, executable
mode and path against the authenticated Git blob inventory. The three-file
candidate ZIP has exact checksums and a verified Galaxy file manifest; every
packaged collection payload file must match the acquired source tree, and its
version must equal the literal authenticated `galaxy.yml` version. Git executable
flags are preserved as private Root0700 files; other payloads remain Root0600. Dependency
bundles remain inert bytes: confined relative links are validated but never
extracted or executed as Root. The actual protected-provision descriptor is
translated into the registry collector schema, binding the original descriptor
path and digest. Its operation/storage/custodian references remain references,
not evidence of operating acceptance.

The Source archive is not a Git checkout. After authenticating the commit/tree
and checking every archive blob, the publisher derives `source-provenance.json`
inside the sealed candidate tree. This is additional Root metadata, not an
extra accepted ZIP member or a change to the candidate checksum file. It records
the exact Source repository/commit/tree and complete path/mode/size/blob inventory.
The engine descriptor seals its bytes alongside the original candidate inputs.
The schema2 controller checks that complete Source snapshot and uses the same
blob identities for scenario/registry evidence. It does not manufacture Git
objects or claim a successful checkout. An arbitrary job-created record outside
the admitted Root engine mount is not an authenticity or activation grant.

A new private generation contains acquired archives, sealed tree inventories,
cells, registry, preparation/runtime configuration, provenance and an inode/hash
inventory. Actual static validators run without creating an Identity, lease,
TLS credential or engine descriptor. Runtime and cell stream-capture limits
must match before publication. Under the existing preparation lock and
Ledger transaction the publisher rechecks inactive units, exact expected anchor,
immutable inputs and the complete sealed generation, requires every old lease
to be `closed`, and replaces only the fixed anchor with `os.replace` plus parent
`fsync`. Readback uses the same fixed-anchor reader as the runtime. Source,
producer, native caller, reusable workflow and controller SHAs remain distinct
bindings. The real consumer invocation is authenticated later by admission. For the
physical Main receiver, static checks use the sealed cell's positive integer
`github.run_id`, independently of the artifact producer run. Publishing these
Root-selected bytes does not authenticate that consumer or authorize a lease;
native admission must verify the same consumer run before any execution.

The maintenance operator must prevent concurrent privileged unit starts during
this offline operation. Read-only systemd observations are not a transactional
service fence. This entry never starts, enables, stops or reloads a unit. Active
or uncertain units, stale CAS, open/cancelled/unknown leases, source mismatch or
file drift fail closed. Partial generations and all prior generations/spools
remain intact; failures never trigger automatic retry, adoption or deletion.
A failed post-CAS readback can mean the anchor changed: inspect the exact fixed
anchor and retained generation before a further attempt. There is no live
routing of old generations or automatic retention cleanup in this interface.

The credential-free proper-EE regression entry is:

```bash
python3 -I -B -m unittest discover -s tests/unit -p test_github_runner_incus_generation_acquisition.py -v
python3 -I -B -m unittest discover -s tests/unit -p test_github_runner_incus_generation_publisher.py -v
python3 -I -B -m unittest discover -s tests/unit -p test_github_runner_incus_cell_contract.py -v
```

Run these inside the repository's pinned Devtools EE. Root filesystem cases
require its isolated Root test context. These commands qualify component source
and archived fixture provenance; they do not prove live GitHub credential access,
native installation, VM/Heavy behavior, backup/restore or operating acceptance.

### Protected rootless engine client component

`files/rootless_podman_client.py` is the unprivileged CLI for a private rootless
engine. Optional `rootless_engine` on a protected instance selects service
preparation through `files/rootless_engine.py`. Omission preserves the existing
runner behavior. This source candidate still needs native installed-package
qualification; its component tests do not qualify a final worker image.

The selected integration registers a fresh protected ephemeral runner with
`service_state: stopped`, re-verifies the Root-generated installation and unused
registration journal, then prepares a separate same-UID rootless Podman service.
The role leaves the runner stopped. Starting a job requires the subsequent
qualified worker-controller phase. The daemon's namespace setup occurs outside the runner's
`NoNewPrivileges` boundary; the job client stays inside its existing AppArmor,
capability and privilege restrictions. Do not add the runner to a rootful
Docker/Podman socket group or pre-create an account to bypass the protected
registrar's fresh-account rule.

The client reads only `/etc/github-runner-engine/client.json` through sealed
Root-owned ancestors. Its closed schema is `schema: 1`, positive integer `uid`
and `gid`, `socket: /run/lit-runner-engine-<name>/podman.sock`, and
`home: /var/lib/lit-runner-engine/<name>`. Names contain lowercase letters,
digits and hyphens, starting with a letter or digit (maximum 48 characters).
The configuration must be a single-link regular file of at most 4096 bytes,
without group/world write access. No CLI or environment configuration override
is accepted. This fixed configuration is scoped to one dedicated worker VM.

The root-owned installed client is intended to be named `podman` in the runner's
fixed PATH, distinct from its underlying `/usr/bin/podman` binary. It clears the
inherited environment, fixes remote mode and the Unix endpoint, verifies the
current UID/GID and absence of supplementary groups, and checks a real same-UID/GID
Unix peer. Both the runtime directory and socket require private permissions.
It permits the image and container commands used by the managed launcher;
endpoint, connection, namespace, storage and module overrides are denied in
engine options even after a subcommand. For `run`, the client recognizes the
managed launcher's explicit run-option vocabulary and stops parsing at the image,
matching Podman's parser. Workload arguments such as `python3 -c` remain intact;
unknown run options are refused. It does not police container workload arguments
or grant privilege beyond the runner's own rootless daemon. The workload sandbox
and network policy remain the responsibility of the managed launcher and worker
controller. Same-user socket replacement is not a Root-attested service proof.

Select `rootless_engine: {subuid_start: 100000, subgid_start: 100000}` only on a
new dedicated worker VM with otherwise valid protected-instance configuration,
`ephemeral: true`, `service_state: stopped`, and a lowercase name containing only
letters, digits and hyphens (maximum 48 characters). Each start reserves exactly
65536 subordinate IDs. The caller must select ranges that overlap neither other
allocations nor actual host accounts. Existing exact mappings are retained;
conflicting, duplicate or malformed mappings are refused. The producer uses
`usermod` and its native account-file locks; it does not replace mapping files.
The selected path installs Ubuntu's `podman`, `uidmap`, `slirp4netns` and
`fuse-overlayfs` prerequisites. Exact OS/toolchain identity must be bound by the
qualified immutable worker image before operational use.

A Root-private journal under `/var/lib/github-runner-engine` records intent
before allocation, file or start effects. A clean repetition verifies the exact
bundle and the same still-live native invocation without another start. Missing,
incomplete, drifted or expired state holds for explicit reconciliation; it never
repairs, restarts, reallocates or unregisters automatically. Keep the VM and
journal available when reconciling unknown outcomes. This producer has no deletion
or retention authority.

The service `lit-runner-engine-<name>.service` is not enabled at boot and has no automatic restart
and a two-hour maximum lifetime, with `MemoryMax=8G`, `TasksMax=256`, private
runtime/home paths, and a Unix socket only. Podman uses cgroupfs and file events
without a user D-Bus session. Root verifies the loaded unit, PID/executable,
UID/GID and Unix peer before recording completion. Podman's re-executed API
child must have an unchanged PID/start-time chain to the exact native main PID,
the same dedicated identity and executable, and that service's cgroup. A short readiness observation
polls that same native invocation; it never reissues start. Runner setup records
the fixed client PATH in its existing sealed confinement drop-in and retains
`NoNewPrivileges=yes`, empty capabilities and AppArmor for the job.

Native installed-package provisioning, kernel/service identity and actual
managed-launcher integration remain required qualifications before enabling a
worker. Component fixtures do not prove a Heavy run, TLS/custodian handoff or
operating acceptance.

## Variables

See `defaults/main.yml` for the full interface. Key variables:

- `github_runner_version` (string, default: `"2.335.1"`): Pinned GitHub runner version.
- `github_runner_url` (string, default: `""`): Repository or organization URL for runner registration.
- `github_runner_runner_group` (string, default: `""`): Optional organization runner group.
- `github_runner_registration_token` (string, default: `""`): Short-lived registration token.
- `github_runner_remove_token` (string, default: `""`): Short-lived runner removal token.
- `github_runner_name` (string, default: inventory host short name): Runner name in GitHub.
- `github_runner_labels` (list): Labels passed to `config.sh`.
- `github_runner_user_groups_extra` (list, default: `[]`): Extra groups for the runner user.
- `github_runner_replace` (bool, default: `false`): Remove and recreate an existing runner registration.
- `github_runner_manage_service` (bool, default: `true`): Install and manage the systemd service.
- `github_runner_instances` (list): Runner instances. Ordinary mappings require unique `name`, `dir`, and relative
  `work_dir` values, plus `labels`; protected mappings use the dedicated absolute paths described above.
  Ordinary optional per-instance keys are `runner_group`, `registration_token`, `remove_token`,
  `replace`, `state`, `service_state`, `external_service_name`, and `external_service_unit_path`. The external service
  keys allow an absent-state migration to stop, disable, and remove a pre-existing systemd unit before deleting its
  registration and installation tree. Its default maps the legacy single-runner variables, preserving backward
  compatibility.

Set an instance to `state: absent` with a fresh remove token to unregister it, uninstall its service, and remove its
installation directory. Set `replace: true` only for the instance that must be re-registered and provide both fresh
token types. Runner services are
installed from each instance directory, enabled when `service_state: started`, and therefore survive reboots.

## Dependencies

None.

## Example Playbook

```yaml
---
- name: Configure GitHub Actions runner
  hosts: github_runners
  become: true
  vars:
    incus_enabled: true
    github_runner_user_groups_extra: "{{ incus_user_groups | default(['incus-admin', 'kvm']) }}"
    github_runner_instances:
      - name: incus-runner-01
        dir: /opt/actions-runner-01
        work_dir: _work-01
        labels: [self-hosted, linux, x64, incus, nested-virt]
        registration_token: "{{ lookup('ansible.builtin.env', 'GITHUB_RUNNER_TOKEN') }}"
        state: present
        service_state: started
      - name: incus-runner-02
        dir: /opt/actions-runner-02
        work_dir: _work-02
        labels: [self-hosted, linux, x64, incus, nested-virt]
        registration_token: "{{ lookup('ansible.builtin.env', 'GITHUB_RUNNER_TOKEN') }}"
        state: present
        service_state: started
  roles:
    - role: lit.ubuntu.incus
    - role: lit.ubuntu.github_runner
      vars:
        github_runner_url: "https://github.com/example-org/example-repo"
```

## License

MIT

## Author

Lightning IT


### Root-local stopped-VM creation provider (unpublished component)

`ephemeral_worker_incus.CreateOnly.allocate(store, operation, now=..., revalidate=...)`
connects the private schema3 lease directly to the local Incus Unix API. Root
controller code selects the socket and machine-id paths; job inputs and response
URLs cannot select an endpoint. The inherited `Inventory` interface remains
read-only. The provider checks the exact machine/profile/cached-image binding,
requires an empty dedicated project, rechecks the template, then submits exactly
one stopped, non-ephemeral VM with the initial operation/ticket markers. It
accepts completion only from the exact task/resource-scoped native operation and
then uses the existing native UUID observation. It never starts or deletes a VM.

A lost reply, native failure, timeout, foreign operation or malformed receipt
retains the durable dispatch intent and capacity. A second allocation call does
not replay POST or adopt the uncertain VM. Other Root administrators remain
outside this controller's flock; project capacity, physical runner fencing,
qualified image/bootstrap, ephemeral registration, TLS/custody, terminal cleanup
and retention remain deployment prerequisites and separate unfinished steps.

The installed-package Unix HTTP tests exercise real local sockets, Root peer
credentials and the durable Store using explicit daemon response fixtures. They
prove protocol/failure behavior, not real Incus/KVM creation or Heavy acceptance.
API reference: Incus v6.0.0 `cmd/incusd/instances_post.go` and
`internal/server/operations/{response,operations}.go` in the upstream repository.


### Root-local one-shot VM start (unpublished component)

`ephemeral_worker_incus.StartOnly.start(store, operation, now=..., revalidate=...)`
connects the allocated UUID to `Store.execute_start_once`. Only the previously
bound stopped VM can be started: native job revalidation, exact local machine,
image/profile scope and UUID readback precede a durable `START_DISPATCH_INTENT`.
The provider rechecks that same stopped UUID immediately before its single PUT.
Its closed state request is `action=start`, `timeout=0`, `force=false`,
`stateful=false`; job arguments cannot choose an action, endpoint or callback.
Monotonic elapsed time consumes the remaining lease window during native reads
and persistence, with a final conservative deadline check before PUT.

The same exact native task/resource completion checks serve create and start.
Only actual integer exit0 is persisted as `START_EXECUTED`; a matching Running
UUID then becomes `STARTED`. `bind_started` can recover readback after proven
completion without another start. Unknown replies, process exit, false success
objects or nonzero results retain the dispatch intent and global capacity.
A running VM alone never proves completion of an uncertain start. Schema3 keeps
its existing fields and extends the phase set; older readers refuse unknown
phases, and older malformed/schema records are neither repaired nor migrated.

`STARTED` proves VM state only. It does not register a runner, establish agent or
service readiness, publish TLS/custody, extend a lease, stop/delete a VM or
release capacity. Terminal supervision and actual end-to-end controller
installation remain open. Root/nonroot tests include real Unix HTTP with explicit
daemon replies, process exit, lost replies, deadline exhaustion and UUID drift;
those component tests do not substitute for the real packaged start provider
and operating acceptance. The separately recorded real Incus6/KVM/agent/fsync
boot fixture used trusted native CLI and is not proof that StartOnly is deployed.


### Root-local graceful stop and quiescence (unpublished component)

`ephemeral_worker_incus.StopOnly.stop(store, operation)` addresses only the native
UUID already bound by the Root controller. It uses native metadata plus runtime
state/PID readback. A Running VM receives exactly one `action=stop`, `timeout=60`,
`force=false`, `stateful=false` request after durable `STOP_DISPATCH_INTENT` under
the same global lock. Completed provider return is persisted as `STOP_EXECUTED`;
only the matching Stopped UUID with an actual integer PID0 becomes `STOPPED`.
An already stopped owned VM needs no mutation. Cleanup remains allowed after
job cancellation/expiry; it does not depend on a still-queued job.

A failed/lost result, process exit, UUID drift or inconsistent PID/status keeps
capacity held. The provider never force-stops, retries, deletes or releases a
lease. `bind_stopped` may read back that exact already-bound UUID after uncertain
stop completion. Stopped/PID0 prove quiescence, not a successful native operation
receipt, runner removal, cleared pending operations or storage cleanup. Even a
confirmed `STOPPED` record still prevents the next worker.

Actual native testing found that the Incus agent may be reachable before D-Bus
and `systemd-logind` are active. ACPI shutdown sent at that point failed to stop
the test VM; after both services were confirmed active, the same VM stopped
normally through the native Incus operation in 1.85 seconds. This is evidence of
a readiness precondition, not proof of every failure cause. Worker image/bootstrap
qualification must establish the guest's power-button handler readiness before
publishing worker readiness; a successful `uname` alone is insufficient. The
production image/bootstrap readiness gate, watchdog, cleanup/retention, actual
Wunderbox Atlas alarm and full operating acceptance remain unfinished.


### Root-local VM removal (unpublished component)

`ephemeral_worker_incus.RemoveOnly.remove(store, operation, authorize=...)`
removes only the exact UUID bound by a `STOPPED` record. A trusted Root controller
authorizer must independently verify the retention decision/expiry and preserved
private evidence. The gate is checked under the durable global fence and again
immediately before deletion. No job-supplied approval is accepted as a controller
gate. The separate Retention component below implements the time/identity gate; live
evidence and identity-verified approval backends remain integration requirements.

The provider verifies native Stopped/PID0, exact scope, owner markers, image,
profile and UUID, and conservatively refuses any nonterminal project operation.
It persists `DELETE_DISPATCH_INTENT` before issuing one DELETE without force or
volume-removal options. Exact native operation completion is persisted as
`DELETE_EXECUTED`; successful scoped instance inventory and operation readback
must then prove absence before `REMOVED`. A failed inventory is never absence.
A lost reply/process exit leaves capacity held and cannot replay deletion;
`bind_removed` permits read-only absence reconciliation after a deletion intent.
It does not claim a successful operation receipt after an uncertain reply.

`REMOVED` does not free capacity or prove runner deregistration, TLS revocation,
snapshot/custom-volume cleanup, evidence preservation or alarm delivery. Those
operating gates and the release transition remain required before another worker
can be admitted. An unrelated administrator remains outside this local fence.


### Terminal-job retention gate (unpublished component)

`ephemeral_worker_retention.Retention` stores a Root-owned mode0600 receipt in
its existing mode0700 worker Store. `seal_terminal` uses the trusted controller's
read-only GitHub client to check the exact admitted repository, Main run/attempt,
caller/callee sources, request and terminal cell identity. Later Main/default
branch movement or other cells still running does not prevent cleanup. A queued
or running job, foreign identity, rerun, unknown conclusion or future completion
time cannot produce a receipt. Re-sealing is idempotent; it never rewrites a
previously sealed conclusion or completion timestamp.

Successful cells need no additional retention delay. Every other recognized
conclusion retains the VM until four hours after the native job completion time.
`extend` requires a trusted Root approval backend to confirm the exact operation,
VM UUID, configured custodian reference, decision reference and requested expiry.
It can only extend a stopped failed cell and never beyond 24 hours after its
completion. Passing a custodian reference alone is not identity verification or
a real operating approval. The live approval backend is not supplied here.

`authorize` is intended as RemoveOnly's callback inside the same global fence.
It validates the exact sidecar/ticket/VM, elapsed retention, unchanged lease and a
fresh positive response from the trusted private-evidence verifier. It rechecks
at the final deletion boundary; only the expected STOPPED-to-dispatch phase
change is allowed. Directory persistence is confirmed before returning. Missing,
malformed, public, linked or identity-drifted receipts, clock rollback, missing
evidence and failed approval/persistence keep capacity held. No deletion,
watchdog, runner/TLS cleanup, alarm delivery or capacity release is performed by
this component. Controller UTC time is a trusted dependency, never job input.

The component tests use explicit GitHub, evidence and approval fixtures and
synthetic clock values. They prove filesystem/fence behavior and time boundaries,
not a live GitHub terminal observation, actual four-hour waiting period, private
backup verification or custodian acceptance. The controller service, production
backends and complete operating integration remain unfinished.


### Allocation dispatch deadline

Create and start both charge native revalidation, profile/image inventory and
local durable-intent persistence against the remaining admission window using
monotonic elapsed time. Allocation checks before and after intent persistence;
CreateOnly checks again immediately before POST, with a conservative one-second
margin. Slow preflight or fsync cannot submit a new VM after the admission
window. A provider operation already submitted within the window may complete
later; that does not authorize starting an expired worker. Stop/retention/cleanup
remain available after expiry. A persisted uncertain dispatch is never reset or
replayed merely because no resource was observed.


### Root watchdog and pending alarm spool (unpublished component)

`ephemeral_worker_watchdog.Watchdog.tick(now=...)` supervises the durable Store
with trusted Root StopOnly/RemoveOnly dependencies. At expiry it quiesces only an
already bound VM through the one-shot graceful stop. Uncertain allocation never
adopts a VM. Stop/deletion intents are reconciled read-only through exact native
UUID/PID or successful scoped absence observations; requests are never replayed.
Stopped/removed resources remain held. A restarted retained VM, unavailable
observation, inconsistent state or clock rollback produces a pending alarm.
Only a still-CLAIMED lease can use the existing abandon-before-effect transition;
it has no VM identity/plan or dispatched native effect. No later phase is freed.

The Root-private `alarm-<event-id>.json` spool uses its own nonblocking flock,
independent of the worker lock. A genuinely busy controller therefore cannot
prevent preserving an expiry alarm. Event IDs bind the closed event kind,
operation, phase, VM UUID and ticket digest. Repeated identical events preserve
the first receipt byte-for-byte. The spool contains no raw exception, state body,
job name, credentials or API payload. All events have `delivery=pending`; neither
a successful local write nor later native recovery acknowledges external alarm
delivery. Corrupt/public/linked alarms are held, never repaired or overwritten;
failed persistence propagates failure instead of claiming an event was saved.

`ephemeral_worker_watchdog_entry.py` provides a Root-only one-tick entry under
Python `-I -B`, taking only `--state-directory`. It validates its Root-owned module
bundle before adding that explicit import directory. Native providers are lazy:
an empty or pre-effect Store can be checked while Incus is unavailable. Healthy,
busy-before-expiry or independently proven held states return zero; an alarm
returns nonzero and `alarm_delivered=false`. Other failures emit only a closed
state and exception class, never the exception payload. This is not a
job-facing service or a new authentication capability.

Tests exercise the real filesystem, a second process holding the actual worker
flock, lost native replies, read-only recovery, clock/UUID drift, corruption and
persistence failure. Native effects are explicit fixtures; standalone CLI tests
run from a separately copied Root-owned bundle in an isolated Linux consumer.
The entry and independent systemd scheduler have passed the isolated native
fixture drill described below. Native VM hard expiry, real alarm
receiver/recipient/readback, terminal/evidence integration and complete resource
release remain required before operating acceptance. The spool is not an Atlas
alarm, an independent host-down check or proof of custodian notification.


### Opt-in watchdog installation (unpublished, isolated native fixture verified)

Use the dedicated `lit.ubuntu.github_runner` entry
`tasks_from: ephemeral_worker_watchdog` for controller-only preparation. It does
not run the legacy runner package/user/registration tasks. The full role includes
this entry only when installation or activation is explicitly requested.
`github_runner_ephemeral_watchdog_install` and
`github_runner_ephemeral_watchdog_activate` both default to `false`. Preparation
alone never starts, stops or disables an existing timer. Activation requires both
flags true; it enables/starts only the named watchdog timer.

The caller must supply the trusted target `machine_id`, fresh `boot_id` and an
exact as-built SHA256 map for the five admission/lease/Incus/watchdog/entry Python
modules. Names use the `github_runner_ephemeral_watchdog_` variable prefix.
The installer checks selected collection bytes, then runs a read-only Root
preflight before effects. Target Python >=3.11 and systemd are required. Default
program/state directories are respectively
`/usr/local/lib/lit-github-runner-ephemeral-worker` and
`/var/lib/lightning-it/github-runner-ephemeral-worker`; both are Root-private0700.
Only private descendants of the declared standard prefixes are supported.
Existing symlinks, writable parents, foreign ownership, unexpected program files,
module/unit hash drift or units with missing program/state prevent installation.
Active/unknown lease records are never initialized, rewritten or removed.

The oneshot service runs `/usr/bin/python3 -I -B` as Root with empty capabilities,
no privilege gain, a read-only system, private home/tmp/devices/network, AF_UNIX
only, bounded memory/CPU/tasks and a 170-second start limit. Only the private state
is writable. It retains privileged native Incus authority through the local Root
Unix socket; the restrictions do not turn it into an unprivileged job service.
The timer runs about every30seconds. Definition changes trigger daemon reload;
unchanged installed bytes and unit definitions are intended to be idempotent.
The isolated scheduler/native VM drill below proves the tested fixture behavior;
production operating acceptance remains separate.
This timer/service timeout is not a kernel-enforced runtime limit on the VM.

All newly created disposable VMs explicitly set `boot.autostart=false`; the
native observation/provenance check requires that exact value before start and
later effects. Missing/enabled autostart on an older VM is not silently repaired
or adopted. Previously recorded native proofs without this property do not
qualify the changed provenance contract.

Tests execute the real Ansible opt-in, source-pin and pre-effect guards. The
isolated native follow-up additionally verified installation and activation from
a fresh collection consumer, unchanged second apply (`changed=0`), actual unit
hardening and private module integrity. An actual four-minute VM lease expired:
the timer issued one completed native Stop operation, Stopped/PID0 was observed
26 seconds after deadline, and the next tick was read-only. The VM explicitly
reported `boot.autostart=false`. This measured fixture result is not an SLA or
a host-reboot behavior test. The new fixture VM was then removed, its test timer
disabled and the outer fixture normally shut down with a clean QCOW check.
The older held failure fixture was preserved unchanged. No new default runner
migration, Source job interruption, alarm receiver or release is implied.


Native installation uses the same dedicated role entry and explicit target/boot
identities plus as-built module pins as the negative tests. A syntax error found
by the first actual guard execution stopped before any writes. The guard was
fixed in source, and its regression now executes the script and parses its actual
stdout JSON rather than matching source text echoed in Ansible argv. This is
why a green negative case alone is not positive installation evidence.

The native fixture package was `lit-ubuntu-1.17.0.tar.gz` with SHA256
`b1fc9bd59c7d3f710a9b1bca7cb67f1d78ce753306f7e4bef9ee09def406d54a`.
It was privately built/installed for local integration, not published. Subsequent
documentation-only packaging must preserve all tested implementation/task/unit
bytes and record its different archive checksum; it is not a new native code test.

### Authenticated alarm ingestion building block (unpublished)

`files/ephemeral_worker_alarm.py` adds an explicitly constructed Root-only
`Receiver` and `Forwarder`. It is not installed or activated by the watchdog
opt-in above. A future separate caller must supervise its lifetime, select
existing pending event IDs, bound backlog/disk use and refresh unresolved alerts.
No endpoint, notification address, client identity or credential is supplied by
default. Job inputs must never construct these trusted controller objects.

The receiver connects only to its configured numeric IP and port, verifies the
configured TLS hostname with its explicit CA and presents a scoped client
certificate. All three PEM files must be Root-owned, single-link regular files,
mode `0400` or `0600`, below trusted Root directories. OpenSSL consumes open file
descriptors; the helper does not export credential bytes. There is no DNS lookup,
proxy-environment interpretation, redirect, plaintext option or implicit retry.
The two fixed Alertmanager v2 calls share a ten-second request budget and bounded
response body. A separate service/process deadline is still required, including
for slow HTTP headers. Rotation constructs a new receiver from the managed files.

One call validates the immutable Root-private alarm, posts a firing alert, then
reads it back by event ID. Stable labels include the native source machine ID,
so unbound state-error events on different machines do not collide. Readback must
match exact labels, annotations and start time, cover the refreshed expiry and
show an active, unsilenced/uninhibited/unmuted alert assigned to the configured
receiver name. A rejected POST, lost reply, wrong certificate, route mismatch or
ambiguous readback produces no new ingestion receipt. Repeating an identified
alarm refreshes the same labels; it never retries any VM operation.

The separate Root-private atomic receipt records ingestion only, with
`notification_delivered=false` and `capacity_released=false`. It never rewrites
the pending event or active worker lease. The forwarder has its own nonblocking
lock, so network delays do not hold the worker or watchdog-alarm locks. Corrupt
receipts and source-clock/machine drift fail closed. Receiver ingestion is not
proof that a notification integration exists or that a custodian received it.

Alert expiry after a failed refresh is **not** safe incident resolution. A
separate external forwarder/host-down check, explicit resolution lifecycle,
bounded spool scheduling, credential handoff, actual Alertmanager-image test and
live receiver/recipient acceptance remain required. Local tests use real Linux
Root file controls and real mutual TLS sockets with a synthetic protocol server;
that server is not the Atlas service or an actual recipient. No live deployment,
message to a third party or worker-capacity release is part of these tests.

A separate clean-package component integration also ran the actual pinned
Alertmanager `v0.34.1` image, with no published ports and a dedicated network-none
namespace shared only with the isolated consumer. The installed forwarder used
real mTLS through a synthetic loopback proxy, read back the active configured
route and refreshed the same alert. Alertmanager delivered one firing webhook
to a local capture sink. The pending event and worker lease stayed unchanged;
both owned containers were removed. The image ran as Linux arm64 in this API
test; it does not qualify the x86 worker kernel or the actual Wunderbox target.
The proxy and capture sink are fixtures, not the production TLS gateway or an
operator notification channel. Live endpoint/custody, outage coverage and human
recipient acceptance remain open.


### Local Root mail pilot building block (unpublished)

`files/ephemeral_worker_local_mail.py` consumes existing immutable pending alarm
files through a Root `Store`. Its only recipient is `root@localhost`. It requires
the configuration sealed by `lit.ubuntu.local_mail`; it does not install an MTA,
adopt existing configuration or configure aliases or forwarding. The caller
must provide an independent process deadline and scheduling; neither is installed
or enabled by this library.

Before invoking the fixed sendmail interface it durably stores a dispatch intent.
It confirms delivery only by matching the unique message identity and exact body
in the bounded local Root mailbox. A successful submission exit alone does not
confirm delivery. After an interrupted, rejected or uncertain attempt, later calls
only reconcile that identity against the mailbox and never automatically submit
again. This may require operator reconciliation when intent was persisted but no
message was accepted; it deliberately does not turn ambiguity into duplicate mail.
A removed or oversized mailbox, ownership drift and malformed state remain held.

Local confirmation never modifies the pending alarm or active worker record,
releases capacity, acknowledges a person or resolves an incident. A full/unreadable
Root mailbox and host outage need a separate operating response. Fresh installed
package tests cover Root state/mailbox files and failure handling with a synthetic
submission fixture. A separate clean-package native Ubuntu 24.04 x86/KVM test
confirmed actual Postfix Root delivery, delayed delivery while the real instance
was stopped, reconciliation after restart without resubmission, and unchanged
pending events. The complete configuration reapply changed nothing. Native
mailbox-limit rejection kept the alarm and dispatch intent unconfirmed and
preserved; the synthetic mailbox was restored afterward. These library component proofs alone do not establish live rollout. The separate
opt-in scheduler and its isolated native qualification are described below.


### Independent local Root mail installation (opt-in candidate)

Use `tasks_from: ephemeral_worker_local_mail` explicitly. The default
`github_runner_ephemeral_local_mail_install: false` prepares nothing, and
`github_runner_ephemeral_local_mail_activate: false` starts nothing. Activation
requires installation. The installer consumes an already prepared, owned
`lit.ubuntu.local_mail` configuration; it never installs Postfix or adopts a
foreign mail configuration.

Supply the exact seven-file `github_runner_ephemeral_local_mail_module_sha256`
inventory from the selected collection package. Target identity and the shared
controller Store use the existing `github_runner_ephemeral_watchdog_machine_id`,
`github_runner_ephemeral_watchdog_boot_id` and
`github_runner_ephemeral_watchdog_state_directory` inputs. The separate
`github_runner_ephemeral_local_mail_program_directory` defaults to
`/usr/local/lib/lit-github-runner-local-mail`. Existing modules, units and target
identities are checked before writes; configuration drift is held. Existing
worker records and pending events are never reset or adopted.

The independent timer requests one bounded tick every 30 seconds. A tick handles
at most one unconfirmed event, with a durable rotating cursor to prevent an
uncertain earlier attempt from starving later events. The spool scan is bounded
to 256 alarm files and 1,024 total entries. Valid historical confirmations are
skipped even after an operator archives the mailbox; they never cause resending.
Confirmation remains local delivery, not personal acknowledgment or resolution.

The service is Root with the prepared Postfix queue group, no added capabilities,
no new privileges, no IP networking, a read-only system and narrowly writable
controller state and Postfix maildrop. The process tree has a 20-second execution
limit. A clean-package native Ubuntu 24.04 x86/KVM run qualified these restrictions:
the real watchdog timer generated an alarm from a synthetic future claim, the
separate mail timer confirmed Root mailbox delivery, and the completed next tick
performed no resubmission. The pending alarm and active controller record stayed
unchanged. A complete reapply changed nothing. Both own timers were disabled and
stopped before the owned fixture VM was removed. This is isolated component
qualification, not live CI rollout, actual GitHub-job acceptance, native hard VM
expiry or personal acknowledgment.

```yaml
- name: Preserve the disabled independent local mail default
  hosts: controllers
  gather_facts: false
  tasks:
    - name: Load local sender installer without effects
      ansible.builtin.include_role:
        name: lit.ubuntu.github_runner
        tasks_from: ephemeral_worker_local_mail
      vars:
        github_runner_ephemeral_local_mail_install: false
        github_runner_ephemeral_local_mail_activate: false
```


### Bound fresh-guest bootstrap prerequisites (unpublished)

When `expected_guest_uuid` is supplied, the role reattests the actual DMI UUID
and nonzero machine ID on every invocation, including existing registrations.
The protected producer independently reattests identity before inspection or
service effects and records the UUID and operation reference in every intent
and completion record. A copied installation, missing binding, changed operation
or removed binding is rejected; existing physical registrations without this
optional binding retain their previous contract. This does not issue a lease or
prove GitHub registration, job affinity or controller admission.

A new ephemeral VM instance may supply `expected_guest_uuid` from the trusted
controller's native allocation, never from a job. Before any new protected
registration effects, `protected_instance` then runs the packaged read-only
`ephemeral_worker_bootstrap_readiness.py` helper through the already bound agent
connection. Existing proven registrations follow their existing manifest
verification; this option does not adopt or rewrite an old installation.

The helper compares the guest DMI UUID, checks a nonzero machine identity,
completed cloud-final state, locked local login passwords and bounded SSH login
policy/credential paths. Conditional or external SSH configuration is rejected
for separate qualification. An existing runner directory is not silently reused.
Known credential file contents are not returned, and rejection never repairs the
guest. This is a bounded prerequisite inspection, not a global secret scan or
proof of image provenance. It grants neither registration nor operating authority.

The actual image/profile digest, live lease, caller/job admission, egress and
later protected registration remain controller requirements. Fresh installed
package tests cover real private filesystem fixtures and the actual role's
pre-effect rejection. On the selected clean Ubuntu 24.04 x86/KVM image, native
inspection passed with no OpenSSH server installed; it neither required nor
installed one. Wrong VM identity and a synthetic stale SSH marker were denied,
the marker was restored, and readiness was unchanged afterward. The actual role
then stopped at its missing-token boundary without registration effects.

This native evidence covers the selected agent-only base image. The installed
OpenSSH policy collector branch still needs its own native qualification if such
an image is selected. Final image/runtime readiness and actual ephemeral
registration remain separate open requirements.


### Controller-owned stopped registration (unpublished)

`ephemeral_worker_registration.Registration` joins the existing Root-only lease
Store fence to protected runner registration. It admits only the live `STARTED`
lease, revalidates the native queued job and checks the native VM UUID, image,
profile, operation and running PID before dispatch. The closed role variables
select x64, the restricted runner group, fixed labels plus the ticket affinity,
a dedicated operation-derived account/storage, `ephemeral: true` and a stopped
service. Paths, labels and UUID are not supplied by the job. Sub-ID ranges and
the custodian reference are trusted controller policy.

The trusted native executor must run the installed `lit.ubuntu.github_runner`
role through the bound Incus agent, inject a fresh one-use registration token
privately and return the actual synchronous exit status. The controller records
`DISPATCH_INTENT` before invoking it. Nonzero, boolean, lost or timed-out results
are held for explicit reconciliation and never retried. Completion requires
both `protected_provision.py registration-proof` from that guest and current
GitHub organization-runner/group readbacks with the exact runner ID, name,
labels and restricted repository/workflow grant. The proof action independently
verifies the sealed installation, VM/operation binding, confinement and an unused
stopped service. Journals contain only nonsecret identity/proof data.

This component does not implement the native executor/token adapter, grant a
lease, start a runner, establish actual job assignment, release capacity or
perform cleanup. The global lease remains `STARTED` for independent watchdog
supervision. Native combined registration and the complete Story integration
remain mandatory before delivery; the public component tests use explicit native
transport doubles. API readback follows the GitHub REST runner and runner-group
contracts: https://docs.github.com/en/rest/actions/self-hosted-runners and
https://docs.github.com/en/rest/actions/self-hosted-runner-groups .


### Validation Main identity on an existing physical runner (unpublished)

The identity verifier distinguishes the exact Validation Main release-App
`workflow_dispatch` from the original human Main `push` contract. This is derived
only from the complete trusted Root policy tuple: Validation repository/owner
IDs, exact caller and isolated callee paths, sole release-App actor ID, protected
pilot-environment subject and an explicit native cell job name. There is no
request-controlled mode flag or additional runner registration. Existing legacy
policy serialization and policy digests remain unchanged.

The receiver path requires the original release-App bot as both native actor and
triggering actor, attempt one, protected Main, immutable caller/callee sources,
valid signed OIDC claims and the actual check-run/job/physical-runner/service-UID
join. The two required profiles may reference the same immutable callee twice;
a different or mutable callee is rejected. Legacy human policies retain their
original event and actor-type checks.

This is an identity component, not a lease or operating grant. The current
workflow candidate still needs the reviewed OIDC permission/token handoff and
Root service/engine/custody integration. A genuine token and native assigned job
must be qualified before any Heavy acceptance is claimed. Claim availability
reference: https://docs.github.com/en/actions/reference/security/oidc .


### Physical runtime host package preparation (unpublished)

`playbooks/github_runner_runtime_host.yml` reuses `lit.ubuntu.podman` for one
explicit literal inventory host. Required private inputs are
`github_runner_runtime_host_target`, `github_runner_runtime_host_machine_id`
and the exact Debian `github_runner_runtime_host_podman_version`. Keep the
inventory and native SSH credential references outside Git. An apply also
requires an external `github_runner_runtime_host_window_reference`; the string
is a traceability reference, not operating authorization.
Generic syntax checks need no live-target inputs. An execution with the target
omitted selects only the controller placeholder and fails the first assertion,
before identity reads, connections to inventory hosts or package actions.

Before the role runs, the play checks the actual machine ID, Ubuntu 24.04,
x86_64, an existing KVM device, exact package selection and unchanged restricted
role options. AppArmor repair, DNS changes and system/user API-socket management
are disabled; an override expanding those options is rejected before package
actions. Existing API-socket state is observed, and an unexpected newly active
system socket after apply fails the result for explicit reconciliation. Package
maintainer effects still belong in the reviewed native package plan.

The separate, default-off
`github_runner_runtime_host_restore_packaged_podman_profile` opt-in addresses a
previously edited Ubuntu AppArmor conffile whose missing `unconfined` attachment
flag prevents even `podman --version` from loading its libraries. It restores
only that exact header and requires the complete resulting bytes to match the
conffile digest recorded by the installed `apparmor` package. Unknown edits,
linked files and different permissions fail closed. The parser validates the
candidate before atomic replacement and reloads that one profile; AppArmor
remains enabled. This does not enable the generic role repairs, change DNS or
start an API socket. Keep the opt-in and package-profile readback in the private
pilot inputs and evidence.

Check mode predicts the exact version's package preparation; it does not prove
a package installation, engine kernel behavior or an idempotent native apply.
A zero exit with no matching target recap is not acceptance. Actual installation
must be followed by the direct executable/hash readback, a second identical
apply and the existing pinned-EE/native namespace probe. This play neither pulls
an image nor changes a runner registration, creates an Incus VM, or activates
the protected runtime. The standard EE runs the test tooling; application test
targets remain Incus VMs on the same physical runner host.

### Stopped expected-ID physical handoff (Root maintenance, unpublished)

`playbooks/github_runner_physical_helper_library.yml` prepares only the private
handoff library on one machine-bound host. Supply the literal
`github_runner_physical_library_target`, its actual
`github_runner_physical_library_machine_id` and an authorized
`github_runner_physical_library_operation_reference` through the private
inventory. The as-built collection determines every helper/module hash. A fresh
installation records a Root-only `.library-binding.json` after verifying the
installed bytes, owner/modes and complete file inventory. Exact reentry is
idempotent; foreign, changed, linked or partially prepared state is preserved
and refused. Do not replay an interrupted preparation over an unbound directory.
Check mode can predict a fresh directory without writing helper files; it does
not prove native CLI imports. Apply imports the installed CLI through its
isolated Python bootstrap and invokes only `--help`. This preparation creates
no account, registration, listener, runtime socket or Incus resource and does
not stop or change the legacy runner. Runner payload, dedicated account,
confinement and actual stopped handoff remain separate requirements.

`playbooks/github_runner_physical_assets.yml` performs that credential-free
asset preparation on one explicitly selected x64 host. Its private input is the
closed provisioner configuration plus target/machine identity and the local
official `2.338.2` x64 payload path. It first verifies every installed helper
byte against the as-built collection and the completed library receipt. A new
account/group and all managed leaf paths must be absent; existing unbound or
partially prepared state is refused before mutation. The profile bytes must
match the collection template and the payload its official digest.
The target downloads the fixed official payload directly over verified HTTPS;
the controller's local archive is only an independently checked reference. This
avoids sending the large archive over the operator's SSH connection. Download
task output is suppressed so redirected signed URLs are not retained.

Apply creates only the new locked `nologin` account without supplementary
groups, its isolated home/work storage, the private payload and the standalone
enforcing AppArmor profile. It verifies native account/group ownership, locked
password status, file/directory boundaries, archive identity and loaded profile
before writing the Root-only `<manifest>.assets.json` receipt. Exact reentry
reads and verifies that receipt and performs no repair. Check mode only runs
the read-only preflight; it does not predict account UIDs or prove preparation.
This play does not extract/run the payload, stop/start a service, request a
registration token or change a runner registration. Once handoff has created
the actual installation, this preparation play deliberately refuses reentry.

The Root-only `migrate_stopped` function in the provisioner connects the native
fence, expected-ID registration journal, pinned stock service generation and
fresh protected installation. The Root-only `handoff-inspect-input` and
`handoff-apply-input` actions use closed stdin envelopes, with no shell token
arguments or job hooks. A trusted
maintenance caller must first reserve/quarantine the exact existing runner,
stop and disable only its old unit, and exclude external service-start operations
throughout this transaction. A fixed private Root lock in `/run` serializes both
ordinary provisioning and stopped handoff calls across the host. Contention fails
before effects; the lock inode is retained and unsafe existing inodes are refused
without repair. This local lock does not replace GitHub quarantine or prevent
unrelated privileged tools from starting a service. The existing role's
legacy-adoption rejection remains unchanged.

Both envelopes contain exactly `configuration`, `native_fence` and
`registration_stage`; apply additionally requires `registration_token` (empty
only for exact successful reentry). The fence is the complete validated
`NativeFencePolicy`, with JSON arrays for labels and old drop-ins. Inspection
requires the already prepared dedicated account/archive/profile and actual
stopped/quarantined native state. It creates no lock, store or staging path,
performs no registration/service mutation and grants no apply capability.
Apply independently reacquires its native observations under the host lock.
These actions do not create an approved operating window, reserve a runner,
install prerequisites or stop/disable the old listener. Those remain explicit
maintenance prerequisites; an opaque window reference alone is not approval.

`playbooks/github_runner_physical_handoff.yml` invokes only an already installed
reviewed helper. Its explicit private inputs are
`github_runner_physical_handoff_target`, `github_runner_physical_handoff_machine_id`,
`github_runner_physical_handoff_helper_sha256`, `github_runner_physical_handoff_request`
and `github_runner_physical_handoff_window`. The window contains `reference`,
`starts_at` and `ends_at` as Unix seconds and must match the fence reference.
A bounded window remains at most two hours long; native host time must show
at least ten minutes remaining. An explicitly owner-approved open-ended window
instead adds exactly `owner_approved_open_end: true` and sets `ends_at: null`.
Its start must still have passed. A null end alone, a false/unknown approval
value or extra fields is refused. This checks the declared window; it does not
create or authenticate user approval. Job hard expiry and retained-cell limits
are independent and unchanged. The request is the three-field inspection
envelope above; apply adds the separately supplied
`github_runner_physical_handoff_registration_token` only to stdin. A token is
unnecessary for inspection or exact successful reentry.

Check mode calls the read-only action even though Ansible normally skips command
tasks. Normal mode calls the serialized stopped handoff. Both first recheck the
actual machine, Root-only helper directory and exact helper hash; the isolated
Python bootstrap rejects writable or symlinked helper ancestors before import.
No prerequisites are installed and no account, runner reservation or old service
is changed by this playbook. Its native apply and the complete maintenance flow
remain unqualified until an actual authorized pilot proves them.

The function requires an unused private registration-store path, a distinct
fresh installation, a dedicated account, the same runner name/group/labels,
architecture and work folder as the Root fence, and no collision with the old
tree or a new service unit. It acquires the stopped/disabled/empty/quarantined
native proof before effects and again after archive verification, immediately
before the expected-ID credential transition. It never invokes stock
`config.sh` to create another registration. `registration.read_completed`
returns only verified completed-store bytes in Root memory; its representation
omits credential and private-key content. No old credential or executable is
copied. The original tree/unit remain retained.

The existing write-ahead transaction records the expected ID, old unit and
private registration-store locator. Stock installation may enable the new
unit, so this path explicitly disables it, reads that state back, stops it and
rechecks both its disabled state and sealed installation before returning.
It never starts a runner, assigns repository access or activates the runtime.
Uncertain provider/service responses retain both journals and staging; later
calls refuse uncertain state instead of rotating a key or replaying a write.
An exact successful stopped handoff can be checked again without a token or
another write. This read-only path requires the completed journal's full
configuration/fence binding, fresh native quarantine and old-unit observations,
the unchanged verified installation and private registration-store bytes, the
collector descriptor, and the new service still stopped and disabled. Changed
requests, incomplete journals, an already started service or material drift are
denied without repair. This is not authorization to activate the runner.
Credential rotation invalidates the old key: rollback cannot mean blindly
starting the old listener. It needs explicit native reconciliation and another
properly fenced expected-ID handoff.

An authentication response without `use_v2_flow` selects the stock legacy
flow; an explicit false value has the same meaning. The Root client validates
the authenticated tenant origin and path, discovers the exact TaskAgent resource
GUIDs and route/version contracts, and reads the expected pool and runner before
one ID-bound PUT. It projects the fetched agent onto the pinned stock DTO
members, excluding unknown informational metadata such as a null runner group
name; group authority comes from the native fence and exact pool route. It
submits the persisted fresh RSA public key and replaces the
whole old authorization object. Tenant tokens stay in memory. V2 registration
remains supported; neither flow adds a replacement runner under a new ID.

Ordinary calls still refuse partial journals. A separate internal Root function,
`registration.resume_rejected_legacy_auth`, requires a Root-private operator
receipt proving the earlier `registration-auth-flow` rejection and binding the
original store, stage and target. It retains the key and original authentication
intent, records a distinct reconciliation intent, and never resets the store to
`prepared`. An unknown authentication or replacement outcome cannot use this
path. A failed reconciliation is held rather than retried automatically.

A proved `legacy-agent-group` preparation rejection before any PUT may use
`registration.resume_legacy_prewrite_rejection` with its independent Root-private
operator receipt. Fresh authentication and full preparation remain read-only;
the original authenticated journal and any earlier reconciliation are retained
until a distinct proof is committed together with the one replacement intent.
An attempted or unknown replacement, existing credentials, drift, or an
unproved rejection cannot enter this continuation.

If registration is complete but the fresh program remains unpublished,
`complete_registered_handoff` can finish that specific Root operation. It
requires the original `registration-intent` journal, verifies every retained
public staging byte/link/mode against a new extraction of the pinned archive,
and reacquires the native stopped-runner fence. It copies only the completed
private registration material and publishes the new service stopped and disabled.
It performs no authentication, registration, key generation or legacy-tree
adoption. Later uncertain publication/service phases remain held for explicit
reconciliation. These internal Root interfaces are not job hooks or activation
approval, and their component tests do not establish native operating acceptance.

The package tests use actual private filesystem sealing, registration journals,
RSA serialization and pinned stock script generation. Provider, fence and
systemd boundaries are modeled. Native physical-host migration, the declarative
maintenance caller, capacity/window/custody inputs, genuine GitHub assignment
and complete runtime/Heavy qualification remain required before activation.

### Main Nexus-readback artifact intake (unpublished)

A Root acquisition request can select the separate `MainArtifactRequest`
domain by including `request_id` in its closed artifact object. It requires
exactly `mlx90-candidate-<request_id>` from the Validation Main dispatch,
attempt one, the original Release App actor and triggering actor, the matching
run title, same-repository head, and the exact current protected Main commit.
The complete attempt-one job inventory must contain one successfully completed
`Nexus exact-byte readback` job for that same run and caller SHA. Root reads the
run, artifact and readback provenance again after downloading; changes deny
acquisition. Only fixed repository endpoints are used, and redirect downloads
receive no API bearer. Legacy producer acquisition is unchanged.

The publisher joins this acquired artifact to the sealed modern registry's
consumer run, caller SHA, workflow ID/path and artifact name. Its profile
selector must equal the installed client's `profile_selector` result. The
source commit and action/controller commit remain separate identities. The
candidate package is still checked against authenticated source Git blobs,
Galaxy payload metadata and inner checksums; no candidate code runs as Root.
This is source preparation, not native job admission, an activated service,
Runner01 migration or Heavy acceptance. Those complete integration steps remain
required. API contracts: https://docs.github.com/en/rest/actions/workflow-runs ,
https://docs.github.com/en/rest/actions/workflow-jobs and
https://docs.github.com/en/rest/actions/artifacts .

### Legacy Runner01 boot fence before an expected-ID handoff

The read-only native fence now reads systemd `UnitFileState` alongside the
selected legacy unit's process and cgroup properties. Both stopped-state reads
must prove `disabled` before issuing an expected-ID registration target.
An inactive but enabled listener, missing state or install-state drift fails
closed. Before-stop planning may still observe an enabled/busy listener; it
never issues a registration capability. This check does not disable a service,
rotate credentials, reserve a runner, or authorize a live migration. The Root
maintenance caller must perform and reconcile that separately authorized
transition while preserving all other runner services and existing workloads.

### Fixed physical-runner profile entry (unpublished)

The installed `incus-runtime-client run-profile --profile heavy --scenario kernel
--target ubuntu24` uses the existing RuntimeV2 `run-cell` protocol. It derives a
`cell-` locator followed by the SHA-256 of the compact JSON array
`[profile,scenario,target]`. Root registry preparation must use the same
locator derivation, independently available in the private Root library as
`policy_registry.profile_selector` and bind the exact native job name, candidate,
image, resources and custody policy. A locator is never execution authority.
Only `heavy` and `application_acceptance` and bounded scenario/target identifiers
are accepted; no endpoint, command, image, token or path option is added.

The host workflow supplies its short-lived job API token and OIDC request
capability only to this installed client. The Root daemon authenticates the
native assignment, owns the pinned EE and same-host Incus test-VM lifecycle,
and returns sanitized evidence. The existing full evidence, actual exit, cleanup
and interruption gates continue to determine the CLI exit status and workflow
outputs. Failed diagnostics may upload, but do not turn a failed test into a pass.
The Root service, native permissions and complete operational path remain
integration prerequisites; adding this entry does not install or activate them.


For the Validation Main domain, the sealed cell's `github` object additionally
requires a positive integer `run_id`. The native admission bridge compares it
to the independently verified assigned run before minting its process-local
proof or preparing a lease. Cell execution and cleanup recheck the same binding.
A genuine different Main run cannot borrow a prepared candidate. Root intake
must derive this field from the verified native request/run readback; it is not
an action-supplied setting. Legacy cells retain their existing `job`/`workflow`
schema. A completed native intake/registry test remains required.
