===================================================
Lightning IT Collection Release Notes Release Notes
===================================================

.. contents:: Topics

v1.18.0
=======

Minor Changes
-------------

- Document Nexus candidates, exact-byte validated Galaxy promotion, transition limitations, and per-Collection cutover evidence.
- Release preparation and back-sync rely on native central review events instead of dispatching the retired local review workflow.

v1.17.0
=======

Minor Changes
-------------

- host_firewall - support default-off exact UDP53 clients bound independently to each observed private bridge gateway.
- openssh_server - add explicit plan/apply/confirm/rollback finalization with source/target guards, candidate rendering, protected snapshots and a controller-independent 300-second systemd rollback timer.
- podman - add an opt-in pinned authoritative-only Aardvark startup policy without restarting the shared resolver.

v1.16.0
=======

Bugfixes
--------

- host_firewall - support explicit rootful container HTTPS publishing with exact source, bridge, endpoint and conntrack-DNAT bindings, plus separately identity-bound local proxy hairpin access; defaults remain closed.

v1.15.0
=======

Minor Changes
-------------

- Add a default-off, least-privilege container-to-host Aardvark DNS input contract to ``lit.ubuntu.host_firewall`` for exact managed interfaces, RFC1918 source networks, and one observed bridge gateway.
- Add fail-closed per-client container-to-host Squid capabilities that bind one bridge, source /32, observed bridge gateway, port, and operating mode without an aggregate interface/source/destination cross product.

v1.14.0
=======

Minor Changes
-------------

- Add an exact, default-off container-to-management service forwarding contract to ``lit.ubuntu.host_firewall`` for tightly scoped application paths such as Guacamole-to-RDP.

Bugfixes
--------

- Preserve path-MTU discovery and other related IPv4 ICMP errors for exact container-service forwarding rules while retaining the configured source, destination, protocol, port, and interface boundaries.

v1.13.0
=======

Minor Changes
-------------

- Add the lit.ubuntu.forward_proxy_client adapter for APT, host processes, systemd services, and explicitly enabled Podman clients. Extend the hardened nftables role with the matching proxy egress boundaries. The portable Squid service is provided by lit.supplementary.forward_proxy.

Security Fixes
--------------

- Require the host-firewall forward-proxy socket owner to be Ubuntu's exact reserved non-login proxy identity at UID/GID 13 before granting public HTTP(S) egress.

v1.12.0
=======

v1.11.0
=======

Minor Changes
-------------

- host_firewall - add a fail-closed Ubuntu 24.04 nftables policy with per-function IPv4 management sources, canonical JSON readback, isolated table/include ownership, a single locked rollback-protected transaction routine, and canonical rejection of every IPv6 input spelling for this target baseline.
- host_firewall - add a fail-closed public service access contract with per-service protocol, port, mode, and exact-host source authorization.

Security Fixes
--------------

- host_firewall - prohibit whole-ruleset backup/replay and root nftables configuration replacement, execute nft validation during global check mode, reject ambiguous aggregate source lists, require short-lived signed one-time authorization, enforce a target-specific deny-by-default egress contract, and reject confirmation unless the end-to-end IPv4-only and evidenced provider IPv6-filter boundaries hold. Bound external commands and lock waits below the rollback watchdog, retry stale-lock rollback, and durably order terminal and active-state transitions.

v1.10.0
=======

Minor Changes
-------------

- Add users_accounts_global as a final user-definition layer whose values take precedence over base and extra definitions for the same account.
- Allow the developer_tools role to upgrade operating-system Node.js packages by setting developer_tools_nodejs_package_state to latest.
- Delegate the live LUKS and Tang scenario plus every ``protected-incus`` scenario to the pinned ``modulix-validation`` workflow with an immutable candidate, mandatory post-assertion markers, centralized cleanup, and normalized evidence.
- Make incus_instance reconciliation idempotent for cloud-init, config, and limit values, reject generated key-only cloud-init without an SSH key, and pass configured profiles correctly when creating an instance.

Bugfixes
--------

- Add an opt-in Podman AppArmor profile repair and targeted reload so Ubuntu hosts can restore the package-compatible unconfined attachment profile before validating the direct Podman executable; also reconcile the system Podman socket to its explicitly configured state.
- Allow opt-in Node.js runtime options for npm and npx operations so hosts without working IPv6 egress can explicitly prefer IPv4 DNS results.
- Allow the Podman role to restore and reload Ubuntu's package-compatible unconfined Buildah AppArmor attachment profile independently.
- Allow the Podman role to restore and reload explicitly declared helper attachment profiles needed by the rootless container toolchain.
- Enable Ubuntu's socket-activated SSH listener in generated Incus cloud-init data while retaining service fallbacks for other guest images.
- Install the configurable openssh-server default in generated Incus cloud-init data so minimal cloud images expose the declared SSH contract.
- Keep generated key-only Incus SSH accounts unlocked while password authentication remains disabled, allowing OpenSSH public-key login.
- Make the shared isolated Python toolchain readable and traversable by declared developer users even when controller umask defaults are restrictive.
- Match generated Incus cloud-init networking to both container and virtual machine Ethernet interface names instead of assuming an incus0 device.
- Reconcile declared Incus preseed networks when the daemon was already initialized with different bridge settings.
- Reconcile missing Incus storage pools from the preseed even when another pool already initialized the daemon.
- Reload the declared Podman AppArmor profile on every real role run so an already-correct file cannot leave stale restrictive kernel policy active.
- Remove the generated guest account's unusable shadow lock after cloud-init creation so OpenSSH accepts its authorized key on images that retain it.

v1.9.0
======

Minor Changes
-------------

- Harden the cis_ubuntu24 integration with separate fail-closed remediation and audit modes, exact native-profile validation, an inventory exception schema, immutable remediation and audit dependency metadata, and idempotent handling of the package AIDE service when the cron scheduler is selected. Preserve a traversable audit log directory when inventory disables the pinned upstream role's defective recursive file-mode remediation, and persist the network sysctls whose pinned audit persistence checks are malformed.
- Reconcile the root Incus SubUID/SubGID allocation before daemon operations.
- collection_tooling - Synchronize the centrally managed Renovate policy and guarded automation workflows.
- developer_tools - Add isolated pinned Python tooling, pinned global npm packages, private workspace directories, and SHA-256-verified standalone release binaries for reproducible development hosts.
- github_runner - Add a backward-compatible, data-driven multi-instance interface with isolated installation and work directories, per-instance registration lifecycle with distinct registration and removal tokens, and independent systemd service management. Organization runner groups and declarative cleanup of externally managed legacy services are supported for controlled migrations.
- incus - Add fail-closed JSON discovery, optional preseed initialization, and declarative project and profile reconciliation for Incus hosts.
- podman - Exercise the role in its basic Molecule scenario with isolated, non-mutating inputs instead of a syntax-only marker stub.
- users - Add opt-in exact supplementary-group and exclusive authorized-key reconciliation for security-sensitive developer accounts.

Breaking Changes / Porting Guide
--------------------------------

- Raise collection minimum ``requires_ansible`` from ``>=2.16.1`` to ``>=2.18``. Consumers running ansible-core below 2.18 must upgrade before using this collection release.

Bugfixes
--------

- Guard external GitHub runner service metadata when the optional unit-file check is skipped.
- Make GitHub runner instance validation compatible with strict Ansible boolean conditionals and redact token-bearing instance data on failures.
- Pass ``--no-profiles`` when an instance explicitly declares an empty profile list.
- developer_tools - Bound npm registry fetch timeouts and retries so global Workbench CLI installation cannot hang indefinitely on transient network failures.
- developer_tools - Install Python virtual-environment support before creating the isolated toolchain on Ubuntu hosts.
- developer_tools - Require an exact Packer archive checksum and prevent the OpenShift client archive from reporting changes on every run.
- incus - Prevent initialization, project, and profile mutations during Ansible check mode.
- incus - Treat the recognized uninitialized-daemon response as empty storage state while failing closed for unrelated discovery errors.
- users - Reject malformed SSH key declarations before authorized-key reconciliation.

v1.8.0
======

Minor Changes
-------------

- luks_unlock - Add an explicitly non-idempotent, one-run recovery option to rebuild initramfs after an existing Clevis binding passes every verifier.

Bugfixes
--------

- luks_unlock - Enforce the declared Tang signing thumbprint during preflight and cached-advertisement enrollment, verify persisted bindings using Clevis's URL-only representation, and bound an exact-keyslot online unlock test without exposing key material.

v1.7.0
======

Minor Changes
-------------

- Add the inventory-driven ``lit.ubuntu.openssh_server`` role with validated multi-port transition support, Ubuntu systemd socket-activation reconciliation, check-mode coverage, directive-injection protection, and secure public-key-only defaults.
- Added guarded Ubuntu LUKS initramfs unlock automation with a secret-free Hetzner installimage Dropbear bootstrap, pinned Clevis Tang bindings, and a minimal Tang socket deployment role.
- developer_tools - Add configurable Node.js/npm/npx installation and markdownlint-cli2 validation support.
- docs - Apply the shared enterprise README structure.
- docs - Consolidate generated governance metadata and license policy on shared-assets-lit.
- netplan - Add validated rendering support for tagged VLAN interfaces.
- release_model - Add managed compatibility matrix documentation and structured release evidence fields.

Bugfixes
--------

- shared_tooling - Dispatch collection publishing from protected main with the managed release environment and Galaxy credential, make lint compatibility detection rely on the execution environment, and ignore generated local collection-install and Python cache artifacts.

v1.6.0
======

Minor Changes
-------------

- developer_tools - Add optional actionlint installation from the upstream release archive with checksum verification.

v1.5.0
======

Minor Changes
-------------

- molecule - Run Docker-driver light scenarios with host networking so they clean up reliably through the rootless Podman API socket.
- podman - Add optional system and rootless user Podman API socket management for workbench container flows without Docker.

v1.4.0
======

Minor Changes
-------------

- lit.ubuntu - Verify automated collection release workflow cycle 2.

v1.3.0
======

Minor Changes
-------------

- lit.ubuntu - Verify automated collection release workflow cycle 1.

v1.2.0
======

Bugfixes
--------

- ubuntu - Restore collection roles, Molecule scenarios, and collection dependency metadata on the develop branch after the shared-assets-lit release workflow migration.

v1.1.0
======

Bugfixes
--------

- ubuntu - Restore collection roles, Molecule scenarios, and collection dependency metadata on the develop branch after the shared-assets-lit release workflow migration.
