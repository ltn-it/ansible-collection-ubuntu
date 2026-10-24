# ansible-collection-ubuntu

<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.

See [RELEASE.md](./RELEASE.md) for:

- branch and release flow
- required quality checks
- test matrix
- release evidence
- artifact publishing
- supported repository-specific release behavior

Repository classification: **Ansible Collection**.
Required test profiles: `pre-commit, lint, light, molecule-light, molecule-heavy-incus, release-validation`.
Publishing targets: `github-release, ansible-galaxy`.

## Supported and Tested Platforms

| Platform / Product |                  Status | Validation       |
| ------------------ | ----------------------: | ---------------- |
| ubuntu-latest      |               Supported | Molecule / Incus |
| ubuntu-lts         |               Supported | Molecule / Incus |
| ansible-core       | Tested where applicable | Molecule / Incus |
| molecule           | Tested where applicable | Molecule / Incus |
| incus              | Tested where applicable | Molecule / Incus |

<!-- END LIT_SHARED_RELEASE_MODEL -->

<!-- BEGIN LIT_QUALITY_BADGES -->

[![CI](https://github.com/lightning-it/ansible-collection-ubuntu/actions/workflows/collection-ci.yml/badge.svg?branch=develop)](https://github.com/lightning-it/ansible-collection-ubuntu/actions/workflows/collection-ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/lightning-it/ansible-collection-ubuntu?sort=semver)](https://github.com/lightning-it/ansible-collection-ubuntu/releases/latest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lightning-it/ansible-collection-ubuntu/badge)](https://scorecard.dev/viewer/?uri=github.com/lightning-it/ansible-collection-ubuntu)
[![Ansible Galaxy](https://img.shields.io/ansible/collection/v/lit/ubuntu?label=Ansible%20Galaxy)](https://galaxy.ansible.com/ui/repo/published/lit/ubuntu/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

<!-- END LIT_QUALITY_BADGES -->

[![Collection CI](https://github.com/lightning-it/ansible-collection-ubuntu/actions/workflows/collection-ci.yml/badge.svg?branch=develop)](https://github.com/lightning-it/ansible-collection-ubuntu/actions/workflows/collection-ci.yml)

Ubuntu-focused Ansible collection covering OS baseline, apt repositories,
automatic updates, users, developer tooling, desktop helpers, and day-2
operational tasks.

This collection is part of the ModuLix / Lightning IT ecosystem and follows the
same shared-assets collection structure as the RHEL collection, while using
Ubuntu-native package and repository management.

## Roles

- `lit.ubuntu.baseline`
  Install baseline packages and configure timezone/locale.
- `lit.ubuntu.repos`
  Configure apt repositories, apt signing key files, and optional apt proxy
  policy.
- `lit.ubuntu.automatic_updates` - periodic updates and signed staged package-data supply and verification
  Schedule weekly `apt-get update && apt-get upgrade` runs via cron.
- `lit.ubuntu.users`
  Manage local Linux users and SSH keys.
- `lit.ubuntu.developer_tools`
  Install developer packages, Python packages, optional GitHub CLI, Argo CD,
  Terragrunt, OpenShift CLI, and SSH agent/private key helpers.
- `lit.ubuntu.incus`
  Configure an Ubuntu host as an Incus host.
- `lit.ubuntu.incus_image`
  Import Incus image artifacts and manage local image aliases.
- `lit.ubuntu.incus_instance`
  Manage Incus instance lifecycle, cloud-init injection, readiness waits, and
  optional generated inventory output.
- `lit.ubuntu.netplan`
  Render and apply Ubuntu netplan interface configuration.
- `lit.ubuntu.openssh_server`
  Render and validate hardened OpenSSH server configuration with safe multi-port transitions and Ubuntu socket
  activation reconciliation.
- `lit.ubuntu.luks_unlock`
  Stage secret-free Dropbear first-boot unlock hooks and safely add pinned Clevis Tang bindings to existing LUKS2
  devices.
- `lit.ubuntu.tang_deploy`
  Install and validate a minimal systemd socket-activated Tang binding service.
- `lit.ubuntu.host_firewall`
  Apply a fail-closed, Podman-aware nftables policy through rollback-protected plan, check, apply, confirm, readback,
  and rollback phases. Its optional forward-proxy egress boundary requires the unique host-local, non-login
  `proxy` identity at exact UID/GID 13; directory-only or duplicate-UID identities fail before policy rendering.
  Optional container DNS is default-off and permits only TCP/UDP 53 to a destination bound by read-only evidence to
  every selected Podman bridge gateway; a generic observed host address cannot authorize that path. Exact
  per-client proxy capabilities bind one bridge, source `/32`, observed gateway, port, and mode without creating an
  interface/source/destination cross product. Container service forwarding remains restricted to the management
  interface. Reverse-proxy-to-backend traffic inside one dedicated Podman bridge stays layer 2 and is therefore not
  represented as host-routed forwarding by this role.
  `host_firewall_container_dns_clients` defaults to an empty mapping. Its separate per-client mode permits only
  INPUT UDP/53 from each exact private `/32` client to its observed bridge gateway; it grants no TCP or FORWARD
  access and cannot coexist with aggregate container DNS access.
- `lit.ubuntu.forward_proxy_client`
  Configure Ubuntu APT, process, systemd, and optional Podman clients for the
  separately deployed portable forward proxy.
- `lit.ubuntu.podman`, `lit.ubuntu.gui`, `lit.ubuntu.xrdp`,
  `lit.ubuntu.firefox`, and `lit.ubuntu.vscode`
  Provide optional workstation and remote desktop building blocks.
  Podman's `podman_dns_authoritative_only` defaults to false. Opting in requires the actual Netavark resolver
  path in `podman_dns_resolver_executable` and its independently approved SHA256 in `podman_dns_resolver_sha256`.
  The role validates the effective helper and trusted ancestors before persisting `AARDVARK_NO_PROXY` for future
  launches. It does not restart an existing resolver or replace occupied networks; runtime cutover and health
  verification remain separate. See the disabled Podman and exact-DNS examples in `playbooks/example.yml`.

## Example

```yaml
---
- name: Configure Ubuntu hosts
  hosts: ubuntu
  become: true

  roles:
    - role: lit.ubuntu.repos
      vars:
        repos_update_cache: true

    - role: lit.ubuntu.baseline
      vars:
        baseline_timezone: Etc/UTC
        baseline_packages_present:
          - vim
          - jq
          - tar
          - bash-completion

    - role: lit.ubuntu.automatic_updates
      vars:
        automatic_updates_enabled: true

    - role: lit.ubuntu.users
      vars:
        users_accounts:
          - name: ops-admin
            groups: ["sudo"]
            shell: /bin/bash
```

## Development

This repository is designed to be used together with:

- `pre-commit` for local linting,
- the shared `wunder-devtools-ee` container for consistent tooling,
- Molecule scenarios for role-level testing.

Each role is expected to provide:

- `meta/main.yml` with Galaxy metadata,
- `defaults/main.yml` with documented variables,
- `README.md` with a clear description and examples.

## Security

See [SECURITY.md](./SECURITY.md) for supported versions and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution and review expectations.

## License

See [LICENSE](./LICENSE).

<!-- BEGIN LIT_RELEASE_QUALITY_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.
The README shows the current supported and tested matrix.
Exact per-version validation proof is stored with each GitHub Release as `release-evidence.md` and `release-evidence.json`.
Releases are created from the protected `main` branch after a reviewed `develop -> main` release promotion.
Collection releases validate collection sanity, Molecule scenarios, build integrity, and Ansible Galaxy publishing where enabled.

See:

- [RELEASE.md](./RELEASE.md)
- [TESTING.md](./TESTING.md)
- [GitHub Releases](../../releases)

Repository classification: **Ansible Collection**.
Required test profiles: `pre-commit, lint, light, molecule-light, molecule-heavy-incus, release-validation`.
Publishing targets: `github-release, ansible-galaxy`.

<!-- END LIT_RELEASE_QUALITY_MODEL -->

<!-- BEGIN LIT_COMPATIBILITY_MATRIX -->

## Compatibility Matrix

| Collection Version | Platform | Product | Validation |
|---|---|---|---|
| Latest release | ubuntu-latest | ansible-core, molecule, incus | See release evidence |
| Latest release | ubuntu-lts | ansible-core, molecule, incus | See release evidence |

| Scenario | Test Type | Validation |
|---|---|---|
| collection-sanity | Collection sanity | See release evidence |
| molecule-light | Molecule light | See release evidence |
| molecule-heavy-incus | Heavy Incus | See release evidence |
| galaxy-build | Galaxy build/publish | See release evidence |

Validation proof for each released version is stored in the corresponding GitHub Release evidence.

<!-- END LIT_COMPATIBILITY_MATRIX -->

## Release Evidence

Every released version includes immutable release evidence attached to the corresponding GitHub Release.
The evidence records:

- tested matrix combinations
- GitHub Actions run links
- artifact references
- publish status
- security scan status

See [GitHub Releases](../../releases), [RELEASE.md](./RELEASE.md), and [TESTING.md](./TESTING.md) for the release process and validation model.
