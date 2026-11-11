# lit.ubuntu.host_firewall

Build and inspect a fail-closed nftables host policy for Ubuntu 24.04. The role owns one `inet` table and optionally
one explicitly managed `bridge` SSH guard in the same transaction and dedicated persistence include.
It never captures, flushes, restores, or persists the complete host ruleset, and it
never overwrites the administrator-owned root nftables configuration. Foreign tables and Podman/Netavark tables stay
outside the role boundary.

Management access is modeled per function. `bootstrap_ssh` uses TCP 22 only in bootstrap mode, `openssh` uses TCP
1905, and `dropbear` uses TCP 2222. Each function has an independent IPv4 `/32` source list. The same source may be
approved for more than one function without granting access to any other port. The active target baseline is
IPv4-only; every IPv6 identity, source, destination, and explicit IPv6 allow path is rejected. IPv6 addresses observed
on a provider interface receive no allow rule and are therefore denied by the host input, forward, and output policy.

Public host application entry points use the separate `host_firewall_public_service_access` mapping. Each named service
declares one TCP/UDP port, explicit bootstrap/hardened modes, and exact IPv4 `/32` sources. Public services never
inherit management or Tang sources and never permit a broad IPv4 source range.

Rootful container-published HTTPS traverses DNAT and FORWARD instead of INPUT. The default-off
`host_firewall_published_https_access` capability reuses the existing `https` TCP/443 source and mode contract.
Each operator-maintained endpoint declares one managed container bridge and one exact RFC1918 container IPv4 address.
The role validates the declaration, not live container membership: before applying it, the caller must independently
verify the actual reverse-proxy membership and keep the declaration current. Stale or mistyped container addresses
are not detected by this role. Rules require both the original public destination socket
and the post-DNAT endpoint. Replies and related ICMP errors are bound to the same connection tuple. Direct backend
access and arbitrary forwarded container traffic remain denied. IPv6 publishing is not supported.

Set `host_proxy: true` only when the existing validated `proxy` UID/GID 13 must reach this same public HTTPS name
through host-local DNAT. This additionally requires the host public `/32` in the HTTPS source list and permits only
that identity, exact bridge, endpoint and original TCP/443 destination. It creates no new NAT rules or listeners.
The enabled declaration participates in the policy fingerprint; default-off leaves existing policy material unchanged.

```yaml
host_firewall_published_https_access:
  enabled: true
  endpoints:
    - interface: podman0
      ipv4: 10.88.0.2
  host_proxy: false
```

`plan` renders the candidate and its closed authorization contract. `preview` executes the candidate in an isolated
network namespace and verifies its canonical readback without changing the host firewall. `check` executes `nft --check` even when Ansible
runs in global check mode. Structured readback uses `nft --json`, removes only documented runtime fields, and compares
the resulting canonical SHA-256 with an independently approved policy artifact. Text comments are not acceptance
evidence.

The preview approval digest hashes the canonical command output directly. It
does not hash a JSON mapping reconstructed by Ansible; the transaction must
compare the same canonical bytes after apply and again before confirmation.

Productive `apply`, `confirm`, and `rollback` use one static root-owned transaction routine and one exclusive lock.
The routine validates a short-lived, externally signed authorization, retains its signed envelope and verifier receipt,
consumes its claim exactly once, snapshots only the role-owned table and include, stages immutable transaction assets,
arms the rollback watchdog, and applies the candidate in one serialized operation. Static runtime installation uses
the same lock and cannot replace a program, unit, or trust anchor while a transaction is active. Confirmation
revalidates the authorization, metadata, verifier, every staged and static asset, root and included persistence files,
and structured runtime readback before and after stopping the watchdog. Explicit and watchdog rollback use the same
lock and record the exact restored runtime and persistence state.

Every external transaction command has a hard timeout, every lock acquisition has a shorter stale-lock timeout, and
the total apply budget reserves a separate rollback budget below the watchdog expiry. The rollback service retries a
failed stale-lock attempt. Evidence creates, terminal publication, watchdog disablement, and active-pointer removal
are ordered with file and parent-directory synchronization so a reboot cannot turn one transaction into contradictory
confirmation and rollback outcomes.

For installations that do not require an external signing authority, set
`host_firewall_authorization_mode: controller_confirmation`. The controller then requires an exact, short-lived token
bound to action, inventory hostname, and candidate SHA-256. Apply remains protected by the rollback watchdog, and
confirmation remains conditional on declared positive and negative test evidence. This mode does not create or deploy
a separate private signing key.

The role enforces output policy `drop`. Egress is expressed as separate fixed functions for DNS, NTP, Atlas Loki,
temporary bootstrap HTTPS, and an optional hardened management proxy. Bootstrap HTTPS is never confirmable. Hardened
confirmation requires an approved deny-by-default policy, disabled bootstrap HTTPS, external positive and negative
test evidence, and an independently approved canonical readback digest. A configured trusted signature verifier and
valid signed envelopes remain deployment prerequisites; repository tests do not constitute live host acceptance.

## Requirements

- Ubuntu 24.04 LTS with `nftables`, systemd, Python 3, and an enabled `nftables.service`.
- Root privileges for the productive lifecycle.
- Trusted host facts containing every expected IPv4 address and no IPv6 address.
- Exact per-function IPv4 `/32` source entries. IPv6 compatibility input is canonicalized only so that every spelling
  is rejected consistently by the target's IPv4-only boundary.
- An administrator-owned, root-owned, non-symlink root configuration containing exactly one literal include for an
  already existing valid role-owned placeholder file. The role will not add, edit, or remove the root include and will
  not accept a dangling include as a rollback baseline.
- Preprovisioned root-owned, non-symlink program and systemd unit directories. The role installs only its named files
  and never creates or changes permissions on these shared directories.
- A root-owned, non-symlink executable signature verifier that returns the exact verification-receipt schema expected
  by the transaction routine.
- An independently reviewed canonical nftables JSON digest for structured readback.
- External positive and negative connectivity tests for confirmation.

The role does not install packages, change provider firewalls, or create DNS. Apart from explicitly declared published
HTTPS, new container forwarding remains denied unless `host_firewall_container_service_access` declares an exact
capability. Each such capability is limited to named
container interfaces and source `/32` addresses, the management interface, destination `/32` addresses, one TCP/UDP
port, and explicit modes. Return traffic is admitted only for the same endpoints and service port in established or
related state; no generic container forwarding is created.
Traffic between a reverse proxy and its backend on the same dedicated Podman bridge remains layer 2; this role does
not claim or render a host-routed forwarding capability for that path.

## Variables

The read-only `files/container_ssh_binding.py --discover` helper plans container
SSH ingress bindings from rootful Podman identity and actual kernel state. Its
stdin JSON contains `capabilities`, `mode`, and `table_name`. Each capability
requires `container_name`, `interface`, one RFC1918 `source_ipv4` `/32`, the
observed bridge `destination_ipv4`, `port: 1905`, and explicit `modes`.

It checks the selected container and namespace twice, refuses host networking
and privileged containers, and verifies both veth directions and bridge
membership. Only public identity fields are requested from Podman; application
environment values are not read. The returned bridge guard binds the observed
port name and index and protects the source identity for IPv4 and ARP. Shared
pod network namespaces are one trust unit; this does not authenticate individual
processes within a namespace or replace SSH key authentication.

The helper changes no firewall, interface, service or persistence file. Set
`host_firewall_container_ssh_guard_managed: true` to have the role discover
active `host_firewall_container_ssh_access` entries and include both the guard
and the exact TCP/1905 INPUT grants in one candidate. The managed flag remains
explicit when entries are removed, so an empty map clears old bindings rather
than orphaning a guard. Default-off consumers retain the single-table canonical
format. A coupled policy uses plan v4, policy v6 and transaction metadata v4,
including the exact owned-table scope and explicit prior table absence.

Coupled confirmation requires both tables to match the approved canonical
digest. Rollback restores both prior tables in one nft batch, including mixed
present/absent states. Explicit rollback and readback do not require a running
application container; rollback reads its protected original transaction
context. Recovered bindings apply only within that rollback invocation, including
its request, confirmation and authorization. They do not override inputs or
derived policy fingerprints in subsequent plays. The existing signing/confirmation
boundary remains required. The
[interface-index data type](https://netfilter.org/projects/nftables/manpage.html)
can still be printed as a live interface name with `--numeric` on nft 1.0.9.
Bridge snapshots therefore resolve scalar `iif`/`oif`/`sdif` equality operands
against the actual network namespace, retain numbers in canonical JSON and
restore text, and reject identity/count drift between text and both structured
observations. Deleted-index decimal JSON strings are normalized as numbers;
ambiguous numeric interface names fail instead of redirecting a stored index.
Interface-name matches and comments keep their original bytes.
Unsupported index sets, assignments or non-equality expressions in the owned
guard fail before mutation. A vanished ingress device cannot require name
resolution during rollback.

Discovery is repeated for each new candidate. A restarted namespace needs a
fresh binding; lifecycle automation and authenticated SSH/Guacamole acceptance
are separate required operational checks. A read-only discovery result alone
does not establish them or authorize a productive apply.

`host_firewall_forward_proxy_egress` optionally binds all hardened public
HTTP(S) egress to one local service identity (`meta skuid`). Direct mode permits
that identity on TCP 80/443; upstream mode permits one exact parent proxy and
port. `host_firewall_forward_proxy_access` separately admits explicit container
networks to the host-local proxy. Application processes receive no direct
Internet rule. When enabled, the socket owner must resolve to the reserved
non-login Ubuntu `proxy` account at exact UID/GID 13. Trusted root must not run
another service under that identity; the role rejects a renamed, login-capable,
numerically different, directory-backed-only, or duplicate-UID account before
rendering the candidate. The identity must exist uniquely in `/etc/passwd`.

`host_firewall_container_dns_access` is a separate default-off input function
for Podman/Aardvark name resolution. When enabled, it renders only TCP and UDP
port 53 from explicit managed container interfaces and canonical RFC1918 source
networks to one observed, non-loopback host gateway address. The destination
must also equal the bridge-specific value in
`host_firewall_observed_container_bridge_gateways_ipv4` for every selected
interface. It grants no
forwarded Internet access and does not inherit proxy, management, or host DNS
egress destinations.

For distinct service bridges, `host_firewall_container_dns_clients` is an empty
by-default map of named capabilities. Each entry contains exactly `interface`,
`source_ipv4` (one RFC1918 `/32`) and `destination_ipv4` (that interface's
read-only observed private gateway). It grants only host INPUT UDP/53, not
TCP/53 or forwarded DNS. The legacy aggregate DNS grant must remain disabled.
Every entry is bound into the policy fingerprint. This grant does not configure
the resolver or prove no-forwarding: verify the resolver policy and positive,
negative and restart evidence separately before acceptance.

See `defaults/main.yml` for the complete interface. Important inputs are:

- `host_firewall_action`: `plan`, `preview`, `check`, `apply`, `confirm`, `rollback`, or `readback`.
- `host_firewall_authorization_mode`: `signed` (external verifier) or `controller_confirmation` (exact candidate-bound token).
- `host_firewall_confirmation`: exact action, host, and candidate-bound controller token when using `controller_confirmation`.
- `host_firewall_mode`: `bootstrap` or `hardened`.
- `host_firewall_management_access`: exact mapping for `bootstrap_ssh`, `openssh`, and `dropbear`; every entry has a
  fixed port/mode contract plus independent `sources_ipv4` and `sources_ipv6` lists.
- `host_firewall_tang_access`: fixed TCP 80 with explicit IPv4 and IPv6 consumer host lists.
- `host_firewall_public_service_access`: independent public application functions with fixed protocol/port, explicit
  modes, and exact source-host lists.
- `host_firewall_published_https_access`: default-off DNAT-bound TCP/443 ingress to exact private container endpoints,
  optionally including the separately identity-bound local forward-proxy path described above.
- `host_firewall_container_service_access`: independent container-to-management functions with exact interfaces,
  source and destination `/32` hosts, protocol/port, and modes. The empty default denies all new forwarding.
- `host_firewall_forward_proxy_client_access`: exact container-to-host Squid clients. Every capability binds one
  managed bridge, one RFC1918 source `/32`, that bridge's observed gateway, one non-privileged port, and modes. It
  cannot be enabled together with the legacy aggregate `host_firewall_forward_proxy_access` contract.
- `host_firewall_expected_*` and `host_firewall_observed_*`: target identity and observed-address binding.
- `host_firewall_observed_container_bridge_gateways_ipv4`: read-only discovery evidence mapping each selected
  managed container bridge interface to its actual IPv4 gateway; generic observed host addresses cannot authorize
  DNS. Unselected managed bridges do not require evidence.
- `host_firewall_control_source_address` and `host_firewall_control_destination_port`: protected live SSH tuple.
- `host_firewall_persistent_root_config_path`: administrator-owned root file, always read-only to the role.
- `host_firewall_persistent_include_path`: the only persistent policy file owned by the role.
- `host_firewall_approved_readback_sha256`: independently approved canonical `nft --json` policy digest.
- `host_firewall_authorization_contract`: exact signed v2 productive-action envelope. It binds the target, action,
  candidate, readback, policy and egress digests, change ID, one-time claim, issue time, and expiry.
- `host_firewall_authorization_verifier_binary`: trusted root-owned verifier used for the signed envelope.
- `host_firewall_egress_policy`: complete target-specific v1 function contract. The empty default intentionally fails
  closed instead of granting generic network access.
- `host_firewall_container_dns_access`: exact container interfaces, RFC1918 source networks, and bridge-evidence-bound
  host gateway allowed to reach only the host-local Aardvark listener on TCP/UDP 53.
- `host_firewall_cis_ipv6_required`: binds the surrounding CIS IPv6 decision. Confirmation fails when that decision
  requires IPv6 while this target's egress baseline is IPv4-only.
- `host_firewall_change_id`: immutable transaction identifier.
- `host_firewall_watchdog_timeout_seconds`, `host_firewall_command_timeout_seconds`, and
  `host_firewall_lock_wait_timeout_seconds`: bounded transaction budgets. Validation requires command and lock limits
  to leave an explicit rollback margin below the watchdog.
- `host_firewall_positive_tests_passed`, `host_firewall_negative_tests_passed`, and
  `host_firewall_test_evidence_reference`: external confirmation evidence.

Deprecated aggregate variables (`host_firewall_controller_source_cidrs`, `host_firewall_recovery_source_cidrs`, and
`host_firewall_tang_consumer_cidrs`) are accepted by the interface only to return a fail-closed migration error; they
never affect the rendered policy.

## Dependencies

None.

## Example Playbook

```yaml
---
- name: Check a hardened firewall candidate with exact proxy clients
  hosts: root_of_trust
  become: true
  gather_facts: true
  roles:
    - role: lit.ubuntu.host_firewall
      vars:
        host_firewall_enabled: true
        host_firewall_action: check
        host_firewall_mode: hardened
        host_firewall_expected_inventory_hostname: root01.example.net
        host_firewall_expected_public_ipv4: 192.0.2.10
        host_firewall_expected_management_ipv4: 10.0.30.10
        host_firewall_public_interface: enp1s0
        host_firewall_management_interface: enp1s0.4091
        host_firewall_observed_ipv4_addresses:
          - 192.0.2.10
          - 10.0.30.10
          - 10.89.0.1
        host_firewall_container_interfaces: [podman1]
        host_firewall_observed_container_bridge_gateways_ipv4:
          podman1: 10.89.0.1
        host_firewall_management_access:
          bootstrap_ssh:
            port: 22
            modes: [bootstrap]
            sources_ipv4: [198.51.100.20/32]
            sources_ipv6: []
          openssh:
            port: 1905
            modes: [bootstrap, hardened]
            sources_ipv4: [198.51.100.20/32]
            sources_ipv6: []
          dropbear:
            port: 2222
            modes: [bootstrap, hardened]
            sources_ipv4: [198.51.100.20/32]
            sources_ipv6: []
        host_firewall_tang_access:
          port: 80
          sources_ipv4:
            - 192.0.2.21/32
            - 192.0.2.22/32
            - 192.0.2.23/32
          sources_ipv6: []
        host_firewall_public_service_access:
          https:
            protocol: tcp
            port: 443
            modes: [bootstrap, hardened]
            sources_ipv4: [198.51.100.20/32]
            sources_ipv6: []
        host_firewall_forward_proxy_egress:
          enabled: true
          status: approved
          mode: direct
          owner_username: proxy
          interface: enp1s0
          destinations_ipv4: [0.0.0.0/0]
          ports: [80, 443]
          residual: "Owner-bound direct egress after proxy hardening."
        host_firewall_forward_proxy_access:
          enabled: false
          port: 3128
          interfaces: []
          sources_ipv4: []
          destination_ipv4: ""
        host_firewall_forward_proxy_client_access:
          keycloak:
            interface: podman1
            source_ipv4: 10.89.0.11/32
            destination_ipv4: 10.89.0.1
            port: 3128
            modes: [hardened]
        host_firewall_egress_policy:
          schema: lit.host_firewall.egress/v1
          status: approved
          stance: deny-by-default
          ipv4_only: true
          functions:
            dns_udp:
              enabled: true
              protocol: udp
              port: 53
              modes: [bootstrap, hardened]
              interface: enp1s0
              destinations_ipv4: [1.1.1.1/32, 8.8.8.8/32]
              destinations_ipv6: []
              declared_fqdns: []
              mtls_required: false
              status: approved
              residual: ""
            dns_tcp:
              enabled: true
              protocol: tcp
              port: 53
              modes: [bootstrap, hardened]
              interface: enp1s0
              destinations_ipv4: [1.1.1.1/32, 8.8.8.8/32]
              destinations_ipv6: []
              declared_fqdns: []
              mtls_required: false
              status: approved
              residual: ""
            ntp:
              enabled: true
              protocol: udp
              port: 123
              modes: [bootstrap, hardened]
              interface: enp1s0
              destinations_ipv4: [0.0.0.0/0]
              destinations_ipv6: []
              declared_fqdns: [ntp1.hetzner.de, ntp2.hetzner.com, ntp3.hetzner.net]
              mtls_required: false
              status: transitional-port-only
              residual: "Destination IPs remain unresolved and require later tightening."
            atlas_loki:
              enabled: true
              protocol: tcp
              port: 3100
              modes: [bootstrap, hardened]
              interface: enp1s0.4091
              destinations_ipv4: [10.10.30.24/32]
              destinations_ipv6: []
              declared_fqdns: []
              mtls_required: true
              status: approved
              residual: ""
            bootstrap_https:
              enabled: false
              protocol: tcp
              port: 443
              modes: [bootstrap]
              interface: enp1s0
              destinations_ipv4: []
              destinations_ipv6: []
              declared_fqdns: []
              mtls_required: false
              status: disabled-staged-transfer
              residual: "Disabled after hardened proxy cutover."
            https_proxy:
              enabled: false
              protocol: tcp
              port: 3128
              modes: [hardened]
              interface: enp1s0.4091
              destinations_ipv4: []
              destinations_ipv6: []
              declared_fqdns: [mirror.hetzner.com, fsn1.your-objectstorage.com, api.github.com]
              mtls_required: false
              status: disabled-staged-transfer
              residual: "Controller-pull and staged transfer are used until a proxy is approved."
```

## License

MIT

## Author

Lightning IT
