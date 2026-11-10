# local_mail

## Requirements

Ubuntu 24.04, Root and an exact approved Postfix package version. The default is
disabled. First initialization requires `local_mail_initialize: true`, no active
Postfix master, no queued mail and no unknown ownership directory. An existing
mail installation is never silently adopted. This role owns both configuration
files once initialized; subsequent drift fails before package or service changes.

The candidate has no SMTP network listener, SMTP/LMTP outbound delivery agent,
aliases, `.forward`, command/file redirection or external relay. Native
sendmail-compatible submission and local UNIX mailbox delivery remain available.
The ownership guard does not read mailbox contents. Existing mail is preserved.
Queue lifetime and message/mailbox limits are bounded; an independent disk/queue
alarm and recipient acknowledgment remain separate operating requirements.

## Variables

See [defaults/main.yml](defaults/main.yml). Enable explicitly and supply
`local_mail_package_version`. `local_mail_install_packages: false` requires the
exact package to be preinstalled. `local_mail_manage_service: false` configures
and checks owned files without starting or stopping a service. Package
installation blocks automatic service activation until configuration is sealed.
For an offline target, `local_mail_package_file` selects one prepared Root-owned
Postfix `.deb`; `local_mail_package_sha256` and the exact version are mandatory.
The caller must authenticate and stage that package and its dependencies through
the normal artifact path. The role checks bytes/name/version and consumes the
prepared file; it does not discover mirrors, download alternatives or generate
credentials. Required dependencies must already be available on an offline target.
Check mode does not install missing dependencies or prove delivery; use the
actual native installation, unchanged second apply and mailbox readback.

## Dependencies

Ansible builtins only. No SMTP credentials or external notification service.

## Example Playbook

```yaml
- name: Preserve the disabled default until an approved version is supplied
  hosts: mail_targets
  roles:
    - role: lit.ubuntu.local_mail
      local_mail_enabled: false
```

This example is intentionally disabled. Clean installed collection consumers
have exercised the role against isolated Ubuntu 24.04 x86/KVM VMs: fresh
installation, an owned configuration correction, actual Root mailbox readback,
external-recipient refusal with a local bounce and an unchanged second apply
without repeated submission passed. A separate native full-mailbox test observed
Postfix's size-limit rejection, preserved the pending alarm and dispatch intent,
and restored the synthetic mailbox. These are isolated component proofs.

Postfix requires process limit `0` for cleanup and bounce services; these mandatory
services do not have a global process-count bound from this role. Neither service
start nor sendmail exit zero alone establishes notification delivery. Live sender
and scheduler integration, rollout and full operating acceptance remain open.

## License

MIT

## Author

Lightning IT
