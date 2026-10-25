# Release Model

This repository follows the Lightning IT shared release and quality model.

## Repository Classification

- Repository: `ansible-collection-ubuntu`
- Type: `ansible_collection`
- Release type: `ansible_galaxy`
- Artifact type: `ansible_collection_tarball`
- Visibility: `public`
- Release evidence: `enabled`
- Heavy Incus release validation: `required`

## Branch Flow

- `develop` is the integration branch for normal work, Renovate updates, and centrally managed synchronization.
- `main` is the protected release branch.
- Releases happen only after `main` is updated.
- A `develop` to `main` promotion PR is created automatically when releasable changes exist.
- The `develop` to `main` PR is a manual gate and must never be auto-merged.
- After `main` changes, a `main` to `develop` backmerge PR is created or updated automatically.
- When a promotion creates a `main`-only merge commit, the backmerge must preserve
  that commit's ancestry even if the `main` and `develop` trees already match;
  otherwise strict up-to-date protection keeps the next promotion PR behind.
- Integration and backmerge PRs may auto-merge only after required checks pass, all review conversations are resolved, and there are no conflicts.

## Mandatory Quality Gates

- Required profiles: `pre-commit, lint, light, molecule-light, molecule-heavy-incus, release-validation`.
- OS matrix: `ubuntu-latest, ubuntu-lts`.
- Product/runtime matrix: `ansible-core, molecule, incus`.
- Fork pull requests run validation without publishing credentials.
- Publishing secrets are available only to trusted `main` release workflows.
- GitHub token permissions must stay least-privilege for each workflow.

## Ansible Collection Release

- Version is maintained in `galaxy.yml`.
- Changelog fragments are managed with `antsibull-changelog`.
- Nexus is the development/candidate Galaxy V3 registry; `galaxy.ansible.com` is production.
- The production target for every current and future Collection is immutable Nexus candidate -> impact-based central validation -> identical bytes to Galaxy.
- Build exactly once with `ansible-galaxy collection build`; bind the source commit, semantic version, filename, SHA-256, signature, SBOM, provenance, scan results and policy identity to that candidate.
- Central validation fetches the exact Nexus digest and executes the affected Heavy role families, followed by Application Acceptance. Promotion never rebuilds or repacks the artifact.
- GitHub Releases use predictable `v<version>` tags.
- Galaxy publication for `lit.ubuntu` requires the admitted production route, exact candidate evidence and applicable genuine one-person approval. A manual workflow start cannot authorize a production release.
- The separately admitted Security route remains reviewer-free with `humanActions=0`; it does not waive its native Security gates.
- Source pull requests use the unprivileged Fast lane. Central validation owns privileged Heavy/Application execution, cleanup and evidence; source tests do not acquire central publishing credentials.

## Operating Transition and Cutover

Existing direct-to-Galaxy publishers remain an explicitly documented operating transition until their actual per-Collection cutover is accepted. This target documentation does not claim that Nexus intake or central promotion has already been deployed.

The central `transition-noop` only prints the future promotion command and records `validated=false` and `release_eligible=false`. It performs no Heavy/Application execution and no Galaxy publication; successful no-op completion is non-release-capable and never release acceptance.

Developers and customers reproduce candidates through their privately configured Nexus server alias, exact semantic version and a clean install path. Verify the downloaded SHA-256 before installation, pin dependencies and never silently fall back to Galaxy or an unpinned latest version. Candidate access does not grant production publication authority.

Before each Collection cutover:

- Record its actual protected source, common workflow and policy revisions, current transition, accountable owners and unresolved implementation work.
- Prove complete authoritative repository visibility and selected-repository App onboarding. An organization-wide baseline/installation does not grant role-scoped privileged environments, secrets or production rights; new Collections need their own authenticated admission.
- Record exact App/installation identity and environment-scoped credential ownership privately. Release Automation dispatch, candidate write/read access, central role execution, Galaxy publishing and evidence archival use separate least-privilege responsibilities.
- Bind explicit numeric job and polling timeouts for build, staging, affected Heavy/Application cells, cleanup, promotion and readback. Superseded validation must retain its canceled result and perform cleanup; an unknown publication outcome never permits a blind retry.
- Exercise missing/mismatched digests, signatures, scans, source/policy identity, expired evidence, failed/skipped/canceled cells, cleanup/API/pagination failures, unauthorized/manual publication and conflicting-version negative cases.
- Publish only the validated Nexus bytes. Download the Galaxy artifact and prove its SHA-256 equals the original candidate; then perform clean installation and the supported FQCN smoke test.
- Verify same-version/same-digest idempotency only after authoritative readback. The same version with another digest fails; published bytes are never overwritten. Corrections use a new version and retained revocation evidence.
- Sign and independently verify the final receipt and complete seven-year immutable evidence archive. GitHub Actions artifact retention alone does not satisfy that requirement.
- Run a new current-head end-to-end operation after the final material change. Read back installed workflows, actual native approvals/results, published bytes and archive retention before claiming cutover acceptance.

The documented target applies to every Collection; a local source change, green Fast job or transitional receipt cannot establish production readiness.

## Release Evidence

Release evidence is generated by CI when enabled for this repository. Evidence records the repository name, repository type, version, tag, commit SHA, workflow run, tested matrix combinations, passed/failed/skipped jobs, built artifacts, published artifacts, changelog link, security scan result, and SBOM/provenance/signature links when available.

Evidence files must not contain tokens, credentials, private inventory values, or secret material.
