# Tasks

## Active

- [ ] **Send only approved SOC security events to Cribl** - Keep raw metrics,
  raw traces, and ordinary operational container logs local for Prometheus,
  Loki, Grafana, and alert evaluation. Export a curated, versioned security-log
  contract instead of selecting whole containers or forwarding every message.
  The reviewed event classes are: sanitized LiteLLM AI request audit records
  (including the authenticated user, project/key identity, request ID, model,
  prompt/completion content, outcome, token use, and cost); Keycloak
  authentication and authorization success/failure events, lockouts, access
  denials, and privileged changes; immutable Envoy provider-policy, CA
  fingerprint, SAN, SNI, startup-gate, and TLS trust events; provider-key
  rotation, Vault seal/unseal and HMAC-protected audit events, break-glass use,
  LDAP/identity drift or sync failures, and other explicit security-gate
  failures. Do not send metric alerts through this log contract. Do not mistake
  general stdout for a complete or safe audit trail. Add a structured emitter
  when an event cannot be classified reliably.
  - Filter the Cribl branch in Alloy with a fail-closed event-class allowlist
    before the persistent export queue. Use Cribl Stream's native OTLP input
    over verified TLS for a real endpoint; plaintext remains legal only for the
    namespaced preprod mock. Reject an untrusted CA, a server-name mismatch, an
    invalid endpoint, a malformed event, or an event outside the allowlist.
    Redact passwords, tokens, authorization headers, cookies, provider keys,
    and any other secret before export. Prompt and completion bodies are an
    explicit sensitive exception and must carry the authenticated attribution
    fields and documented retention warning. Never export raw OTLP traces or
    metrics.
  - Bound the gateway's Cribl delivery queue to 24 hours and require the Cribl
    team to set a 24-hour destination retention policy. Treat queue pressure as
    a metric-driven operations alert through the separate Alertmanager path;
    never feed Alloy's own exporter-error logs or alert payloads into Cribl.
    Keep Prometheus metrics locally for 30 days. Document and size its byte
    limit because Prometheus applies the time or size limit that is reached
    first.
  - Add contract tests and a seeded local-preprod receipt test proving that each
    approved security-event class arrives and that raw metrics, raw traces,
    malformed records, and ordinary non-security service logs do not. Test TLS
    trust failure, queue outage/recovery, redaction, and allowlist rejection.
  - Create or update a plain-language logging-team handoff. It must define the
    versioned event/field contract, data classification, prompt-content warning,
    redactions, Alloy ownership, OTLP/gRPC endpoint and port, CA and TLS
    server-name requirements, firewall path, persistent queue, retry and
    overflow behavior, Cribl-side source/routes, retention and access-control
    expectations, receipt checks, outage/recovery test, troubleshooting steps,
    and team ownership. Update the observability architecture, security model,
    operator runbook, diagrams, links, anchors, and navigation. State clearly
    what stays local, what leaves the host, and why. Create any missing document
    or diagram and write it at about an eighth-grade reading level.
## Waiting On

- [ ] **GitHub history and owner cleanup decision** - Forward-tree cleanup is in scope now. Removing personal author metadata from old commits or changing the repository owner requires an explicit repository transfer/history-rewrite decision.

## Someday

- [ ] **Immutable, provider-selectable Envoy egress image builds** - Replace
  the hard-coded Envoy build configuration with a reviewed,
  immutable build-time provider-selection design. A future developer must be
  able to implement this task from this entry without relying on the original
  conversation.
  - **Operator interface:** Accept repeated provider selections while preparing
    the offline seed. The intended command shape is:

    ```bash
    python3 -I scripts/update-images.py prepare \
      --provider anthropic \
      --platform linux/amd64 \
      --archive /release/aigw.docker.tar.zst \
      --manifest /release/aigw.manifest.json
    ```

    Canonicalize provider ordering, handle duplicate arguments safely, and
    reject unknown providers and an empty selection. Never accept an arbitrary
    provider hostname or CA path through the CLI.
  - **Reviewed provider catalog:** Resolve every provider name through a
    committed, reviewed catalog. Each entry must contain the provider name, API
    hostname, Envoy route prefix, SNI requirement, exact SAN requirement,
    reviewed CA bundle, and expected SHA-256 fingerprint for every CA
    certificate. Adding a provider requires a reviewed catalog change and a new
    release build.
  - **Immutable and reproducible build:** Keep the Docker build network-disabled
    and reproducible. Ansible must never discover or download CA trust material
    during deployment. Put only the selected providers' routes, policy, and CA
    bundles in the final Envoy image. Identical canonical selections must
    reproduce the same policy inputs, while different selections must produce
    different immutable image IDs.
  - **Fail-closed startup gate:** Refuse startup when selected CA material is
    missing, unexpected, malformed, expired, or does not match the reviewed
    fingerprints. Validate the configured hostname, SNI, and exact SAN rules as
    part of the gate. Do not silently fall back to host or system trust.
  - **Schema-v2 release record:** Record the canonical selected providers,
    provider hostnames, CA certificate fingerprints, generated egress-policy
    digest, and final Envoy image ID in the schema-v2 offline-seed manifest.
    Make the Envoy image and provider policy one release unit for seed loading,
    remote upgrade, validation, and rollback.
  - **Offline and preprod proof:** Load the exact generated image through the
    offline-seed loader and exercise it in the full local preprod validation.
    Remote promotion must validate that exact image and policy. A failed
    validation must restore the previous Envoy image and matching provider
    policy together.
  - **Trusted CA maintenance:** Capture CA certificates only through a separate,
    trusted release-maintenance procedure with recorded provenance verification,
    review, and approval. Document CA rotation as a catalog update followed by a
    new release build, seed, validation, and rollback rehearsal. State clearly
    that a certificate subject containing `C=US` and a matching hash proves
    certificate integrity only; it does not prove original trust provenance,
    endpoint geography, US data residency, or where a provider processes data.
  - **Documentation:** Find and correct any claim that provider CA bundles are
    runtime-mounted placeholders; the current design bakes reviewed bundles into
    the image. At about an eighth-grade reading level, document why provider CA
    bundles are immutable, how operators select providers, how a provider is
    added and reviewed, how CA rotation works, how selection changes the offline
    seed, and how validation and rollback work. Explain the differences among
    certificate integrity, the CA organization's country, endpoint geography,
    and data residency. Update the architecture documentation, image-update
    workflow, deployment and operator runbooks, security model, and
    provider-onboarding documentation. Create any missing required document and
    include direct commands and examples.
  - **Diagrams and navigation:** Review every architecture and deployment
    diagram for consistency. Add or update diagrams for: (1) provider selection
    through catalog validation, immutable Envoy build, and offline seed; (2) the
    runtime request path through Envoy to selected vendors; (3) CA capture,
    review, rotation, and the release-approval boundary; and (4) offline-seed
    deployment, validation, and rollback. Create missing diagrams. Verify all
    diagram labels, internal links, anchors/bookmarks, and navigation between
    related pages.
  - **Contract and security tests:** Cover repeated `--provider` arguments,
    canonical ordering, duplicates, unknown providers, and empty selections.
    Prove arbitrary hostnames and CA paths are rejected. Test CA fingerprints,
    expiration, SAN, SNI, and every fail-closed startup condition.
  - **Build and contents tests:** Prove identical canonical selections produce
    deterministic build inputs and policy output; prove different selections
    change both policy and image identity. Inspect the final image to confirm
    that only selected routes and CA files are present.
  - **Release acceptance:** Add offline-seed manifest and loader contract tests,
    run a full local preprod test from the generated seed, and validate
    documentation links and diagram references. The task is complete only when
    all tests pass and the tested artifacts show the Envoy image ID and policy
    digest promoted and rolled back as one unit.
- [ ] **Rewrite all documentation at an 8th-grade reading level** - Separate
  preprod and production paths and rewrite every active page in direct,
  eighth-grade-level language with working commands and examples. Review and
  update every architecture, deployment, identity, networking, security,
  upgrade, rollback, and operator diagram. Verify every bookmark, heading
  anchor, internal link, external hyperlink, table of contents, and navigation
  path, and add automated link and diagram-reference checks. Create any missing
  page, diagram, index, or navigation aid needed for a complete operator path.
  Remove or archive obsolete, duplicate, contradictory, or unsupported material
  and repair every inbound link to it. This remains the repository-wide audit;
  provider-specific documentation and diagrams belong to the immutable Envoy
  task above so the work is not tracked twice. Completion requires a clean
  generated link/reference report and a manual review that diagrams match the
  deployed preprod and production designs.
  - Add one plain-language testing section that explains the purpose and order
    of unit tests, contract tests, integration tests, end-to-end tests, real
    browser tests, and the final release-acceptance gate. Show which checks run
    in GitHub Actions and which require local Docker or a dedicated self-hosted
    runner. Do not call a release tested when a credential or runner limitation
    caused a required stage to be skipped.
  - Document the exact final rehearsal: build new production and preprod
    offline-seed archives from reviewed pins and provider selections; destroy
    the namespaced preprod containers, volumes, networks, and old seed
    activation files; load the new preprod archive; deploy it with Ansible in
    seed mode with pulls and source builds disabled; run service, LDAP/LDAPS,
    Root CA, Vault, WIF, Keycloak/OIDC, role, upgrade, validation, and rollback
    checks; then use a real browser to test portal login, redirects to and from
    Keycloak, cookies, logout, allowed roles, and denied roles. Include the
    commands, expected success markers, evidence to save, and failure steps.
- [ ] **Run a full security audit** - Review the complete codebase and run Trivy against source plus every exact upstream and custom container image. Record fixes, waivers, SBOMs, provenance, and remaining risk.
- [ ] **Add proactive capacity alerts to the Grafana dashboard** - Build
  this after the current release work is complete. Docker health checks only
  mark one container healthy or unhealthy; they do not forecast host pressure
  or show an operator what needs attention. Keep the reviewed Prometheus rules
  as the only source of alert evaluation. Use Alertmanager for grouping,
  deduplication, inhibition, and resolved lifecycle state, and show active and
  recently resolved alerts in Grafana. The Grafana dashboard is the approved
  destination; do not require email, Slack, Teams, or another external
  receiver. This operations-alert path is separate from the Cribl security log
  export: never send alert payloads through the SOC log schema.
  - Keep the existing scrape-down, telemetry-queue, filesystem-low,
    filesystem-critical, and 24-hour disk-exhaustion forecast rules. Add
    reviewed warning and critical rules for CPU/load saturation, memory and
    swap pressure, OOM events, filesystem inode pressure, disk latency and I/O
    saturation, network errors/drops/throughput saturation, connection-table
    pressure, repeated container restarts or unhealthy containers, service
    latency/error-rate burn, certificate expiry, failed backups, and a sealed
    Vault after reboot. Add only signals that the hardened deployment can
    collect without exposing the Docker socket or weakening a network boundary.
  - Define clear thresholds, hold times, severity, owner, runbook link,
    deduplication, inhibition, grouping, and recovery behavior. Prefer trend
    and exhaustion forecasts where they give useful warning before a failure.
    Avoid high-cardinality labels and alert storms. Use warnings for conditions
    trending toward failure or needing correction, and critical alerts for a
    failed, unavailable, or unsafe state that needs immediate action. Preserve
    and display resolved state after recovery, including for Cribl exporter
    backpressure.
  - Add a dead-man/watchdog rule and dashboard panel so a silent Prometheus to
    Alertmanager to Grafana path is visible. Bind both APIs only to their
    private observability network and expose no unauthenticated host port.
  - Add Grafana capacity and active-alert views for the same rules; do not
    create a second set of conflicting Grafana-managed alert rules. Update the
    observability architecture, operator runbook, troubleshooting steps, and
    a short response runbook for every alert class at about an eighth-grade
    reading level.
  - Add contract tests for the exact rule and alert-lifecycle graph, Prometheus
    rule validation, and preprod fault-injection tests for disk, CPU, memory,
    network, container-health, Vault-seal, and Grafana dashboard paths. Record
    which host-level signals local Docker Desktop preprod cannot faithfully
    prove. Do not claim those host-only checks passed based on Docker Desktop
    results, and do not require a separate rehearsal VM.
- [ ] **Rehearse the PostgreSQL 18 migration with production-sized data** -
  The source now pins PostgreSQL 18.4 and includes the separate, fail-closed
  logical migration workflow, fresh-volume cutover, validation, bounded
  pre-write rollback, and plain-language SOP. The general image updater still
  refuses major changes. A bounded ARM64 check on 2026-07-21 proved that the
  exact DHI PostgreSQL 17.10 and 18.4 images both work with the current
  database setup, LiteLLM, Keycloak, key-rotator, Grafana access rules,
  PostgreSQL 16 logical restore, and same-major physical restore. PostgreSQL
  18.4 is stable, and the operator selected it. This check is useful evidence,
  but it is not the full seeded preprod rehearsal. Finish this item by building
  PostgreSQL 18 into the
  exact offline seed, proving a clean preprod start, migrating production-sized
  PostgreSQL 16 test data, testing all database consumers, forcing both a safe
  pre-cutover rollback and a refused post-cutover downgrade, and rehearsing a
  same-major PostgreSQL 18 physical restore. Git history contains no recorded
  technical reason for the original PostgreSQL 16 choice; describe any claim
  beyond that as an inference.
- [ ] **Upgrade every DHI and upstream image to its newest supported stable release** -
  Check the authoritative upstream and DHI catalogs for every base and runtime
  image. Pin each approved release by an exact version and digest; never use a
  moving `latest` tag. Record the version, support status, selection reason,
  and provenance. If a newer image changes its user, paths, health checks,
  configuration, storage layout, or other runtime contract, update the
  Compose/Ansible integration to match the image instead of holding an older
  version without evidence. Build, scan, load from the offline seed, and run
  the full local preprod suite for every promoted image before the production
  release can pass.
  - Update the image-update SOP and operator runbook with the complete engineer
    workflow: identify whether the exact pin belongs in Compose, a Dockerfile,
    or a Compose build argument; review upstream compatibility and security
    notes; change the Git-tracked `tag@sha256:digest`; update configuration and
  health checks for the new image contract; run `scripts/update-images.py
    prepare` with selected providers and the seeded preprod option; require the
    full stack to pass from the generated preprod archive; and promote only the
    generated production-scoped archive through the remote upgrade/rollback
    command. State clearly that generated schema-v2 manifests are immutable
    outputs and are never hand-edited as the image-selection input. Include
    direct commands, expected success markers, failure handling, and the dated
    production/preprod artifact naming convention at an eighth-grade reading
    level.
  - Treat the software inside each image as part of the same update. Review the
    newest supported stable Python and Go toolchains, regenerate Python locks
    for the selected Python version, verify every exact direct and transitive
    dependency, keep `go.mod` versions aligned with the builder, and review the
    pinned Ansible, test, lint, security, and CI tools. Record why any component
    is held below the newest stable release. Run Python service tests and lint,
    Go race tests and vet, network-disabled Docker builds, source/container
    Trivy scans, and the full seeded preprod suite before promotion.

## Done

- [x] ~~Run the final current-source schema-v2 seed rehearsal~~ (2026-07-21)
  - Release r10 built a 40-image ARM64 production archive and a 43-image
    preprod archive with Anthropic as the only selected provider. The
    production manifest excludes the two preprod-only images.
  - The clean-room play removed 26 owned containers, 19 owned networks, 11
    owned volumes, and 43 old release image IDs. It preserved 129 unrelated
    image IDs. The fresh load and one Ansible seed-mode deploy ended with
    `PREPROD_CLEAN_ROOM_OK`, `PREPROD_E2E_PASSED`, and
    `SEEDED_PREPROD_E2E_PASSED`.
  - Production archive SHA-256:
    `958ee15a3609a9bdee13d7144b941cbb4379136b1d674103f5ae887bf04cd453`.
    Production manifest SHA-256:
    `0960fab4f0133cf4be610c8e552a554eb3d795d5114bb108201243deb90c3da7`.
    Preprod archive SHA-256:
    `73e244dc6fc6fd347f7b8711a8710b586f554c603bcb1c4e0a3ca5938f0ad7e8`.
    Preprod manifest SHA-256:
    `80173e1a67fcb0997fd90572a1f1e8087d22ecd9a2438038f33f1191d93d7d02`.
  - The exact seeded portal image contains the automatic-setup wording. A
    later comment-only provider wording change was reconverged against the
    same seed and passed the full acceptance and Cribl recovery gates again.
  - After the documentation overhaul, the same `r10` preprod archive passed a
    second full clean-room load and one Ansible seed-mode deploy. Pulls and
    source builds stayed disabled, all three success markers returned, and all
    25 long-running containers were healthy.
- [x] ~~Run the credential-gated release rehearsal~~ (2026-07-21)
  - Release r7 built a schema-v2 ARM64 production archive with 40 images and a
    preprod archive with 43 images. The clean-room play removed only the owned
    project and all 43 old release image IDs while preserving 55 unrelated
    image IDs. It then freshly loaded the preprod archive and deployed it with
    Ansible in seed mode. The run ended with `PREPROD_E2E_PASSED` and
    `SEEDED_PREPROD_E2E_PASSED` after Vault, LDAPS, automatic Keycloak setup,
    static users, OIDC roles, WIF, the immutable production Envoy startup gate,
    and local mock inference passed.
  - Production archive SHA-256:
    `74b6d1df3325863c3bc7dc218edd97faa231dbac7bd2ea83553b6d48ea625c66`.
    Production manifest SHA-256:
    `6d8003c40053ef7bd0788309f40d2f3d60999b31da63d1421d735b3d05328e0c`.
    Preprod archive SHA-256:
    `cd19310e9e3a496871a706bdc0d97b0fb4a59744bb8ce9d12979c3935f154a0c`.
    Preprod manifest SHA-256:
    `0012ec5faa4febcc59b29704a81d3a657a15f7e20c27b0427dee4635dd74511b`.
- [x] ~~Finish the production-safe image release and upgrade workflow~~
  (2026-07-21)
  - One build now emits a full preprod release and a production-only
    projection. The loader and remote staging path reject a preprod-scoped
    release, verify every checksum and image ID, and keep image plus state
    rollback fail closed. Contract tests cover source-tag materialization,
    exact transfer IDs, preprod-byte rejection, validation, and rollback.

- [x] ~~Authenticate to DHI and build the exact schema-v2 release seed~~
  (2026-07-21)
  - The ARM64 seed contains 24 exact external images and 19 repository-built
    images. Its archive and manifest checksums pass the schema-v2 local release
    receipt. Loading and full live preprod validation remain active above.
- [x] ~~Replace the old lab with local Docker preprod~~ (2026-07-21)
  - Ansible now owns the fixed `aigw-preprod` project, `aigw.internal`, three
    host planes, isolated service networks, persistent test Root CA, Samba AD
    LDAPS, WIF mock, static test identities, verify, and confirmed destroy.
  - This records implementation and static/contract validation. The real
    seeded live rehearsal remains active above.
- [x] ~~Automate identity setup and domain-derived OIDC clients~~ (2026-07-21)
  - The admin-portal initialization step is gone. Ansible configures and checks
    LDAP federation, controller authority, escrow, temporary-admin cleanup,
    redirect URLs, origins, logout URLs, and WIF issuer URLs from the supplied
    domain, including brownfield repair.
- [x] ~~Finish all verification that does not require DHI credentials~~ (2026-07-21)
  - The stable tree passes 601 infrastructure tests, Compose and identity
    validation, service tests, Go race/vet, ShellCheck, yamllint, Ruff, Bandit,
    Samba image tests, and an independent preprod security review.
- [x] ~~Add and verify the post-reboot Vault unseal SOP~~ (2026-07-21)
  - The SOP uses the normal Ansible converge so the encrypted controller-held
    share travels on stdin with pipelining enabled; commands, links, and
    fail-closed checks are covered by contracts.
- [x] ~~Simplify active operator documentation and this implementation~~ (2026-07-21)
  - Current preprod and production paths are separate, the main runbook was
    shortened, and 171 active relative links/bookmarks were checked.
  - The broader reading-level and diagram audit stays in Someday below.

- [x] ~~Fix production bootstrap usability~~ (2026-07-20)
  - A no-argument terminal run now opens a guided setup; a non-interactive run prints all three required flags and a working example.
- [x] ~~Remove prohibited identifiers from the forward tree~~ (2026-07-20)
  - Customer domains, personal handles, personal home paths, and branded filenames were removed; a CI contract now prevents them from returning.
  - Git history and repository ownership remain the separate decision above.
- [x] ~~Remove the confirmed Parallels AI Gateway VM and its dedicated networks~~ (2026-07-20)
  - The unrelated Windows VM and unrelated Docker containers were left alone.
- [x] ~~Move the old Parallels lab build and disaster-recovery directories to Trash~~ (2026-07-20)
  - They remain recoverable until Trash is emptied.
- [x] ~~Retire remaining confirmed local lab credentials, seed, CA, DR key, and VM SSH host keys~~ (2026-07-20)
  - Exact artifacts were moved to `~/.Trash/aigw-retired-lab-20260720`; ambiguous or unrelated local files were not touched.
