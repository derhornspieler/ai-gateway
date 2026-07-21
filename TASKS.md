# Tasks

## Active

- [ ] **Finish `r13` visual browser acceptance** - Candidate `r13` was built
  from pushed commit `15e47d6d48a82a05281b386f3446bbbd1760d455`. Its exact
  preprod pair passed clean-room purge, fresh archive loading, one Ansible
  seed-mode deploy, and the full integration and end-to-end gate. The receipt
  removed 26 containers, 19 networks, 11 volumes, 62 aliases, and all 43 target
  image IDs while preserving 185 unrelated IDs. Pulls and source builds stayed
  off. All 25 long-running containers were healthy on the exact manifest image
  IDs. The run ended with `PREPROD_CLEAN_ROOM_OK`, `PREPROD_E2E_PASSED`, and
  `SEEDED_PREPROD_E2E_PASSED`.

  The exact Open WebUI runtime image is
  `sha256:83cf446e3f3fffb5c99c2f8d8a09e59e1c3b9c5c5c65d4836692caf28c294792`.
  It was healthy, and its hardened-path gate passed.

  After a Vault restart, the test proved `initialized=true` and `sealed=true`.
  A second identical seed-mode converge auto-unsealed Vault and passed the full
  end-to-end and Cribl tests again. The visual browser replay could not run
  because the current test runtime exposed no browser. Run that replay when a
  browser is available.
  Keep the `r10` Chrome result as historical evidence; do not use it as `r13`
  proof.
- [ ] **Finish the approved Cribl security-event feed** - Alloy now sends a
  small, versioned security feed over verified OTLP/gRPC TLS. Raw metrics, raw
  traces, alerts, ordinary service logs, and the raw Vault audit file stay
  local. The persistent queue is capped at 2 GiB and retries a dequeued batch
  for up to 24 hours. Prometheus stays local with a 30-day and 5 GB cap.

  - **Implemented event paths:** AI request audit, the exact Keycloak
    authentication event list, reviewed portal actions, identity deployment
    success/failure, deployment break-glass use, provider-rotation terminal
    result, Vault state, bounded Vault audit metadata, Envoy startup success or
    failure, and selected-provider TLS failure.
  - **Fixed-field boundary:** Alloy rebuilds structured records from approved
    scalar fields. It never exports the source JSON, an unknown field, a nested
    value, or an unparsed fallback. The Anthropic startup record contains the
    policy digest, provider, SNI, exact SAN, and reviewed CA fingerprints. The
    Envoy image ID is correlated from the verified manifest and live Docker
    inspection; it is not self-embedded in the image event.
  - **Current test evidence:** the preprod Docker-log records are synthetic
    classifier fixtures. They prove allow, deny, fixed-field, unknown-field,
    and nested-secret behavior. The AI request follows Alloy's real OTLP path,
    and the Vault audit check follows the real Vault file path. Verified TLS,
    wrong-server-name rejection, queue outage/recovery, and Alloy restart also
    pass. Do not use a synthetic fixture as proof that a live producer emitted
    an event.
  - **Prompt-value redaction gap:** Alloy redacts three tested credential forms
    from the four reviewed string fields: named credential assignments, Bearer
    or Basic tokens, and `sk-` or `sk-ant-` keys. It now removes a non-string or
    nested value before spanlogs can copy it to Loki or Cribl. Still add narrow,
    reviewed string patterns for other supported secret formats. Do not use a
    generic high-entropy rule that would destroy useful prompt records.
  - **Attribution gap:** AI request export now requires bounded user ID, user
    name, key hash, project ID, and request ID fields. Still prove source
    authenticity and readable-name quality for chat, direct API, and every
    supported client path. `aigw.user.name` is readable attribution, not an
    authorization fact. Keep stable subject, key, and project evidence
    separate.
  - **Source-authentication gap:** the shared OTLP listener trusts a caller's
    `service.name=litellm` attribute. A peer on the telemetry network can spoof
    an AI request record. Add a dedicated authenticated LiteLLM ingest path,
    stamp a server-owned source marker, require that marker in the AI filter,
    and prove another container cannot forge it. Do not accept a caller-owned
    attribute as proof of source.
  - **Common-record gap:** the handoff expects a recent UTC time, fixed
    environment, producer, and schema on every record. The current projection
    does not enforce all four fields for every event class. Add fixed
    `preprod`/`production` values, a reviewed producer name, and recent-time
    checks. Test every record class and reject a zero or stale timestamp.
  - **Event gaps:** add a reviewed sender for controller-only events; provider
    rotation start, attempt, rollback, and recovery; application authorization
    denials and uncovered privileged changes; LDAP and managed-identity drift,
    reconcile failure, and recovery; and break-glass activation, disable, and
    cleanup. Add natural producer receipt tests for every new event.
  - **External acceptance:** the Cribl/SOC team must supply the approved
    endpoint and CA, repeat the wire and field receipt, enforce and prove
    24-hour destination retention, and decide whether the gateway also needs a
    hard per-record 24-hour queue age. Keep queue alerts on the local metrics
    path; never send alert payloads through the SOC feed.

## Waiting On

- [ ] **Add approved DHI credentials to GitHub release scans** - The
  credential-independent `main` jobs are green. The release image jobs stop at
  the required credential gate before their raw Trivy records and blocking
  VEX-aware Scout checks can finish because the protected
  `release-container-security` environment has no `DHI_USERNAME` or
  `DHI_PASSWORD` secret. A repository administrator must add approved
  credentials and rerun the failed jobs. Do not copy a developer's local login
  into GitHub or weaken the gate without explicit approval.
- [ ] **Run the Rocky Linux 9 deployment, upgrade, and rollback test** - The
  operator requested this test, but no reachable Rocky VM exists. The old
  `10.8.10.10` VM and its dedicated networks were removed. Get an existing
  three-NIC Rocky Linux 9 target or approval to create a new VM and networks.
  Then use the newest production-scoped release that passes every local and CI
  gate. Run bootstrap, preflight, the two-pass Ansible converge, validation,
  guarded upgrade, forced validation failure, and rollback. Keep Anthropic
  enrollment as a separate operator step after the platform and identity proof.
  Never send the preprod-only image pair to production.
- [ ] **Complete the customer Cribl acceptance ceremony** - The local TLS mock,
  allow-list, redaction, queue outage, and recovery tests pass. The Cribl/SOC
  team must supply its approved endpoint and CA, enforce and prove 24-hour
  destination retention, and decide whether a hard per-record 24-hour limit is
  also required on the gateway queue.
- [ ] **GitHub history and owner cleanup decision** - Forward-tree cleanup is in scope now. Removing personal author metadata from old commits or changing the repository owner requires an explicit repository transfer/history-rewrite decision.

## Someday

- [ ] **Finish external acceptance for immutable, provider-selectable Envoy
  releases** - The reviewed catalog, repeated `--provider` interface,
  network-disabled image build, baked CA bundles, startup gate, schema-v2
  release record, loader contracts, documentation, diagrams, and exact seeded
  local preprod proof are complete. Release `r10` selected only `anthropic` and
  reproduced the same Envoy image ID twice. Candidate `r13` also selects only
  `anthropic` and passed the exact seeded local preprod gate. Its policy digest
  is `8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`,
  and its Envoy image ID is
  `sha256:04f3d74c450509bdf288ec64fdbee584e616522f503428a3699442a48b8cc08f`.
  Its visual browser replay is still active above. Keep the full design below
  so a future developer can finish the remaining protected GitHub image scan
  and approved remote promote/validate/rollback proof without this
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
- [ ] **Finish the credential-gated security audit** - Local quality, security,
  dependency, CodeQL, secret-scanning, and release-contract gates are green.
  GitHub still must run Trivy against the source and every exact upstream and
  custom image after an administrator supplies the protected DHI credentials.
  Record fixes, waivers, SBOMs, provenance, and remaining risk; do not describe
  a credential-blocked scan as passed.
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
  18.4 is stable, and the operator selected it. Release `r10` then put the exact
  PostgreSQL 18 image in both seeds and passed two clean seeded preprod starts
  with every database consumer healthy. Finish this item with
  production-sized PostgreSQL 16 test data, a forced safe pre-cutover rollback,
  a refused post-cutover downgrade, and a same-major PostgreSQL 18 physical
  restore on an approved production-like host. Git history contains no recorded
  technical reason for the original PostgreSQL 16 choice; describe any claim
  beyond that as an inference.
- [ ] **Finish protected scans for the newest supported image release** - The
  authoritative upstream and DHI catalog review, exact version-and-digest pins,
  compatibility fixes, software/toolchain review, network-disabled `r13`
  builds, and exact seeded local preprod checks are complete. The visual `r13`
  browser replay is still active above. The release cannot pass until that
  replay is complete and GitHub builds and scans every final image with
  protected credentials. Save raw Trivy JSON, VEX-aware Scout results,
  waivers, SBOMs, provenance, and remaining risk.
  - Update the image-update SOP and operator runbook with the complete engineer
    workflow: identify whether the exact pin belongs in Compose, a Dockerfile,
    or a Compose build argument; review upstream compatibility and security
    notes; change the Git-tracked `tag@sha256:digest`; update configuration and
    health checks for the new image contract; run
    `scripts/update-images.py prepare` with selected providers and the seeded
    preprod option; require the
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

- [x] ~~Rewrite and verify all active documentation and diagrams~~ (2026-07-21)
  - All 48 active documentation pages now separate preprod from production and
    use short, direct operator language at about an eighth-grade reading level.
    Obsolete lab material is archived and labeled as non-operational.
  - Architecture, deployment, identity, network, security, provider, release,
    Cribl, PostgreSQL, Vault, and testing diagrams and procedures match the
    deployed design. The automated link, anchor/bookmark, navigation, and
    Mermaid-reference validator is green.
  - The test runbook explains unit, contract, integration, end-to-end, browser,
    and final release gates.
- [x] ~~Run real-browser release acceptance~~ (2026-07-21)
  - System Chrome followed the domain-derived redirects between the developer
    portal, admin portal, Open WebUI, Grafana, and Keycloak.
  - The developer and administrator reached their allowed pages. The normal
    user and developer received the expected denied-role pages. Chat SSO worked
    for the normal user, and Grafana SSO worked for the administrator.
  - Application and Keycloak identity cookies were secure and host-bounded.
    Logout cleared both application and Keycloak sessions, and Back plus
    Refresh did not reopen the protected developer page.
- [x] ~~Run the `r10` schema-v2 seed rehearsal~~ (2026-07-21)
  - Release r10 built a 40-image ARM64 production archive and a 43-image
    preprod archive with Anthropic as the only selected provider. The
    production manifest excludes the two preprod-only custom service images
    and their extra Debian 13.6-slim base reference.
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

- [x] ~~Build, hash-check, seed-test, and restart-test the `r13` schema-v2
  candidate~~ (2026-07-21)
  - The candidate was built from pushed commit
    `15e47d6d48a82a05281b386f3446bbbd1760d455`. Production contains 23 exact
    external and 17 repository-built references, for 40 total. Preprod contains
    24 exact external and 19 repository-built references, for 43 total.
    Anthropic is the only selected provider.
  - Production archive SHA-256:
    `8825cd55ba8e1b5998621b6823efcebd8caafd260d203e0aea124940af00e68a`.
    Production manifest SHA-256:
    `57852a98089709f05873c56bd315563060c4cbb2714639842ddd58e281dff03e`.
    Preprod archive SHA-256:
    `1280df053dfd18fe3891e3a07d4375ccbe12714a11e512d909156e5861c8a59a`.
    Preprod manifest SHA-256:
    `1653b490b0ca2ab62c84d576d9b7c770217736b7ec07cc578894b8172c10ee9f`.
  - The clean-room run removed 26 containers, 19 networks, 11 volumes, 62
    aliases, and all 43 target image IDs. It preserved 185 unrelated IDs. Fresh
    seed loading and Ansible ended with `PREPROD_CLEAN_ROOM_OK`,
    `PREPROD_E2E_PASSED`, and `SEEDED_PREPROD_E2E_PASSED`.
  - After a Vault restart, the test proved `initialized=true` and `sealed=true`.
    The same seed-mode converge auto-unsealed Vault and passed the full edge,
    identity, and Cribl tests again. Visual browser acceptance remains active
    above because the current runtime exposes no browser.

- [x] ~~Build, hash-check, and seed-test the `r12` schema-v2 candidate~~
  (2026-07-21)
  - The candidate was built from pushed commit
    `d63b70f7c9e7cac3762de4594264b41267f3912d`. Production contains 23 exact
    external and 17 repository-built references, for 40 total. Preprod contains
    24 exact external and 19 repository-built references, for 43 total.
    Anthropic is the only selected provider.
  - Production archive SHA-256:
    `89b77840300ebd555dc73bb1ec8a2cae4a23422031b0df05af7a4e0d9ca15f63`.
    Production manifest SHA-256:
    `b09ef4b194e1c7c1a090119b5f95ca6ec1543a24acaeeb8736f6e5fc566d0d66`.
    Preprod archive SHA-256:
    `b5f4ae324cf6801b8102ae7f4418d532a16f4f5309bf3e88278472a0e3a29e5c`.
    Preprod manifest SHA-256:
    `b81df70057f1b0c8f8c00950cd201038555efa892ff389adb94a4d2ee8ba535d`.
  - The Envoy policy digest is
    `8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`.
    The exact Envoy image ID is
    `sha256:04f3d74c450509bdf288ec64fdbee584e616522f503428a3699442a48b8cc08f`.
  - The clean-room run removed 26 containers, 19 networks, 11 volumes, 62
    aliases, and all 43 target image IDs. It preserved 167 unrelated IDs. Fresh
    seed loading and Ansible ended with `PREPROD_CLEAN_ROOM_OK`,
    `PREPROD_E2E_PASSED`, and `SEEDED_PREPROD_E2E_PASSED`. All 25 long-running
    containers were healthy on the exact manifest image IDs.
  - After a Vault restart, the test proved `initialized=true`, `sealed=true`,
    and HTTP 503. The same seed-mode converge auto-unsealed Vault, proved
    `sealed=false` and HTTP 200, and passed the full end-to-end and Cribl tests
    again. Visual browser acceptance did not run and remains active above.

- [x] ~~Build and hash-check the `r11` schema-v2 release candidate~~
  (2026-07-21)
  - The candidate was built from pushed commit `5c43a83`. Production contains
    23 exact external and 17 repository-built references. Preprod contains 24
    exact external and 19 repository-built references. Its four file hashes
    pass the schema-v2 local release receipt. The exact preprod pair later
    passed fresh loading, seeded validation, and a second converge after a
    Vault restart. Visual browser acceptance remains active above.
  - Production archive SHA-256:
    `fd38eec7d7769c102ab6ad018342f52236877727159db638258a74b3d87b52ad`.
    Production manifest SHA-256:
    `3f5db8d7b8b7548f84975015182cb134132075c748a30984d9bf1b419d34f9b7`.
    Preprod archive SHA-256:
    `df65120821a48f99741493cdfaf31d5a8e9ad569db975d338d2c81898f2b06fa`.
    Preprod manifest SHA-256:
    `891601332abb46c58afa3359d73125f73f8e264252f849a31d029378eab967fd`.
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
