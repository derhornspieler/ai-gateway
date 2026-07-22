# Tasks

## Active

<a id="finish-r14-visual-browser-acceptance"></a>

- [ ] **Finish `r14` visual browser acceptance** - Candidate `r14` was built
  from pushed commit `c5c1e503053c76e35f8bb93d242a9ac630d1b98e`. Its exact
  preprod pair passed clean-room purge, fresh archive loading, one Ansible
  seed-mode deploy, and the full integration and end-to-end gate. The initial
  pre-deploy purge receipt removed 26 containers, 19 networks, 11 volumes, 62
  aliases, and all 43 target image IDs while preserving 185 unrelated IDs.
  Pulls and source builds stayed off. All 25 long-running containers were
  healthy on the exact manifest image IDs. The run ended with
  `PREPROD_CLEAN_ROOM_OK`, `PREPROD_E2E_PASSED`, and
  `SEEDED_PREPROD_E2E_PASSED`.

  The r14 test also proved that LiteLLM audit spans use Alloy's authenticated
  receiver and that missing, wrong, or caller-forged source proof is rejected.
  The visual browser replay could not run because no browser session exists.
  Reload the exact r14 preprod pair and run that replay when a browser is
  available. Keep the `r10` Chrome result as historical evidence; do not use it
  as `r14` proof.

  After testing, the final bounded clean-room teardown returned
  `PREPROD_CLEAN_ROOM_OK` for project `aigw-preprod`, cleanup-receipt schema 1,
  and manifest
  `1ab6902ace9c1b25a3e8a3a1d1a81e014dbf60d0045d8e67a4b8604b7b58ceab`.
  It removed 26 containers, 19 networks, 11 volumes, 43 image aliases, 43 image
  IDs, and three generated state files while preserving 185 unrelated image
  IDs. Ansible also removed the owned macOS loopback aliases and marker-bounded
  hosts fragment.
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
    name, key hash, project ID, and request ID fields. Still prove readable-name
    quality for chat, direct API, and every supported client path.
    `aigw.user.name` is readable attribution, not an authorization fact. Keep
    stable subject, key, and project evidence separate.
  - **Source authentication is complete:** commit `c5c1e50` added a dedicated
    bearer-authenticated LiteLLM receiver. The open receiver removes a
    caller-owned trust marker and rejects `service.name=litellm`. Alloy stamps
    its own marker only after the token passes. Commit `33c79e5` validates a
    restored token before it repairs the exact reader group and file mode.
  - **Common-record gap:** the handoff expects a recent UTC time, fixed
    environment, producer, and schema on every record. The current projection
    does not enforce all four fields for every event class. Add fixed
    `preprod`/`production` values, a reviewed producer name, and recent-time
    checks. Test every record class and reject a zero or stale timestamp.
  - **Event gaps:** add a reviewed sender for controller-only events; provider
    rotation start, attempt, failure, and recovery; application authorization
    denials and uncovered privileged changes; LDAP and managed-identity drift,
    reconcile failure, and recovery; and break-glass activation, disable, and
    cleanup. Current provider-key promotion does not restore the previous
    secret. Design and implement a safe recovery or rollback capability before
    adding an event that claims it happened. Add natural producer receipt tests
    for every new event.
  - **External acceptance:** the Cribl/SOC team must supply the approved
    endpoint and CA, repeat the wire and field receipt, enforce and prove
    24-hour destination retention, and decide whether the gateway also needs a
    hard per-record 24-hour queue age. Keep queue alerts on the local metrics
    path; never send alert payloads through the SOC feed.

## Waiting On

<a id="provide-protected-dhi-credentials-and-finish-the-release-security-audit"></a>

- [ ] **Provide protected DHI credentials and finish the release security
  audit** - The credential-independent quality, dependency, CodeQL,
  secret-scanning, and release-contract jobs are green. The image jobs stop at
  the required credential gate because the protected
  `release-container-security` environment has no `DHI_USERNAME` or
  `DHI_PASSWORD` secret.

  - A repository administrator must add approved DHI credentials and rerun the
    jobs for the exact release commit. Do not copy a developer's local login
    into GitHub or weaken the gate.
  - GitHub must scan the source and every exact external and custom image in the
    production and preprod union. Save raw Trivy JSON, blocking VEX-aware Docker
    Scout results, SBOMs, provenance, and the final image IDs.
  - Review every finding. Fix it or add an owned, dated, package-specific waiver
    with a clear reason. Record the remaining risk. A missing credential or
    skipped image is not a pass.
  - Keep this as one release gate with the active r14 browser item. Customer
    Cribl receipt and retention remain the separate acceptance task below.

<a id="complete-the-customer-cribl-acceptance-ceremony"></a>

- [ ] **Complete the customer Cribl acceptance ceremony** - The local TLS mock,
  allow-list, redaction, queue outage, and recovery tests pass. The Cribl/SOC
  team must supply its approved endpoint and CA, enforce and prove 24-hour
  destination retention, and decide whether a hard per-record 24-hour limit is
  also required on the gateway queue.
- [ ] **GitHub history and owner cleanup decision** - Forward-tree cleanup is in scope now. Removing personal author metadata from old commits or changing the repository owner requires an explicit repository transfer/history-rewrite decision.

## Someday

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
- [ ] **Add model-aware usage, limits, catalog, cost, dashboards, and routing**
  - Start this only after the current release gates are complete. It does not
    block r14. Reuse the existing LiteLLM, portal, Postgres, and Grafana paths;
    do not add a second billing or identity source without an approved design.
  - **Track tokens by model, user, and project:** Record the requested model,
    actual provider model, stable user ID, project ID, input tokens, output
    tokens, cache-write tokens, and cache-read tokens for each completed
    request. Keep request IDs for audit joins. Do not put prompts, API keys, or
    high-cardinality request IDs in Prometheus labels. Define retry, streaming,
    failed-request, and missing-usage behavior. Acceptance requires contract
    tests, database migration and rollback tests, and seeded preprod requests
    proving the totals match LiteLLM and provider receipts.
  - **Design and enforce per-model token limits:** Decide which controls the
    product needs before writing code: a per-request maximum output, a fixed or
    rolling time-window quota, tokens per minute, a money budget, or a reviewed
    combination. Define units, reset rules, and precedence when model, user,
    project, and key rules overlap. Do not treat these controls as the same
    limit. For each hard limit, reserve or check capacity before the provider
    call so parallel requests cannot bypass it. Return a safe denial and emit an
    audit event. Acceptance requires tests for every chosen control, precedence,
    boundaries, reset or rolling windows, concurrency, streaming, retries,
    admin RBAC, and fail-closed database errors.
  - **Add hidden custom models:** Let an administrator add a model that normal
    users cannot see until it is assigned. Require an explicit reviewed
    provider and provider model name. Store an explicit
    `visible_in_discovery` flag, or an equally clear inverse `hidden` flag. A
    hidden model must stay absent from `/v1/models` and user-facing discovery
    until an administrator makes it visible, even if the model can be assigned
    through the admin path. Reject an arbitrary provider hostname, route, CA
    file, or provider that is absent from the immutable Envoy release. Keep
    credentials in Vault and never return them through the portal. Acceptance
    requires create, update, assign, visibility, hidden-discovery, revoke,
    duplicate-name, unsupported-provider, audit, restart, backup, restore, and
    seeded preprod tests.
  - **Build Grafana token dashboards:** Add admin-only views for token use by
    model, project, and user. Show input, output, cache-write, cache-read, total,
    request count, failures, and cost. Use bounded filters and a data source that
    can answer per-user questions without unsafe Prometheus labels. Show the
    data time range and an `unknown` bucket instead of hiding incomplete rows.
    Acceptance requires dashboard schema tests, role checks, seeded data, and
    totals that reconcile with the usage store.
  - **Account for cached and regular token cost:** Research the current official
    Anthropic request/response fields and pricing documentation before design.
    Record regular input, cache creation, cache read, and output units
    separately. Version and date every price entry so a later price change does
    not rewrite old cost. Handle models, cache durations, or usage fields with
    no reviewed price as `unknown`, not zero. Acceptance requires saved source
    links, dated pricing fixtures, payload fixtures, rounding tests, historical
    price-change tests, and totals reconciled to an approved Anthropic example.
  - **Explore automatic model routing:** Write an ADR before code. Evaluate the
    LiteLLM routing features that can choose a model from a user's prompt.
    Document prompt privacy, supported signals, quality, latency, cost, limits,
    fallback, auditability, and failure modes. Routing may choose only models
    assigned to that user or project and only providers built into the immutable
    Envoy release. It must not send a prompt to an extra model just to classify
    it unless that separate disclosure is approved. Acceptance for this future
    item is a reviewed design, a disabled-by-default prototype, fixed test
    prompts with expected choices, an operator override, and proof that a
    routing failure cannot bypass access or token limits.

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

- [x] ~~Complete immutable, provider-selectable Envoy releases~~ (2026-07-21)
  - The release CLI accepts repeated provider names, canonicalizes them, and
    resolves them only through the committed provider catalog. It rejects an
    empty set, unknown provider, arbitrary hostname, and arbitrary CA path.
  - The network-disabled build bakes only the selected routes, policy, and
    reviewed CA files into Envoy. The startup gate fails closed for missing,
    extra, malformed, expired, fingerprint-mismatched, SNI-mismatched, or
    SAN-mismatched trust data. Ansible downloads no provider trust at deploy
    time.
  - Schema-v2 manifests bind the provider list, hostnames, CA fingerprints,
    policy digest, and final Envoy image ID. The loader and validation path
    treat the image and policy as one release unit. Provider and CA changes
    require a reviewed catalog change and a new offline release.
  - The provider, CA-maintenance, architecture, image-update, security, and
    operator guides explain selection, capture provenance, CA rotation,
    validation, and recovery. They also separate certificate integrity, CA
    organization country, endpoint geography, and data residency.
  - Exact r14 seeded preprod selected only `anthropic` and passed the owner-
    approved live acceptance gate. Its policy digest is
    `8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`,
    and its Envoy image ID is
    `sha256:04f3d74c450509bdf288ec64fdbee584e616522f503428a3699442a48b8cc08f`.
    Seeded local preprod is the owner-approved live acceptance gate. No
    separate rehearsal environment is required.
  - This closes the Envoy core, not the whole release. The
    [active r14 browser check](#finish-r14-visual-browser-acceptance),
    [credential-gated DHI security audit](#provide-protected-dhi-credentials-and-finish-the-release-security-audit),
    and [customer Cribl acceptance](#complete-the-customer-cribl-acceptance-ceremony)
    remain open.

- [x] ~~Authenticate the LiteLLM request-audit source~~ (2026-07-21)
  - Commit `c5c1e50` added a private OTLP/HTTP trace receiver on port 4319.
    LiteLLM reads a fixed-shape token from a read-only file and sends it as a
    bearer header. The token is not in Compose environment data, command
    arguments, LiteLLM settings, or logs.
  - Alloy checks the token, stamps the server-owned source marker, and requires
    it before an AI request can enter Loki or Cribl. Its ordinary OTLP receiver
    deletes a caller-supplied marker and rejects a caller that claims to be
    LiteLLM. Preprod tests rejected a missing token, wrong token, and forged
    marker.
  - Commit `33c79e5` completed the state-restore path. Ansible accepts only the
    safe temporary `root:root` restore state, validates the token contents, then
    restores group 473 and mode `0440` before the final boundary check.

- [x] ~~Build, hash-check, seed-test, and clean up the `r14` schema-v2
  candidate~~ (2026-07-21)
  - The candidate was built from pushed commit
    `c5c1e503053c76e35f8bb93d242a9ac630d1b98e`. Production contains 23 exact
    external and 17 repository-built references, for 40 total. Preprod contains
    24 exact external and 19 repository-built references, for 43 total.
    Anthropic is the only selected provider.
  - Production archive SHA-256:
    `b04cce16df11c366a098b3a9d801bc57a96051e0766caba182cd342493285298`.
    Production manifest SHA-256:
    `9b2efbd2f6768bd98f969b3f4312cf8d0cff9b1761d5d59dd7ebd44a6869c92f`.
    Preprod archive SHA-256:
    `482618f21eb5e09c3f41e9c9c55deada7e317edf4c4fada0f96dd7e93ff2a691`.
    Preprod manifest SHA-256:
    `1ab6902ace9c1b25a3e8a3a1d1a81e014dbf60d0045d8e67a4b8604b7b58ceab`.
  - The exact manifest selects `anthropic`, route `/anthropic/`, and hostname,
    SNI, and SAN `api.anthropic.com`. Its Envoy policy digest is
    `8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`.
    Its Envoy image ID is
    `sha256:04f3d74c450509bdf288ec64fdbee584e616522f503428a3699442a48b8cc08f`.
  - Fresh seed loading and Ansible ended with `PREPROD_E2E_PASSED` and
    `SEEDED_PREPROD_E2E_PASSED`. The tests covered the authenticated LiteLLM
    audit path and the full Cribl gate. Browser acceptance did not run because
    no browser session exists, so it remains active above.
  - The initial pre-deploy purge removed 26 containers, 19 networks, 11
    volumes, 62 aliases, and all 43 target image IDs while preserving 185
    unrelated image IDs.
  - The final clean-room teardown returned `PREPROD_CLEAN_ROOM_OK` for project
    `aigw-preprod`, cleanup-receipt schema 1, and manifest
    `1ab6902ace9c1b25a3e8a3a1d1a81e014dbf60d0045d8e67a4b8604b7b58ceab`.
    It removed 26 containers, 19 networks, 11 volumes, 43 image aliases, 43
    image IDs, and three generated state files while preserving 185 unrelated
    image IDs. Ansible separately removed the owned macOS loopback aliases and
    marker-bounded hosts fragment.

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
