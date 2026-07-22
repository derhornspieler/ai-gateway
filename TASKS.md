# Tasks

## Active

<a id="complete-current-candidate-release-acceptance"></a>

- [ ] **Complete the current source candidate release acceptance** - The
  runtime image inputs were built from `77c50d3`. Commits `5e84392` and
  `3e8cafa` repair only the local PostgreSQL rehearsal and exact cleanup
  helpers. Commit `689bb67` also makes the production migration remove its
  temporary age identity after an early input failure. None of these changes
  alters a seed runtime image. The schema-v2 reader accepted the same release.

  - The Anthropic-only ARM64 production release contains 23 external and 17
    custom images. Its archive SHA-256 is
    `45d6495e63ff09fca7d15579bea1878150c44d64e31203cc6c5b086128823390`.
    Its manifest SHA-256 is
    `d735d17e08d7720d1e6649b3fedbf4d95f62e3f4616cb23b6651eed5b52cac80`.
  - The matching preprod release contains 25 external and 19 custom images.
    Its archive SHA-256 is
    `ac87381f624463f5badc8b0d2c35c8e80786ac939ffc24d369e04a52a21db119`.
    Its manifest SHA-256 is
    `3552fe7f29ff2190348093f374ee48e2368a131ac04b80c50ed0b988e1a41d3b`.
  - The provider-policy digest is
    `8c553d83bc98edeee4e1157368b8620ec6234e557b59a8195be6390677cdada6`.
    The exact Envoy image ID is
    `sha256:04f3d74c450509bdf288ec64fdbee584e616522f503428a3699442a48b8cc08f`.
  - The release-grade run started with an exact Ansible clean room, loaded all
    44 preprod image IDs from the archive, and kept pulls and source builds
    disabled. All 25 long-running services were healthy on PostgreSQL 16.14.
    The application and Cribl acceptance tests passed before and after the
    forced pre-cutover recovery.
  - The same run restored more than 128 MiB of deterministic data in each of
    the Keycloak, LiteLLM, and rotator databases to the exact PostgreSQL 18.4
    seed image. It proved each service role still owned and could read and
    write its data, passed full application and Cribl checks, refused a real
    PostgreSQL 16 downgrade without mutation after writes opened, restored a
    same-major physical backup, and passed the full checks again. Receipt
    SHA-256: `5be54a1d8cb4d918f4addb060101adb14f8d9631c1ae3401275b8319904a2085`.
  - Accepted test boundary: the macOS exact-seed run did not literally execute
    the Linux/root `state-backup.sh`, `postgres-major-migrate.py`, or the
    `generic_rocky9` plays in `migrate-postgres18.yml`. Their unit, source, and
    Ansible contracts passed. The real commands remain an approved maintenance-
    window gate on the existing production Linux host. No rehearsal VM will be
    created, and the local receipt does not claim those commands ran.
  - The 875 infrastructure contracts, 532 Python service tests, four Go
    race/vet suites, Compose, identity, ShellCheck, yamllint, Bandit, Ruff,
    dependency audit, documentation links, and Ansible syntax checks passed.
  - Final exact-manifest teardown removed 26 containers, 19 networks, 11
    volumes, all 44 release aliases and image IDs, and six run-state files
    while preserving all 16 unrelated image IDs. Separate read-only checks
    found no owned container, seed image alias, volume, network, or hosts
    entry. Reusable local test CA, keys, static test credentials, and rendered
    inputs remain by design so later PreProd deployments use the same identity.
  - Eight of ten GitHub workflows passed on `689bb67`. Repository Trivy,
    CodeQL, secret scanning, infrastructure, Python, Go, policy, runtime-skew,
    and hygiene checks passed. The two red workflows stopped only at the
    protected DHI credential gates, so final DHI image, VEX, SBOM, and
    container scans remain blocked until a repository administrator adds both
    required secrets.
  - Real-browser acceptance remains `BLOCKED/NOT RUN`: this session exposed no
    browser backend. The browserless OIDC, cookie-scope, role, logout, and
    callback tests passed, but they do not replace the manual browser checklist.
    Do not create a Rocky or Parallels test VM for either remaining gate.

- [x] ~~Finish the current-candidate Cribl release receipt~~ (2026-07-22) -
  The exact new preprod seed produced the final receipt. Manifest
  `c19b82a39c5d07342361d431e8bad0d978ef71c314f530c1c0d9aa4689a5eea7`
  passed the natural Keycloak, authenticated LiteLLM, malformed-field,
  redaction, TLS, bounded backpressure, outage, and recovery checks twice,
  including after the Vault restart.

  - Alloy applies one common-record gate with a server-owned schema,
    environment, producer, matching service name, and recent UTC time.
  - The reviewed feed includes AI request audit, natural quoted Keycloak login
    events, portal and identity actions, provider rotation, Vault state and
    bounded audit metadata, Envoy trust events, and controller upgrade or
    rollback events from the protected target file source.
  - Prompt and completion fields use the six reviewed secret patterns and drop
    non-string or nested values. Unknown source fields are ignored; malformed
    or missing approved fields drop the outbound record.
  - Open WebUI's signed subject is the stable per-user audit ID. Its signed
    username or e-mail is the one reviewed readable-name exception and may
    contain `@`. The shared LiteLLM key proves service authorization only.
  - Managed identity uses planned/applied or security-drift/recovery events.
    One durable UUID follows retries through the pending Vault state. LDAP
    provider rename fails closed unless a legacy blank-name record points to
    the same live provider ID.
  - The exact seeded preprod test received natural quoted `LOGIN`,
    `LOGIN_ERROR`, and `LOGOUT` records through the TLS Cribl mock.

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
  - Keep this as one release gate with the active current-candidate item. Customer
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
<a id="run-a-new-operator-documentation-usability-review"></a>

- [ ] **Run a new-operator documentation usability review** - The active guides
  and diagrams use short sentences, direct commands, and checked links. Ask a
  new preprod operator and a production operator to follow them without verbal
  help. Fix unclear words, steps, links, bookmarks, and diagram labels. Save the
  review notes with the next release evidence.
- [ ] **Add model-aware usage, limits, catalog, cost, dashboards, and routing**
  - Start this only after the current release gates are complete. It does not
    block the current release. Reuse the existing LiteLLM, portal, Postgres,
    and Grafana paths; do not add a second billing or identity source without
    an approved design.
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

The dated `r7` through `r14` entries below are historical checkpoints. They do
not approve the current source candidate.

- [x] ~~Rehearse the PostgreSQL 18 migration with production-sized data~~
  (2026-07-22)
  - The exact 44-image ARM64 PreProd seed contained PostgreSQL 16.14 and 18.4.
    Ansible started the complete PostgreSQL 16 graph and passed application and
    Cribl checks before creating more than 128 MiB of fixed test data in each
    application database.
  - A forced failure before cutover restarted the unchanged source volume and
    passed the full checks again. The logical move preserved table ownership
    and grants. Keycloak, LiteLLM, and the rotator could each read and write
    their restored data as their own restricted database role.
  - PostgreSQL 18.4 passed the full application and Cribl checks. A real
    PostgreSQL 16 command then failed closed after writes opened without
    changing the target. A same-major physical backup and restore passed the
    complete checks a final time.
  - The exact-manifest teardown removed the whole deployment and all 44 seed
    image IDs. No separate Rocky or Parallels rehearsal VM was created. The
    migration SOP states that Git history gives no reason for the old
    PostgreSQL 16 choice; any other explanation would be an inference.

<a id="review-every-container-image-and-language-dependency-version"></a>

- [x] ~~Review every container image and language dependency version~~
  (2026-07-22)
  - The DHI catalog confirmed that every selected DHI tag is the newest stable
    matching tag for its major version and image variant. Alloy `1.18.0`,
    Grafana `13.1.1`, and Traefik `3.7.8` were newer upstream, but matching DHI
    tags did not exist. The release keeps the newest DHI Alloy and Grafana
    images. Its custom Traefik image adds the reviewed current `3.7.8` binary
    to the newest DHI Traefik runtime.
  - Official release sources confirmed current PostgreSQL `18.4`, Python
    `3.14.6`, Go `1.26.5`, Debian `13.6`, Docker Engine `29.6.2`, and Docker
    Compose `5.3.1`. The selected containerd `2.2.6` is the version Docker
    Engine `29.6.2` packages, so it remains a tested compatibility set instead
    of mixing in upstream containerd `2.3`.
  - Every direct Python runtime and test dependency matched its current PyPI
    project version. The four Go modules use only the standard library. The
    exact ARM64 seed build and full local rehearsal passed. See the
    [dated version review](docs/image-version-review.md) for every pin and the
    review method. GitHub's protected DHI scans remain the separate security
    audit gate; version review does not replace those scans.
- [x] ~~Rewrite active documentation and add automated documentation checks~~ (2026-07-21)
  - Active documentation separates preprod from production and uses short,
    direct operator language. Obsolete lab material is archived and labeled as
    non-operational.
  - Architecture, deployment, identity, network, security, provider, release,
    Cribl, PostgreSQL, Vault, and testing diagrams and procedures match the
    deployed design. The automated link, anchor/bookmark, navigation, and
    Mermaid-reference validator is green.
  - The test runbook explains unit, contract, integration, end-to-end, browser,
    and final release gates. The new-operator usability review remains open
    above; automated checks cannot prove that every reader understands a page.
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
  - Historical seeded preprod proved the Anthropic-only path. The current
    candidate must create its own receipt through the active gate above.
    Seeded local preprod is the live acceptance environment. No separate
    rehearsal host or VM is required.
  - This closes the Envoy core, not the whole release. The
    [current-candidate release check](#complete-current-candidate-release-acceptance),
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
