# Archived Runbook Clarity Report — 2026-07-14

> Historical evidence only. This report discusses the retired Rocky/Parallels
> lab and is not current operator guidance.

**To:** RAG Agent team
**From:** Documentation pass on the `docs/handoff-refresh` branch (Vault unseal
custody + auto-unseal converge contract + Grafana dashboards, commit `92ab429`)
**Scope of this report:** ambiguities and missing examples found while reading
`deploy-runbook.md`, `deploy-guide.md`, `operations.md`, and `test-runbook.md`
as an entry-level operator would. Items 1–6 are gaps in docs I touched this
pass but could not fully close without new tooling or a product decision; items
7–11 are out-of-scope or pending parallel-workstream gaps that need their own
follow-up. None of these block the surgical edits already committed.

---

## Gaps in the runbooks I worked through

**1. `vault-bootstrap.sh` refuses the very profile the pilot runbook builds.**
- *Doc + section:* `deploy-runbook.md` Part 7; `deploy-guide.md` "First bootstrap
  after Compose starts".
- *Unclear/missing:* the runbook builds a `generic-rocky9` pilot, but
  `vault-bootstrap.sh` fails closed on that profile unless
  `AIGW_ALLOW_INSECURE_VAULT_BOOTSTRAP=I_UNDERSTAND_THIS_IS_LAB_ONLY` is set
  (`scripts/vault-bootstrap.sh` lines 67–78). The pre-edit runbook told
  operators to run `sudo scripts/vault-bootstrap.sh`, which would just print a
  FATAL. I added the acknowledgement variable, but the deeper ambiguity remains:
  *should a customer pilot run the lab bootstrap at all, or always the reviewed
  production ceremony?* An entry-level operator cannot make that call from the
  current text.
- *Fix:* a short "pilot vs. production first-init" decision note, plus a
  committed `production-rocky9`/pilot wrapper example that makes the intended
  path explicit rather than relying on the lab escape hatch.

**2. Custody destination path is guessed, not derived.**
- *Doc + section:* `deploy-runbook.md` Part 7 (Step 7b);
  `deploy-guide.md` "Encrypted secret overlay".
- *Unclear/missing:* `store-vault-unseal-key.py --vault-file
  ansible/inventory/generated/<alias>/group_vars/generic_rocky9/vault-unseal.yml`
  assumes the operator knows (a) the group is named `generic_rocky9`, (b) a new
  sibling `vault-unseal.yml` is auto-loaded, and (c) the parent directory passes
  the helper's ownership/permission checks (`store-vault-unseal-key.py` lines
  94–109). A first-timer has none of that context for their own alias.
- *Fix:* have `bootstrap-generic-rocky9.py` print the exact custody
  `--vault-file` path in its "next command" output, or add a snippet showing the
  generated inventory tree with the intended `vault-unseal.yml` sibling.

**3. The first-init example scripts need undocumented env vars.**
- *Doc + section:* `ansible/inventory/examples/rocky9-lab.first-init.sh.example`
  and `production-rocky9.first-init.sh.example` (referenced from all three
  runbooks).
- *Unclear/missing:* each script `: "${VAR:?...}"`-guards several inputs
  (`AIGW_SSH_TARGET`, `AIGW_INVENTORY`, `AIGW_INVENTORY_ALIAS`, `AIGW_VAULT_ID`,
  `AIGW_VAULT_PASSWORD_FILE`). Nothing maps these to the values an operator set
  in `deploy-runbook.md` Part 3, and the lab example writes to a committed
  `inventory/group_vars/gateway/vault-unseal.yml` path while the production
  example writes to a generated-inventory sibling — the difference is
  unexplained.
- *Fix:* a companion "how to run the first-init example" block (or an expanded
  header comment) enumerating each variable with one concrete example value and
  the Part 3 field it comes from.

**4. `store-vault-unseal-key.py` failure modes are opaque.**
- *Doc + section:* `deploy-runbook.md` Part 7 (Step 7b), Troubleshooting table.
- *Unclear/missing:* the helper fails closed with a terse `FATAL:` on a
  group/world-writable parent dir, a vault-password file that is not `0600`, a
  whole-file-encrypted target overlay, an already-present `vault_unseal_key`, or
  a share that is not exactly `[A-Za-z0-9+/]{43}=`. None of these have a
  documented remediation.
- *Fix:* a symptom → cause → fix table for the helper (mirrors the existing
  preflight troubleshooting rows), or richer remediation text in the helper's
  own error strings.

**5. "1-of-1 Shamir" / `t=1`/`n=1` jargon is unexplained for the entry-level
audience.**
- *Doc + section:* `deploy-runbook.md` (auto-unseal wording + Glossary);
  echoed in `deploy-guide.md` and `test-runbook.md`.
- *Unclear/missing:* the runbook is written for "average IT knowledge," but the
  auto-unseal contract and the guide/test docs lean on "Shamir share," "seal
  contract," and `t=1`/`n=1` without a plain-language definition.
- *Fix:* one Glossary line, e.g. "unseal share / threshold — this deployment
  splits Vault's unlock secret into exactly one share and needs exactly that one
  to unlock (`t=1`, `n=1`)."

**6. Reboot recovery gives two paths but no decision rule or copy-paste manual
command.**
- *Doc + section:* `deploy-runbook.md` Troubleshooting; `operations.md`
  "Normal boot and reboot".
- *Unclear/missing:* after a reboot an operator can rerun the full converge
  (auto-unseal, slow) or run `vault-unseal.sh` on the VM (fast). The docs now
  name both but the runbook troubleshooting cell does not give the exact
  `read -rsp … | sudo scripts/vault-unseal.sh` idiom, and there is no "use A
  when X, B when Y" rule.
- *Fix:* a two-line decision note plus the exact stdin-only manual command in
  the runbook (the idiom already exists verbatim in `operations.md` and can be
  reused).

## Out-of-scope / pending-feature gaps (not fixed this pass)

**7. Restore/DR path conflicts with the new mandatory auto-unseal — needs DR
workstream reconciliation. (PENDING)**
- *Doc + section:* `operations.md` "Recovery order" steps 4–5;
  `test-runbook.md` §12; `archive/lab-dr-rehearsal.md`.
- *Unclear/missing:* the new `verify` role refuses to finish with an initialized
  Vault sealed, and the `docker_stack` auto-unseal task fires on any
  initialized+sealed Vault — including the restore path. If the controller
  `vault_unseal_key` matches the restored backup's share, the step-4 converge
  now unseals automatically and the step-5 manual `vault-unseal.sh` is redundant;
  if it does not match, the converge fails closed at the key/unseal assert
  *before* step 5 is reachable. The documented "restored Vault stays sealed …
  then stream the separately held old share" sequence predates this. I added
  caveats but deliberately did not rewrite the mandated DR sequence.
- *Fix:* the DR workstream should decide whether restore expects
  `vault_unseal_key` to equal the restored backup's share, then rewrite
  `operations.md` steps 4–5, `test-runbook.md` §12, and `lab-dr-rehearsal.md` as
  one reviewed change. These are the "Vault-readiness changes … source-tested but
  not yet live" already on release hold.

**8. `observability-operations.md` is now stale about the dashboard set (outside
this pass's four-doc scope).**
- *Doc + section:* `docs/observability-operations.md` (around the "AI Gateway"
  folder description).
- *Unclear/missing:* it states the folder holds three dashboards (overview, live
  logs, request audit); there are now six. It does not describe the three new
  dashboards (`rocky9-host`, `grafana-lgtm-stack`, `edge-identity-services`),
  their scraped-native-metric sources, or the exact-scrape-target component
  health panels (`== bool 5` / `== bool 4`).
- *Fix:* a follow-up edit to `observability-operations.md` cataloguing all six
  dashboards and the new metric contracts (the exact metric lists are pinned in
  `scripts/tests/test_grafana_provisioning_contract.py`).

**9. Production Vault initialization ceremony and PKI/TLS remain undocumented.
(PENDING parallel workstream)**
- *Doc + section:* `deploy-guide.md` "Production-readiness warning" (bullet
  "production Vault bootstrap/unseal/PKI/TLS instead of the lab 1-of-1 script").
- *Unclear/missing:* the new custody helper closes the *unseal-key custody* gap
  for an already-initialized Vault, but the production *initialization* ceremony
  (customer-rooted intermediate, TLS on the Vault listener, multi-custodian or
  reviewed KMS auto-unseal) still has no runbook. `production-rocky9.first-init.sh.example`
  assumes the reviewed ceremony has already run and returned the share.
- *Fix:* a production Vault init runbook owned by the security/PKI workstream;
  until then, keep the "production bootstrap/PKI/TLS" item flagged as a blocker.

**10. Production AD/LDAPS identity federation is still lab-only. (PENDING
parallel workstream)**
- *Doc + section:* `deploy-guide.md` "First bootstrap after Compose starts" and
  `identity-operations.md`; `deploy-runbook.md` Part 8.
- *Unclear/missing:* the committed flow federates a lab **Samba AD** over LDAPS;
  the customer AD/LDAPS federation path (real directory, real CA trust) is
  referenced but not spelled out for an entry-level operator.
- *Fix:* a customer-directory federation runbook from the identity workstream;
  note as pending-feature docs.

**11. Dashboards prove "loads," not "populated."**
- *Doc + section:* `test-runbook.md` §10 (the new dashboard bullet I added);
  `deploy-runbook.md` Part 8.
- *Unclear/missing:* the three new dashboards render even when a scrape target is
  down (empty panels). §10 now asks operators to confirm population, but there is
  no per-dashboard "expected non-empty series" checklist, so a first-timer cannot
  distinguish "healthy but idle" from "scrape broken."
- *Fix:* a small expected-series checklist per new dashboard (e.g., `rocky9-host`
  must show non-null `node_load1`; `grafana-lgtm-stack` must show a non-zero
  component-up count), derivable from the metric contracts in
  `test_grafana_provisioning_contract.py`.

**12. Post-ceremony domain migration has no break-glass runbook for customer
profiles. (PARTIAL — automatic repair landed; re-bootstrap path still thin)**
- *Doc + section:* `identity-operations.md` "Domain migration on an existing
  realm" (added this pass); `operations.md` OIDC troubleshooting.
- *What changed:* a converge now reconciles the four managed OIDC clients'
  `redirectUris`/`webOrigins` to `aigw_domain` automatically **while the
  bootstrap window is open** (temporary `aigw-bootstrap-controller` still
  present), via `app.reconcile_oidc_redirect_uris` using only that reviewed
  credential. This closes the common lab/pre-bootstrap case: after a domain
  change, re-running the converge restores browser SSO with no manual Keycloak
  edits.
- *Remaining gap:* on a host that has already completed the interactive
  **Initialize identity control** ceremony, the temporary client is gone and the
  durable controller intentionally holds no `manage-clients` role, so the
  converge fails closed with
  `OIDC_REDIRECT_URI_PREBOOTSTRAP_RECONCILIATION_REBOOTSTRAP_REQUIRED` and a note
  to re-run the ceremony. For the **lab** that is a re-seed + re-init; for a
  **customer** profile the exact reviewed break-glass sequence to safely
  recreate `aigw-bootstrap-controller` (or otherwise re-open the bootstrap
  window) and re-run the ceremony is referenced but not yet written as an
  operator procedure.
- *Fix:* a customer break-glass runbook from the identity workstream covering
  domain migration on an already-bootstrapped host, aligned with the production
  Vault/PKI ceremony gaps in items 9–10.

## Gaps found in the PKI + playbook-split pass (2026-07-14, customer-intermediate wave)

New ambiguities hit while documenting the three-playbook split, the
`customer-intermediate` edge-TLS mode, and the LUKS warn-only change
(`operations.md`, `deploy-guide.md`, `deploy-runbook.md`, `os-security.md`).

**13. The lab `customer-intermediate` example is host-vars only — no runnable
inventory wiring.**
- *Doc + section:* `ansible/inventory/examples/rocky9-lab.customer-intermediate.host-vars.yml.example`;
  `operations.md` "Mode 3 ceremony".
- *Unclear/missing:* the example is a **host_vars document**, but there is no
  matching `hosts.yml`/inventory example showing where it plugs in. The committed
  lab inventory (`ansible/inventory/lab.yml`) uses `vault-intermediate`, so an
  operator who wants to exercise `customer-intermediate` in the lab has no
  documented "assemble these files into a runnable inventory" step. The staging
  script echoes `ansible-playbook -i <lab inventory> ansible/site.yml` but never
  says how to build `<lab inventory>` from the example host-vars.
- *Fix:* a short "wiring the customer-intermediate lab inventory" snippet, or a
  companion committed `hosts.yml` example that references the host-vars document.

**14. Re-running the import ceremony silently requires another converge first.**
- *Doc + section:* `operations.md` "Mode 3 ceremony"; `scripts/vault-pki-intermediate.sh`
  `import-intermediate`.
- *Unclear/missing:* `import-intermediate` `shred`s
  `secrets/aigw-intermediate-import.key` (and removes the staged cert/chain copies)
  on success. The subcommand is idempotent against Vault, but the staged inputs it
  reads are gone after the first run, and the Ansible staging step is **gated on
  the ceremony marker being absent** — so a post-ceremony `site.yml` will not
  re-stage either. Recovering or re-running the ceremony therefore means removing
  the `.state/edge-tls-issued` marker *and* re-converging, which nothing states.
  I documented "another converge first," but the exact marker-clear + re-stage
  recovery path is still thin.
- *Fix:* an explicit "how to re-run or roll back the import ceremony" note (which
  marker to clear, that re-staging is marker-gated), ideally with a supported
  `--regenerate`-style flow rather than manual marker surgery.

**15. No switch turns the LUKS warning back into a hard failure for customers who
want it enforced.**
- *Doc + section:* `deploy-runbook.md` Part 1 (row 5); `deploy-guide.md`
  "Sensitive state backing"; `os-security.md` §3.
- *Unclear/missing:* the encrypted-state preflight now only **warns** on missing
  LUKS (`AIGW_ENCRYPTED_STATE_WARNING`) even on a customer profile with
  `require_encrypted_state: true`; `false` merely skips the check. There is no
  inventory value that makes a missing LUKS volume fail closed. A customer whose
  policy requires encrypted state at rest has no way to make the converge enforce
  it, and an entry-level operator cannot judge whether proceeding past the warning
  is acceptable — that is a risk-acceptance decision the docs cannot make for them.
- *Fix:* either a documented `require_encrypted_state`-style "hard fail" option, or
  a clear risk-acceptance note naming who signs off on deploying customer data
  without LUKS.

**16. The `customer-intermediate` name-constraint check always tests
`samba-ad.<domain>`, even in production where Samba is not deployed.**
- *Doc + section:* `scripts/edge-tls.py` `validate-intermediate`; `operations.md`
  "Mode 3 ceremony" name-constraints callout.
- *Unclear/missing:* the offline test-leaf verification exercises **both**
  `portal.<domain>` and `samba-ad.<domain>` against the supplied intermediate,
  regardless of deployment profile. In production (no Samba) the `samba-ad`
  hostname is still validated, so an intermediate whose name constraints permit
  `<domain>` but somehow exclude `samba-ad.<domain>` would fail the ceremony for a
  certificate the production edge never serves. In practice a subtree permitting
  `<domain>` covers `samba-ad.<domain>`, so this is usually moot — but it is
  undocumented, and an operator with an unusual constraint set could hit a
  confusing failure.
- *Fix:* note in the ceremony docs that validation always checks a wildcard-covering
  set including `samba-ad.<domain>`, so the permitted subtree must cover the whole
  `<domain>` one-level namespace, not just the apex.
