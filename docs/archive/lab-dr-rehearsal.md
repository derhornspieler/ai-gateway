# Lab Destructive Rebuild and Restore Rehearsal

This runbook recreates the disposable Rocky Linux 9 lab VM from vanilla
media and restores the `rocky9-lab` AI Gateway state. It is a
destructive recovery exercise, not the ordinary lab deployment procedure.
The 2026-07-13 execution record below is updated only when a gate has its
required evidence. A passed preparation gate does not imply that converge,
restore, persistence comparison, or release has passed.

The repository's Ansible does not create the VM, attach NICs, create
NetworkManager profiles, or change their static addresses, routes, gateways,
DNS, or interface bindings. Perform those steps from the hypervisor and the Rocky
console before running Ansible. The bounded exception is the firewalld-owned
`connection.zone` property: Ansible persists it by the supplied profile's
active UUID without cycling or reactivating the link.

## Safety boundary and roles

Use two distinct systems:

- **source VM** -- the current gateway, retained powered off until acceptance
  whenever capacity permits; and
- **recovery workstation/storage** -- the Mac or another device that holds the
  encrypted artifact, its authenticated receipt, the repository or source
  archive, and the deployment material needed to recreate the VM.

A hypervisor snapshot, a hypervisor disk image on the same Mac storage, or a file
under `/var/backups` on the source VM is not an off-box backup. It can be useful
for lab rollback, but it does not demonstrate recovery from loss of that
device. This rehearsal may prove VM-loss recovery only after the encrypted
artifact has left the source VM and its checksum and decryptability have been
verified at the recovery location. It still does not prove Mac-host or
site-loss recovery unless another independent device holds a verified copy.

Do not place the age identity, Vault unseal share, plaintext credentials, or
private keys inside the encrypted state artifact. Use separate authenticated
custody for the expected SHA-256 and separate restricted custody for each
recovery secret.

## Gate register

| Gate | Required result | Status | Evidence |
|---|---|---|---|
| G0 | Off-box artifact and every separately held recovery input verified | **PASS** | 2026-07-13 recovery-workstation custody record summarized below |
| G1 | Source quiesced; destructive action and rollback choice approved | **PASS** | final artifact verified, destructive replacement explicitly approved, old VM deleted; the verified recovery inputs are now the rollback path |
| G2 | Vanilla VM, three NICs, static topology, SSH key, and sudo verified | **PASS** | new hypervisor/console/SSH identity and topology record summarized below |
| G3 | Full Ansible security baseline completed before any manual container start | **PASS** | fifth full converge, `2026-07-13T05:38:42Z`–`05:41:32Z`, exit 0; protected log named below |
| G4 | Artifact checksum and hostile-archive validation passed before mutation | **PASS** | corrected offline repeat `2026-07-13T07:07:00Z`–`07:07:39Z`, exit 0, zero running project containers; receipt named below |
| G5 | Current-source converge passed, then restored Vault unsealed with the old separately held share and the complete runtime became healthy | **PASS** | sealed converge exit 0; one-share unseal exit 0; bounded runtime-only retry exit 0 with 22/22 healthy and zero restarts; receipts named below |
| G6 | Persistence, security, identity, and configured functional comparisons passed with external lanes classified truthfully | **PASS** | durable/identity/infrastructure/key-lifecycle/negative and synthetic collector-correlation lanes passed; real Anthropic/WIF inference is NOT EXECUTED |
| G7 | Final source deployed, controlled Docker-daemon and long-running-service sealed-Vault restart lanes passed, unchanged converge passed, and controlled access was reopened | **PENDING / RELEASE HOLD** | exact predecessor key-rotator image recovery has passed; SELinux/MCS, bind-recreation, Vault-readiness, rollback-retention, and Docker-parent-ACL source changes are not yet live, and the final restart/unchanged-converge proof remains open |

Record commands, UTC timestamps, operator, exit status, and sanitized output in
the evidence column or a linked evidence bundle. Never paste secrets into it.

## Current 2026-07-13 execution evidence

The recovery workstation directory
`/Users/jamesrudisill/.aigw-lab-dr/20260713-pre-rebuild` is mode `0700`; its
artifacts are mode `0600`. G0 verified all of the following before the old VM
was deleted:

- encrypted state artifact
  `aigw-20260713T035736Z-post-audit-fixed.tar.gz.age`, 33,873,497 bytes,
  SHA-256
  `ebf2bf27d7bd0dd524d1d6305ce13a1e14db7187c27833ae7434ece718bf1d94`,
  backup ID `6528e403-2940-452b-835e-aee85e77cb21`, profile
  `rocky9-lab`, with 12 declared volumes, 23 images, and 22 running
  services;
- independent decryption/listing and complete hostile-archive parsing of that
  artifact, without extracting it into the working tree;
- separate restricted custody of the age identity, old Vault unseal input,
  Ansible Vault input, automation SSH key, authenticated receipt, and source;
- non-secret pre-destroy marker set `persistence-markers-pre.json`, SHA-256
  `d4f87d3409c867b3cb4d6bb22fdeffe1eb908dea6227a2ac644a0f4c1246fc6d`;
  and
- the attempt-4 post-re-key, post-ACL-order deployment-source archive
  `/Users/jamesrudisill/.aigw-lab-dr/20260713-pre-rebuild/ai-gateway-source-post-acl-order-20260713T052206Z.tar.gz`,
  396,669 bytes and 230 archive members, SHA-256
  `15a8bf3f61aa8395e02aabc2eec3e43b2e76cb25e48b5b11ac366d6d10623b50`.

The last item was the content-addressed source input selected for attempt 4.
Its gzip integrity and mode-`0600` sidecar digest both passed. Attempt 4 then
required the bounded NetworkManager-zone fix described below, so this archive
is no longer an approved input for the next attempt. Capture a new immutable
source archive and independently recorded digest after the fix is frozen; do
not silently treat the old digest as current.

Later immutable source checkpoints supersede that attempt-4 input. The
post-G6 marker/lock checkpoint is
`ai-gateway-source-final-marker-lock-20260713T090043Z.tar.gz`, SHA-256
`809465d313def4cdcaf6b0028a4816d9d0f6b6c8bab715437e819fdf50e1a232`.
The subsequent key-rotator sealed-retry candidate is
`ai-gateway-source-key-rotator-sealed-retry-20260713T104657Z.tar.gz`, SHA-256
`c5ed5b732dcf8931ce053b41833c6bd6051a517c717a6023825b0205b68d85f8`.
Neither is the final G7 source because rollback-retention, Docker ACL,
SELinux/MCS, bind-recreation, Vault-readiness, build-framing, and portal/
identity changes were added afterward. Freeze and receipt a new archive only
after the complete source candidate and build plan pass review; never relabel
an earlier digest.

### Credential-custody incident and re-key

During documentation evidence collection, a read-only search was scoped too
broadly and emitted the **lab Ansible Vault password** into an agent tool
transcript. This record intentionally contains neither the retired value nor
any replacement value. The observed command did not read the separately held
age identity, Vault unseal input, provider credentials, or application
secrets.

The exposed lab password was treated as compromised: the encrypted Ansible
Vault overlay was re-keyed, restricted recovery custody was replaced, and the
old value was retired before the designated source archive above was created.
Re-keying protects the current overlay but cannot retroactively protect an old
source archive that contains a copy of the overlay encrypted under the retired
password. Every pre-re-key source archive is therefore superseded and must not
be used for deployment or recovery; retain it only under restricted
incident-evidence custody until its approved removal. The independently
age-encrypted state artifact has a different encryption boundary and was not
re-encrypted as part of this controller-credential response.

G2 verified a genuinely new VM created only after the old/proof VMs were
deleted:

| Fact | Verified value |
|---|---|
| hypervisor identity | `aigw01`, UUID `eb1cdcf8-af33-4057-bf43-85ec1f6cd71d` |
| Capacity/firmware | 6 vCPU, 16 GiB RAM, 80 GiB disk, ARM64 EFI, Secure Boot off |
| OS/kernel | Rocky Linux 9.8, `5.14.0-687.24.1.el9_8.aarch64` |
| Static hostname | `aigw01.aigw.aegisgroup.ch` |
| egress | `enp0s5`, MAC `00:1c:42:1f:b2:86`, `10.211.55.3/24`, sole main default via `10.211.55.1` |
| ADM | `enp0s7`, MAC `00:1c:42:d1:c3:fb`, `10.8.10.10/24`, no main default |
| internal | `enp0s8`, MAC `00:1c:42:a0:d3:fa`, `10.20.0.10/24`, no main default |
| Mandatory access | `ansible` Ed25519 key login and `sudo -n` passed; root account locked |
| New SSH host key | Ed25519 fingerprint `SHA256:5l2/cq/oC0bEg86ADIB8dt5HT0qZiPpZfRLUEX4u3fY`, explicitly different from the destroyed VM |
| Mandatory access control | SELinux enforcing at runtime and in configuration |

### G3 converge-attempt chronology

All logs below are beneath the recovery directory's `deployment-logs/`. A
failed prerequisite is useful fail-closed evidence, not a G3 pass.

| Attempt/log | Proven result |
|---|---|
| 1 — `first-full-converge-20260713T050027Z.log` | Stopped at the read-only routing-table-registry preflight because vanilla Rocky had `/usr/share/iproute2/rt_tables` and no `/etc` override. Recap: `ok=9`, `changed=0`, `failed=1`; no mutation or container start occurred. |
| 2 — `full-converge-rerun-20260713T050630Z.log` | Established the host firewall/SSH/Docker/network boundary, then stopped before Compose because pristine-host render validation incorrectly required the not-yet-rendered `/opt/ai-gateway/.env`. Recap: `ok=105`, `changed=49`, `failed=1`. The validator now accepts an explicit non-secret validation domain before `.env` exists and requires agreement after it exists. |
| 3 — `full-converge-third-20260713T051551Z.log` | Reached the same render-only gate, then stopped because the deployed validator correctly attempted to inspect `/usr/local/sbin/aigw-docker-log-acl`, but Ansible still installed that helper later. Recap: `ok=99`, `changed=6`, `failed=1`; the application graph had not started. |
| 4 — `full-converge-fourth-20260713T052249Z.log` | Began at `2026-07-13T05:22:49Z` and reached final verification. The final firewalld reload let blank saved `connection.zone` values re-advertise all three physical interfaces into default `public`; the exact-zone verifier stopped the run. Recap: `ok=175`, `changed=33`, `failed=1`, `skipped=14`; ended `2026-07-13T05:26:29Z`, exit 2. |
| 5 — `full-converge-fifth-20260713T053842Z.log` | Began `2026-07-13T05:38:42Z`, ended `05:41:32Z`, and exited 0. Recap: `ok=208`, `changed=7`, `failed=0`, `skipped=15`. Exact saved/runtime/permanent physical-interface zones agreed, `public` was empty, one default route and five policy rules remained, maintenance/native/`DOCKER-USER` guards and exact listeners passed, and no container ID or restart count changed. Pre-restore Vault correctly remained `initialized=false`, `sealed=true`. |

The current source fixes attempt 1 by reading the safe effective registry and
seeding a missing `/etc` override from Rocky's vendor file. For attempt 3, it
installs the exact ACL helper and systemd unit before deployed-layout
validation, while leaving timer activation and immediate reconciliation behind
the later Docker-directory ACL setup. `scripts/validate-compose.sh` contains a
regression assertion for this ordering; its local base/lab render-only run
passed before attempt 4.

Attempt 4 temporarily left the ADM and internal static legs in `public`, so
the wildcard SSH listener was reachable beyond its intended VPN source rule.
The daemon was already key-only with root/password/interactive login and
forwarding disabled, and there was no Cockpit listener. The independent native
nftables and `DOCKER-USER` forward guards remained active and continued to
bound Docker-published DNS/HTTPS to their exact DNAT source/address/port
contracts. These controls reduced impact but do not make the host-input zone
failure acceptable.

The bounded correction treats NetworkManager as authoritative for zone
persistence. For each physical interface it resolves the active connection
UUID, rejects absent/unsafe/duplicate mappings, reads the saved zone, and
modifies only a drifted `connection.zone`. It does not reactivate or cycle a
profile and does not modify addresses, routes, DNS, gateway, or interface
binding. Before later reloads it proves the saved values; final verification
requires exact agreement among saved `connection.zone`, runtime
`firewall-cmd --get-zone-of-interface`, and the permanent zone's sole interface
entry. It also canonicalizes inventory `%%REJECT%%` to firewalld's reported
`REJECT` during target comparison so an unchanged converge does not cause a
spurious final reload. Attempt 5 proved that correction and closed G3. The
later G4–G6 evidence is recorded below; G7 remains open.

### G4 corrected offline restore evidence

The corrected repeat ran from `2026-07-13T07:07:00Z` through `07:07:39Z` and
exited 0. It authenticated the independently held artifact SHA-256, completed
hostile-archive validation before mutation, restored all declared volumes and
captured configuration, and finished with all 23 project containers stopped
and restart sum zero. The marker was a regular, single-link `root:root 0600`
file containing exactly the authenticated artifact SHA-256. Maintenance,
physical zones, routing, native nftables, `DOCKER-USER`, listener, and
persistence-service contracts remained exact; no bootstrap, unseal, runtime
start, Ansible run, marker clear, reload, or reboot occurred during restore.

Protected evidence beneath `deployment-logs/`:

- `state-restore-repeat-20260713T070700Z.log` plus its `.sha256`;
- `state-restore-repeat-20260713T070700Z.receipt`; and
- `state-restore-repeat-20260713T070700Z.receipt.addendum`.

The addendum records that the archive correctly replaced the on-disk
`state-restore.sh` with its older captured copy after the running shell had
already executed the corrected logic. That captured script was not invoked;
the next action was the required designated current-source converge.

### G5 current-source converge, unseal, and runtime evidence

The post-offline-restore converge ran from `2026-07-13T07:20:18Z` through
`07:23:07Z` and exited 0 with `ok=225`, `changed=23`, `failed=0`. It began with
0/23 project containers running, deployed the designated current source,
restored exact bind ownership/modes, retained the exact marker, and recognized
Vault as `initialized=true`, `sealed=true`; no bootstrap or unseal occurred.
It started only the current graph, preserved maintenance and every host/network
boundary, and passed the maintenance-safe direct edge contract
`portal=200`, `api=403`, `admin=403`.

The separately held one-share lab input was then streamed directly to the
approved unseal helper: unseal exited 0 with Vault initialized and unsealed,
without placing the share in argv, environment, a staged file, or logs. The
immediate Compose wait sampled `key-rotator` during its post-unseal recovery
interval and exited 1; the service recovered without a restart or recreation.
One runtime-only retry from `2026-07-13T07:35:20Z` through `07:35:22Z` exited 0
without another share: all 22 long-running services were healthy, all restart
counts were zero, `volume-init` remained exited 0, and the container IDs were
unchanged. The marker and maintenance guard remained exact.

Protected evidence beneath `deployment-logs/`:

- `full-converge-post-offline-restore-current-20260713T072006Z.log`, its
  `.sha256`, and `.receipt`;
- `unseal-runtime-gate-corrected-20260713T073255Z.log`, its `.sha256`, and
  `.receipt`; and
- `runtime-up-only-retry-20260713T073435Z.log`, its `.sha256`, and `.receipt`.

### G6 evidence and disposition

The following sanitized evidence lanes passed while the marker and maintenance
guard remained in place:

- `g6-readonly-persistence-baseline-20260713T075119Z.txt`: the exact
  PostgreSQL ACL/owner/role matrix, LiteLLM tables and safe key inventory, Open
  WebUI schema/counts, retained rotator history, Vault public identity/policies
  and safe path names, and Samba counts/selected immutable IDs passed;
- `identity-g6-readonly-baseline-20260713T074335Z.md` and
  `identity-g6-oidc-ldaps-login-20260713T074919Z.md`: exact realm/provider/
  user/group/service-account IDs, controller usability, hostname-verified
  LDAPS, three real directory login/authorization results, and corrected
  Keycloak logout redirect passed;
- `identity-g6-key-lifecycle-20260713T080137Z.md`: one-time display,
  non-retention, one-active-key denial, explicit deactivate-before-regenerate,
  cleanup, and exact in-memory plaintext scans across Docker, Loki, and the lab
  Cribl sink passed; no active human/acceptance key remained; and
- `g6-infra-observability-acceptance-20260713T074313Z.log` plus
  `g6-post-lifecycle-negative-20260713T081652Z.log`: 22/22 healthy with zero
  restarts, exact topology/hardening/routes/firewalls/listeners, direct edge
  `200/403/403`, Redis/Grafana/Prometheus contracts, existing telemetry flow,
  zero reviewed secret-pattern matches, container cross-plane/host/public
  denials, authoritative non-recursive DNS, and internal management denials
  passed.
- `g6-synthetic-correlation-20260713T084705Z.log` (mode `0600`, immutable,
  SHA-256
  `939132ab7fd5337d6eb24db92554b0364d642baac28e4a00b6993cc2c2e7b3a3`):
  exactly one non-sensitive four-span fake batch traversed Alloy. The positive
  span received all five exact canonical fields; the missing/invalid/
  non-LiteLLM negatives received none. Tempo and the lab Cribl sink each
  received 4/4 spans, spanmetrics reported four, original IDs/timestamps/tags/
  harmless prompt were preserved, drops/losses were zero, queues were empty,
  and runtime/marker/firewall/health/restart state did not drift.

The apparent Keycloak count delta is classified, not waived. The backup held
9 `offline_client_session` plus 9 `offline_user_session` rows, but authenticated
dump inspection proved every row had `offline_flag=0`: they were persistent
online-session records, not offline sessions. Their timestamps predated the
restored Keycloak start by more than the realm's deterministic 1,800-second SSO
idle timeout. Their removal is expected online-session expiry, not durable
identity loss. Excluding those two volatile tables and the one live
`jgroups_ping` membership row, backup and live state matched across 87 tables
and 2,435 rows with the same explicit canonical digest.

Two evidence-coverage gaps remain explicit. The pre-destroy marker retained
opaque historical row-count digests without their canonicalizer/provenance, so
they cannot be independently reproduced or guessed; the G6 baseline instead
records authenticated dump-member hashes and documented supplemental
canonicalizers. The marker also omitted independent pre-destroy controller and
broker certificate fingerprints. Current Vault-backed fingerprints match the
public certificates registered on the exact Keycloak clients and live
controller authentication works, but that is not an exact pre/post fingerprint
comparison.

Current source adds the controller-only `scripts/safe-inventory-marker.py`
contract for future captures. It canonicalizes bounded non-secret
`aigw.safe-inventory/v1` JSON, emits a separate SHA-256/count receipt, rejects
sensitive/malformed fields, and permits only explicitly declared volatile or
append-only comparison policies. Fifteen focused tests passed as part of the
47-test repository suite. The tool is intentionally absent from the VM's
operational-script allow-list and is not retroactive evidence for the old
marker.

The synthetic result closes the configured collector correlation requirement
but is not a provider or LiteLLM request. The customer-supplied Anthropic WIF
configuration is absent: real token exchange, Envoy traversal, end-to-end
LiteLLM inference, and inference-derived telemetry are **NOT EXECUTED**, not
PASS. The lifecycle canary stopped at LiteLLM HTTP 401 with zero Anthropic Envoy
upstream delta and was safely cleaned up. G6 is PASS with that external
dependency and both historical evidence limitations recorded. G7 remains
PENDING; the marker has not been cleared and controlled access has not been
reopened.

### Post-G6 reboot persistence evidence and defects found

The replacement VM has completed exactly one controlled host reboot. The boot
guard loaded after firewalld and before Docker. Across the reboot, all 23
project container identities, image identities, declared volumes, and Docker
networks remained stable; `volume-init` stayed exited zero and did not rerun.
Vault restarted initialized and sealed as designed, accepted exactly one lab
share streamed only on stdin, and returned healthy. All 22 long-running
services then returned healthy with zero Docker restart counts. The durable
semantic comparison matched.

Protected, non-secret evidence includes:

- reboot gate log SHA-256
  `8b98e83e517ca4c2aebb2a9ba0a2e30d945ac38f8d1bb6c0573948393075128d`;
- post-reboot receipt SHA-256
  `5670f0b07c5074f0e06481b5818d22d805c05e6554e82558a523455183638204`;
- manifest SHA-256
  `36bc8c3cc08bf9913f1794b299a1ef3486753946b2ab8d2f91cc1f6f2925b8d2`;
- zero-match secret-scan receipt SHA-256
  `808e4755...`; and
- durable-semantic-match receipt SHA-256
  `fbeecef8...`.

The abbreviated hashes are evidence labels retained in the protected bundle,
not values an operator should reconstruct or pad. Consult that bundle for the
complete receipt names and digests.

The reboot also exposed two real defects, so it does not close G7:

1. `key-rotator` scheduled its zero-interval startup rotations as one-use
   `DateTrigger` jobs. While Vault was sealed, those jobs were consumed and two
   failed history rows were written; unsealing Vault did not recreate them.
2. Docker recreated `/var/lib/docker/containers` without Alloy uid 473's
   required access ACL. The deployed 15-second reconciler repaired child
   entries only. A later Ansible converge restored the parent ACL, proving the
   timer did not make this boundary reboot-safe by itself.

The persistence result remains PASS because restored durable application data
matched; the scheduler and ACL findings are separate release-blocking
operational/security defects.

### Key-rotator sealed-Vault retry remediation

The scheduler now treats sealed or temporarily unavailable Vault as a
deferral: it writes no rotation-history row and schedules a bounded retry.
An explicit driver-requested retry also recreates a `DateTrigger`; ordinary
driver failures remain terminal so permanent errors cannot spin forever. The
change includes disable/manual/race regression coverage. The key-rotator suite
passed 50 tests, and Ruff, high-severity Bandit, and `pip-audit` passed for the
candidate.

One controlled patch converge ran from `2026-07-13T11:01:56Z` through
`11:05:07Z` and exited zero with `ok=223`, `changed=9`, and `failed=0`. It
replaced only the key-rotator container/image; the other 22 project container
identities remained exact. With Vault already available and no configured
static seed keys, it appended exactly two `skipped` rows and no key material.
The prior history prefix and schedule settings remained exact. The protected
comparator has SHA-256
`2115a6633070613b567f9c757506df80fd394033d6d91106bc6bc8ea51359c6d`;
the converge transcript has SHA-256
`4e79d2de9754e667646a986b812b3c3d8c7651e55ef8dbd59e3e0aa8e67b6026`.

That deployment proves the patched image and ordinary available-Vault path;
it does **not** prove the original failure sequence. G7 must restart the Docker
daemon separately under `live-restore`, then explicitly restart only the
profile's long-running services so Vault starts sealed. It must prove zero new
history before unseal, stream the share exactly once through stdin, and observe
the bounded deferred runs complete without failed rows.

### Final security source remediation and rollback recovery

The key-rotator patch converge also exposed a binary-rollback gap. Moving the
mutable local build tag and replacing the old container allowed Docker's
containerd image store to garbage-collect the predecessor OCI image index even
though no operator ran `docker image rm` or a prune. The exact predecessor
image ID is
`sha256:e97456d86594d67c32388868e388efcfd82ead8b866f0d4af3bcd4a2d0cce6e5`.
It has since been recovered from a separately reviewed neutral OCI artifact
and loaded as
`ai-gateway-key-rotator:aigw-rollback-a61ec5c301e447942e30f9de-e97456d86594d67c32388868e388efcfd82ead8b866f0d4af3bcd4a2d0cce6e5`.
The post-load inventory changed only by the expected additional image; all 23
containers were unchanged. The protected receipt is
`exact-key-rotator-e974-load-20260713T120856Z.receipt.json`; the artifact and
receipt are mode `0600`, immutable, single-link, and secret-scan clean. This is
exact image-recovery evidence, not a source-deployment or rollback-execution
pass.

Current source adds a fail-closed pre-build helper. For each planned custom
build it requires exactly one healthy, running, zero-restart Compose container,
proves its desired tag and immutable image ID agree, creates and rechecks an
immutable project/service/full-source-digest rollback reference, and atomically
records schema 2 in a single-link `root:root 0600` manifest. Existing retained
service mappings must still match, and a new generation cannot move a
reference named by the committed manifest. Ambiguous containers, races,
unhealthy sources, missing health contracts, malformed manifests, and
unexpected local Docker context fail the build. A truly container-free first
build is recorded explicitly without inventing an old image, and the temporary
proof is retired after the successful build marker is durable. The shared
build planner now uses a domain-separated, explicitly length-framed stream to
remove the former structural ambiguity between a file payload and its
following inventory record. Focused source tests and render-validation
assertions pass, but these controls have not yet completed their live
deployment gate.

Current source also extends the least-privilege Docker-log ACL reconciler. It
verifies, but does not mutate, the traversal-only uid 473 ACL on
`/var/lib/docker`; repairs access/default ACLs on the configured
`/var/lib/docker/containers` root before walking bounded children; checks that
Docker enumeration itself succeeded; and limits its systemd write boundary to
that containers subtree. Inventory paths/project names receive fail-closed
canonical validation before interpolation. Focused source tests pass, but the
fix has not yet been deployed or proved across a controlled Docker-daemon
restart.
The later source gate also covers the SELinux/MCS, bind-digest, build-framing,
and fail-closed Vault-readiness contracts; test success is not live G7
evidence.

The final source candidate also refuses to mutate a host unless Rocky's
`targeted` SELinux policy is already enforcing, enables and verifies Docker
SELinux integration, recreates the long-running graph under per-container MCS
labels, and asserts exact `z`/`Z` bind contexts, Docker runtime types, live
seccomp/capability state, and zero converge-window AVCs. Only Alloy and node-
exporter retain bounded `label=disable` exceptions for policy-owned host trees.
Per-service keyed bind-source digests close stale-inode exposure after atomic
Ansible replacement; restore removes the local digest key as an epoch change
so current-source converge recreates every restored bind consumer. Finally,
an initialized and unsealed Vault with a failed strict readiness probe now
fails closed instead of entering the reduced bootstrap wait. None of these
source assertions is recorded as live replacement-VM evidence before G7.

During rollback investigation, an audit agent's build-history export command
mistakenly created a literal `/home/ansible/-` file on the VM. It was
immediately made private, scanned, copied byte-for-byte into restricted off-box
quarantine, and removed from the VM. The quarantined 59,908-byte Docker
build-record archive is
`deployment-logs/quarantine-accidental-buildx-history-e97456d-20260713T110929Z.dockerbuild`,
SHA-256
`929e1aa4...`; its receipt and remote-removal evidence are retained separately.
It has not been imported and is not an OCI image archive or rollback proof.
This agent-created artifact is incident evidence only.

## G0 -- establish recoverable off-box custody

Do not destroy or detach the source VM until every item in this section is
present and independently verified.

1. Create a fresh quiesced encrypted backup as described in
   [operations](../operations.md#create-an-encrypted-backup). Prefer a destination
   physically backed by recovery storage. If the lab-only same-device override
   is used, immediately copy the completed `.age` file from the source VM to
   the recovery workstation; the source copy alone is not recovery evidence.
2. On recovery storage, compute SHA-256 again and compare it with the value
   captured directly from `state-backup.sh` and `.state/last-backup.json`.
   Retain that expected value through an authenticated path independent of the
   artifact.
3. With the mode-`0600` age identity on a restricted recovery system, prove the
   copied file is addressed to the expected identity and can be decrypted and
   listed without extracting it into an ordinary user directory. For example:

```bash
sha256sum /recovery/aigw-STATE.tar.gz.age
age-inspect /recovery/aigw-STATE.tar.gz.age
age --decrypt -i /secure-recovery/age-identity.txt \
  /recovery/aigw-STATE.tar.gz.age | tar -tzf - >/dev/null
```

4. Record the backup receipt, artifact byte size, SHA-256, backup UTC time,
   deployment profile, and the restore-script/parser version to be used. Do not
   record decrypted content.
5. Retain a reviewed copy of this repository, its encrypted Ansible Vault
   overlay, the Ansible Vault password through separate custody, and the exact
   inventory. Record a commit identifier when available; when the workspace is
   not under version control, retain a read-only source archive plus a
   deterministic hash manifest instead of inventing a revision.
6. Confirm custody of the **old Vault unseal share** associated with the
   artifact. The backup intentionally excludes `secrets/vault-init.json`; a
   restored file-backed Vault cannot be recovered without the old share.
7. Confirm the recovery workstation retains the automation SSH private key and
   that its public key is available for installation on the new VM. Do not copy
   that private key into the VM or evidence bundle.
8. Capture non-secret pre-destroy persistence markers:

   - deployment profile, Compose image references, and manifest volume list;
   - Keycloak controller/broker public fingerprints and selected realm/client
     identifiers;
   - a named Samba lab user/group membership canary and directory object counts;
   - PostgreSQL database/schema row counts or purpose-built non-secret canary
     rows for LiteLLM, Keycloak, and rotator state;
   - an Open WebUI non-secret application/chat canary and durable record count;
   - API-key record identifiers, active/revoked counts, and hashes only--never
     API-key plaintext;
   - Vault public certificate or public-key fingerprints; and
   - selected non-sensitive telemetry record/trace identifiers and time ranges.

   Feed only a reviewed `aigw.safe-inventory/v1` JSON document through the
   controller-only `scripts/safe-inventory-marker.py canonicalize` command and
   retain its canonical stdout and separate SHA-256/count receipt stderr. Record
   the tool/source identity with the evidence. For comparison, declare only
   reviewed volatile scalar JSON pointers or append-only list prefixes; all
   other fields remain exact.

Do not put API keys, tokens, passwords, session cookies, prompt/completion
bodies, Vault responses, unseal shares, or private keys in the marker set. The
acceptance procedures in [the test runbook](../test-runbook.md) are the source of
truth for obtaining the identity and isolation evidence.

**Stop G0** if the copied checksum differs, the age identity cannot decrypt the
artifact, the artifact/profile is unknown, the source/deployment overlay is
missing, or the old Vault share is not available. Do not rely on the existing
same-device artifact or a hypervisor snapshot as the only copy.

## G1 -- quiesce the source and preserve rollback

1. Close user and ADM ingress for the maintenance window and stop new writes.
2. Finish G0 after that quiesce so the backup represents the final approved
   source state. Remember that backup restarts Vault sealed; either unseal it
   for final source checks or keep the source intentionally offline.
3. Record the source VM identity, hypervisor configuration, virtual disk size,
   Rocky release, CPU/memory, NIC order/network attachment, and the three MAC
   addresses as evidence. Do not reuse the old and new VM simultaneously with
   the same static IPs.
4. Power the source VM off. Retain it without starting it until G7 when
   practical. A retained source VM is a convenient lab rollback, but not a
   substitute for the off-box artifact.
5. If the exercise explicitly requires deleting the source VM, obtain that
   approval only after G0 passes. Deletion makes the verified off-box artifact
   and separately held inputs the recovery path.

**Stop G1** if write quiescence cannot be proved, the final artifact does not
match its receipt, an IP conflict exists, or no approved rollback choice has
been recorded.

## G2 -- recreate the vanilla Rocky 9 VM

Create a new Rocky Linux 9 VM with capacity no smaller than the approved lab
baseline and enough free Docker-root space for both restore staging and the
declared archive. The deployment guide describes 4 vCPU, 12 GiB RAM, and 40 GB
as a low-volume lab only; reproduce the measured current capacity rather than
blindly shrinking to those values.

Attach three adapters in this role order:

| Adapter role | hypervisor attachment | Required Rocky interface/address | Gateway use |
|---|---|---|---|
| egress | shared/NAT lab network | `enp0s5`, `10.211.55.3/24` | only main-table default via `10.211.55.1` |
| ADM | ADM host-only network | `enp0s7`, `10.8.10.10/24` | directly reachable `10.8.10.2`; no main default |
| internal | internal host-only network | `enp0s8`, `10.20.0.10/24` | directly reachable `10.20.0.2`; no main default |

The Mac-side host-only addresses/gateways must already be `10.8.10.2` and
`10.20.0.2`, without DHCP assigning the VM a conflicting address. The initial
Rocky resolver is `10.211.55.1`. The authoritative `aigw.aegisgroup.ch` lab DNS
service does not exist until the stack is deployed.

Interface enumeration can change when virtual hardware/order changes. This
lab profile deliberately asserts the exact names and addresses above. If they
do not match, stop and correct the hypervisor adapter order/virtual hardware or
perform a separately reviewed profile change; do not conceal the mismatch with
an ad hoc Ansible override.

Using the Rocky console, configure persistent NetworkManager connections and
verify before Ansible:

```bash
ip -br -4 address
ip -4 route show table main
ip -4 route get 10.211.55.1 oif enp0s5
ip -4 route get 10.8.10.2 oif enp0s7
ip -4 route get 10.20.0.2 oif enp0s8
getent ahostsv4 example.com
timedatectl status
```

There must be exactly one main-table default route, through `enp0s5`. Install
Python 3, create the `ansible` sudo-capable account, install the controller's
SSH public key in that account, and prove `sudo -n true` works. Keep a console
session open during the first converge because Ansible will harden SSH.

### Replace only the recreated host's SSH key record

A recreated VM correctly has a new SSH host key. Do not disable strict host-key
checking or erase the controller's entire `known_hosts` file. From the VM
console obtain the new Ed25519 fingerprint:

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

On the recovery workstation, scan to a temporary file and compare its
fingerprint with the console value. Only after an exact match, remove the old
record for this IP and install the verified new key:

```bash
umask 077
ssh-keyscan -t ed25519 10.8.10.10 > /tmp/lab-aigw01.hostkey
ssh-keygen -lf /tmp/lab-aigw01.hostkey
ssh-keygen -R 10.8.10.10
cat /tmp/lab-aigw01.hostkey >> ~/.ssh/known_hosts
rm -f /tmp/lab-aigw01.hostkey
ssh -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  ansible@10.8.10.10 sudo -n true
```

If a hostname or non-default port also has an old entry, remove only that exact
entry after the same console comparison.

**Stop G2** for an unexpected fingerprint, a duplicate IP, wrong interface
name/address, more than one default route, failed gateway/time/DNS checks,
password-only SSH, or unavailable non-interactive sudo.

## G3 -- establish the host boundary before state

Do not install or manually start Docker/Compose containers on the vanilla VM.
Run the full ordered playbook from the recovery workstation:

```bash
ansible-galaxy collection install -r ansible/requirements.yml
ansible -i ansible/inventory/lab.yml gateway -m ping
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --ask-vault-pass
```

The full play validates the live topology, installs policy routing, firewalld,
the native nftables guard, and `DOCKER-USER`, and only then installs/starts
Docker, creates the pinned bridges, and renders/starts the empty stack. It is
expected to finish at the documented first-deploy Vault gate without claiming
full application readiness while Vault is uninitialized. Do not use
`deploy-stack-only.yml` for a vanilla host and do not run
`vault-bootstrap.sh`: this is a restore, so the new empty state will be
replaced by the authenticated artifact.

Before admitting restored state, capture the routing/firewall/listener/network
verification results from the full play and confirm the deployed `.env`
contains `DEPLOYMENT_PROFILE=rocky9-lab`. Keep user and ADM client
traffic closed except for the recovery operator.

**Stop G3** if containers existed before policy, the full play reports a
topology/collision/firewall/network ABI error, an unexpected profile is
rendered, or any listener appears on the egress address or `0.0.0.0`.

## Fresh deployment and restore are different paths

Use exactly one path:

- **Fresh lab:** run full Ansible against empty volumes, then run
  `scripts/vault-bootstrap.sh` to initialize a new Vault and new application
  state. Its persistence markers are expected not to match the old system.
- **Recovery rehearsal:** run full Ansible only to establish the host boundary
  and exact empty stack scaffolding, then run `state-restore.sh`. Never run
  `vault-bootstrap.sh`; the restore marker makes replacement initialization a
  hard Ansible failure. Re-converge the full current source with that marker
  present, then unseal the restored Vault with the old separately held share.

Initializing Vault on the recovery path creates replacement state and can
destroy or obscure the evidence the exercise is intended to validate.

## G4 and G5 -- restore and unseal

Copy the immutable encrypted artifact and the age identity to separate
restricted paths on the new VM. Make the identity mode `0600`; retrieve the
expected SHA-256 from the independent authenticated receipt, not from the file
being restored. Then run:

```bash
cd /opt/ai-gateway
sudo ./scripts/state-restore.sh \
  --input /recovery/aigw-STATE.tar.gz.age \
  --identity /secure-recovery/age-identity.txt \
  --sha256 <authenticated-64-character-sha256> \
  --confirm RESTORE_AI_GATEWAY_STATE
```

The script authenticates the encrypted file and completely validates the
hostile outer/nested archive, profile volume set, declared capacity, and staged
configuration before its first destructive stop. Preserve the validation
output as candidate G4 evidence. After exact-volume/configuration replacement,
the corrected script requires zero running project containers and exits zero
without starting the captured graph. It leaves
`.state/restore-required-unseal` as a `root:root 0600` regular single-link file
containing only the independently authenticated artifact SHA-256.

Keep both ingress legs in maintenance and the marker in place. From the
recovery workstation, run the full current-source play again before providing
any old Vault share:

```bash
ansible-playbook -i ansible/inventory/lab.yml ansible/site.yml \
  --ask-vault-pass
```

This converge replaces captured configuration with the designated current
source, applies deterministic non-secret modes and exact private bind-tree
ownership, and starts only the current graph. The marker-aware gate requires
the restored Vault to be initialized and permits it to remain sealed. It
forbids `scripts/vault-bootstrap.sh` and any replacement initialization.

Only after that converge succeeds, prompt for the old share without putting it
in shell history or process arguments, then wait for the complete profile:

```bash
cd /opt/ai-gateway
read -rsp 'Old Vault unseal share: ' AIGW_UNSEAL_SHARE; printf '\n'
printf '%s\n' "$AIGW_UNSEAL_SHARE" | sudo scripts/vault-unseal.sh
unset AIGW_UNSEAL_SHARE
sudo scripts/aigw-runtime-up.sh -d --wait --wait-timeout 300
```

This rehearsal's state artifact predates the current audited Traefik
derivative, firewall, portal, PostgreSQL, build-gate, and deployment-boundary
source. `state-restore.sh` deliberately restores its captured configuration as
data but never executes that graph. Only the post-restore current-source graph
may be unsealed, fully started, or enter G6. Do not treat the pre-restore
host-boundary converge or the backup's older configuration as final release
evidence.

The first destructive restore attempt exited 1 and is failed, quarantined
evidence only. The earlier workflow started the captured graph before current
Ansible reconciled its bind trees; non-root Keycloak could not read the
root-owned restored realm tree. Ingress remained in maintenance, the marker
was not cleared, and no gate was awarded from that attempt. The complete
corrected restore was subsequently repeated from the immutable authenticated
artifact and is the sole G4 evidence described above; the first attempt remains
a failure record and was not repaired into a pass.

**Stop G4/G5** on a checksum/parser/profile/capacity failure, if the restored
Vault does not accept the old share, or if any operator proposes initializing a
new Vault. Also stop if restore exits nonzero, any project container remains
running at restore exit, the marker is not exact, or current-source converge
fails before unseal. Do not expose endpoints, clear the marker, manually mix
files from different backups, or patch restored volumes in place. Preserve the
failed VM for evidence and retry the immutable artifact on a newly rebuilt
clean target.

## G6 -- compare persistence and security

Repeat the complete [acceptance test runbook](../test-runbook.md), including its
stateful recovery section, on the isolated restored target. At minimum compare
every G0 marker and prove:

- PostgreSQL application state and role/database/`CONNECT` ACL matrix match;
- Keycloak and Samba durable identifiers/users/groups match; compare
  controller/broker fingerprints only when the pre-destroy evidence actually
  retained them, and otherwise record the coverage gap rather than inventing a
  baseline;
- Open WebUI durable application/chat data matches. Its deliberately excluded
  embedding cache may require an approved offline reseed before RAG tests;
- API-key hashes, active/revoked state, single-active-key enforcement, and
  one-time display behavior match without revealing key plaintext;
- the restored Vault public identity matches and the key rotator is ready;
- expected telemetry retention markers match, with any accepted gap recorded;
- all containers are healthy with stable restart counts;
- negative routing, firewall, listener, cross-network, OAuth/OIDC logout, and
  secret-leak checks pass; and
- the synthetic collector-correlation lane proves the canonical telemetry
  transform/export path; and
- a permitted provider canary succeeds through the pinned egress path when the
  external provider configuration exists. If Anthropic WIF has not been
  customer-configured, record real exchange/inference as **NOT EXECUTED** and
  do not relabel an HTTP 401 or network-only result as inference PASS.

A fresh-deployment marker set is not acceptable evidence for this gate. Any
unexpected identity/fingerprint or durable-data mismatch is a restore failure,
not a value to update in the expected manifest.

Only after all mandatory G6 evidence passes may the operator remove the marker.
G6 has now passed, but the current checkpoint deliberately retains the marker
and maintenance guard pending a separately authorized G7 transition. Do not run
this command until that transition is authorized:

```bash
sudo rm /opt/ai-gateway/.state/restore-required-unseal
```

## G7 -- unchanged converge and release

G7 is currently on release hold. Complete these steps in order, retaining
sanitized before/after evidence:

1. Reverify the already recovered predecessor key-rotator image against the
   protected neutral-OCI/load receipt and exact immutable schema-2 rollback
   reference. Fail G7 on any image-ID or tag drift. Do not substitute a rebuild
   with a different OCI identity or import an unreviewed build-history record.
2. Freeze and receipt the final source containing the reviewed SELinux/MCS,
   bind-recreation, Vault-readiness, build-framing, rollback-retention, and
   Docker ACL changes plus the frozen portal/identity corrections. Capture a
   fresh semantic baseline and encrypted backup, compute the exact build plan,
   and preserve every affected healthy running predecessor under its immutable
   schema-2 reference before a build changes a mutable tag. Run the full lab
   playbook as a controlled change converge. Require only the reviewed planned
   builds and expected SELinux-generation/bind-digest recreations, and no
   `volume-init` rerun. Verify the helpers' exact deployed ownership/modes and
   the private manifest without printing environment or secret data.
3. With maintenance ingress and the restore marker still intact, capture the
   exact 23-container/image/config/volume/network inventory, rotation-history
   prefix, ACL state, SELinux process/mount/bind contexts, Docker runtime types,
   host packet policy, and durable semantic markers. Require no AVC/USER_AVC in
   the controlled converge window.
4. Restart the Docker daemon once. Because `live-restore` is enabled, require
   the host/native guards to remain active; the same 23 running container IDs,
   images, configurations, volumes, and networks to remain; `volume-init` not
   to rerun; and no unexpected restart/OOM state. Vault is expected to remain
   unsealed in this lane; a daemon restart is not sealed-start evidence.
5. Within the documented timer bound, require Alloy uid 473 traversal on the
   Docker root, `r-x` plus the reviewed default entry on the containers root,
   and exact child/log/non-log ACLs. The timer must fail rather than silently
   pass if Docker enumeration fails. No broader Docker-root write or read
   permission is acceptable.
6. Derive the exact profile-aware service set, require exactly 22 long-running
   services plus the separate one-shot initializer, and explicitly restart
   only the 22 long-running services. Do not use a broad Compose restart or
   dependency traversal. Require `volume-init` to retain its original exited-
   zero timestamps, Vault to start initialized/sealed, and the patched
   scheduler to append no failure or other history row before unseal.
7. Stream exactly one lab unseal share only through stdin. Within the bounded
   scheduler retry, require exactly the expected two static-provider outcomes
   (`skipped` when no seed keys exist), no failed row, and no key material in
   argv, environment, status, logs, or evidence. Return all 22 long-running
   services to healthy with zero Docker restart counts and repeat the durable,
   identity, packet, and telemetry comparisons.
8. Run the full lab playbook again without source or inventory changes. Require
   zero custom-image builds, no initializer rerun, unchanged long-running
   container identities/start times/restart counts, Vault healthy/unsealed,
   exact rollback/ACL/SELinux/bind-digest state, and no changed modeled
   semantic leaf. Repeat the short security/listener/identity smoke set.

Reopen controlled ADM/internal access only when G0 through G7 are PASS. Retain
the evidence bundle and off-box artifact for the approved retention period.
Delete the powered-off old VM or other rollback copy only after explicit
post-acceptance approval.

## Failure and rollback rules

- Before destruction, any missing recovery input or failed verification means
  keep the source VM and return to G0.
- Before restore, any host/network/security-boundary failure means rebuild or
  correct the vanilla VM; do not admit state to a partially secured host.
- After restore starts, never convert a partial target into a fresh deployment,
  never bootstrap over restored Vault data, and never combine volumes from
  separate artifacts. Preserve it for diagnosis and rebuild a clean target.
- If the old source VM was retained, keep it powered off while the recovery VM
  uses the same IPs. Roll back by powering off/isolation of the recovery VM,
  then deliberately restoring the old VM--never run both concurrently.
- If the source VM was deleted, the only rollback is another clean rebuild from
  the independently verified immutable artifact and separately held inputs.
- Do not clear `.state/restore-required-unseal`, reopen client access, or mark a
  gate PASS to work around a timeout, marker mismatch, failed old-share unseal,
  or unhealthy service.
