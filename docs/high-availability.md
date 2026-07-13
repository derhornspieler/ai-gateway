# High Availability and Rolling-Update Matrix

The implemented `generic-rocky9` and `parallels-rocky9-lab` profiles run one
Docker Compose project on one Rocky Linux VM. They are **not highly available**.
Starting two containers on that VM can improve process capacity, but the host,
Docker daemon, kernel, storage, firewalls, physical interfaces, and power remain
one failure domain. Nothing in this document changes that current status or
claims that the future topology is implemented.

This matrix is a bounded design input for a separate production-HA profile.
Product behavior was reviewed against the linked primary documentation on
2026-07-12. Versions and upgrade guarantees change; recheck the exact candidate
versions and license entitlements during implementation.

## Terms and minimum bar

- A **failure domain** is infrastructure that can fail independently: normally
  a separate physical host and, where the customer platform supports it, a
  separate rack or availability zone.
- **Service HA** means a tested loss of one declared failure domain still leaves
  the service usable within its recorded RTO/RPO. It does not mean merely that
  a supervisor restarts a failed container.
- A **rolling update** admits a ready replacement, removes the old instance from
  new traffic, drains in-flight work, and preserves the component's quorum or
  replication factor before proceeding to the next instance.
- The minimum target below generally tolerates one process/host failure.
  Customer RTO/RPO, maintenance capacity, and zone-loss requirements can require
  more instances.

## Request, authentication, and application plane

| Service | Current single-VM state | Minimum future topology and state | Rolling-update rule / blocker |
|---|---|---|---|
| `traefik-int`, `traefik-adm` | One process for each physical leg; file provider; file certificates; no Docker socket | At least two instances **per leg** on separate hosts, behind customer L4 VIPs/load balancers that preserve the ADM/internal separation. Render identical reviewed file-provider config and certificate versions to each node. | Enable a private `/ping` health path. Remove one instance from the external LB, honor Traefik request-accept and graceful-drain intervals, then update it. Keep at least one ready instance per leg. See [Traefik health](https://doc.traefik.io/traefik/reference/install-configuration/observability/healthcheck/) and [entrypoint lifecycle](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/). Certificate issuance/distribution must have one authority; do not make independent edges race renewal. |
| `oauth2-proxy`, `oauth2-proxy-grafana` | One process for each ADM application; encrypted client-side cookie store; separate cookie names | Two or more instances of each proxy on separate hosts, with identical OIDC client configuration and stable cookie/client secrets. The cookie backend is stateless; a customer may instead select an HA Redis session store after evaluating refresh locking and token size. | Route only to `/ready` instances and roll one at a time without rotating secrets. Prove existing cookies and Keycloak role revocation across both replicas. OAuth2 Proxy documents the [cookie/Redis session tradeoff](https://oauth2-proxy.github.io/oauth2-proxy/configuration/session_storage/) and [`/ping` versus `/ready`](https://oauth2-proxy.github.io/oauth2-proxy/features/endpoints/). |
| `litellm` | One container, default one Uvicorn worker, single Postgres/Redis dependencies | At least two one-worker replicas on separate hosts behind the static, socket-free internal load balancer described in [LiteLLM capacity and scaling](litellm-scaling.md). All replicas share the same HA PostgreSQL/Redis services, salt/master keys, reviewed model config, and controlled credential state. | Run schema migration exactly once, start a ready replacement, drain for longer than the longest approved stream, then stop one old replica. Verify rotation/key revocation reaches every replica. Ad hoc Compose `--scale` is not supported. |
| `dev-portal` | One container and exactly one Uvicorn worker; API-key owner/project creation lock is process-local | **Blocked.** Before two replicas are allowed, move key creation/deactivation serialization into a database transaction or distributed lock and prove sessions/CSRF/step-up behavior with a stable shared session secret. Then place at least two replicas on separate hosts behind a static LB. | No rolling no-downtime claim exists today. After the shared lock is implemented, remove a replica from readiness, drain short browser/admin requests, and roll one at a time. The one-time plaintext key must never enter shared state, logs, or a replacement replica. |
| `open-webui` | One instance using local `openwebui_data`; stable encrypted-overlay `WEBUI_SECRET_KEY`; no shared PostgreSQL, Redis WebSocket manager, or external vector store | At least two replicas on separate hosts with the same stable `WEBUI_SECRET_KEY`, external HA PostgreSQL, shared HA Redis for WebSocket/application coordination, and a supported external vector/object store. Local SQLite/Chroma storage is not multi-replica storage. | Preserve the signing-secret digest, run database migration once, admit ready replicas, and drain WebSocket/stream connections before stopping an old node. Open WebUI's current [Scaling and HA guide](https://docs.openwebui.com/getting-started/advanced-topics/scaling/) and [environment contract](https://docs.openwebui.com/reference/env-configuration/) require PostgreSQL/Redis and coordinated migrations for multi-replica use. |
| `keycloak` | One DHI Keycloak node with embedded distributed-cache defaults and one PostgreSQL container | At least two Keycloak nodes on separate machines; three gives maintenance headroom. Use the same HA PostgreSQL writer endpoint, stable cluster name/node topology, supported cache discovery, TLS, and an external LB. Configure topology awareness and keep cache owners on different machines. | Change one member at a time and never remove multiple embedded-cache members together. Keycloak documents [distributed caches](https://www.keycloak.org/server/caching), [horizontal scaling](https://www.keycloak.org/getting-started/getting-started-scaling-and-tuning), and [update compatibility](https://www.keycloak.org/server/update-compatibility). Patch rolling compatibility is not permission to mix arbitrary major/minor versions; use the version-specific supported procedure and prove OIDC/admin/session continuity. |
| `key-rotator` | One process owns schedules, provider rotation, identity control, cleanup, and its internal API; managed-group topology serialization is process-local | **Blocked.** Split or coordinate the stateless API and singleton scheduler/controller duties with a fenced PostgreSQL lease/leader election. Replace the in-process group topology lock with a database-backed or distributed fenced lock. At least two API instances may then run on separate hosts; exactly one healthy lease holder may mutate a vendor credential, Keycloak identity state, group topology, or cleanup job at a time. | A new worker must acquire the fenced lease before the old leader releases/expires it; overlapping leaders are a release blocker. Rotation and identity state must make retries idempotent after leader loss. Roll API instances independently only after all callers use a stable static LB endpoint. |

## Identity, data, secrets, egress, and DNS plane

| Service | Current single-VM state | Minimum future topology and state | Rolling-update rule / blocker |
|---|---|---|---|
| `samba-ad` / customer directory | One disposable lab-only Samba DC; no published ports | The production-HA profile must not deploy this container. Use the customer's supported AD/LDAP service with at least two writable directory/DNS servers in independent failure domains, correct site/SRV discovery, independently trusted LDAPS certificates, backup, and customer-owned recovery. | Directory maintenance is customer-owned. Keycloak federation must contain tested failover endpoints/discovery and must never disable certificate/hostname validation to survive an outage. Microsoft documents why [DCs must span independent platforms](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/virtualized-domain-controller-deployment-and-configuration) and how [DC locator uses DNS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/dc-locator). |
| `postgres` | One PostgreSQL process and one local `pg_data` volume serving three databases | Customer-selected managed PostgreSQL HA or a separately operated cluster with one writable primary, standby capacity in independent domains, a fenced automatic-failover controller/stable writer endpoint, WAL archive/base backups, and declared synchronous/asynchronous RPO. Do not share `PGDATA` as a network filesystem. | Database minor/major and failover semantics come from the selected service/controller. Keep primary/standbys at supported versions, prove replication lag and fencing, update standbys first where supported, perform controlled switchover, then update the former primary. PostgreSQL documents [streaming, synchronous replication, and standby tradeoffs](https://www.postgresql.org/docs/current/warm-standby.html); it does not supply this repository with an automatic failover control plane. |
| `redis` | One password-protected tmpfs instance; loss discards cache/router state | Customer chooses an HA Redis service. A bounded Sentinel design needs a primary, at least one replica on another host, and at least three Sentinel voters on independent hosts; a managed service or Redis Cluster is an alternative. Define persistence, TLS/auth, eviction, acknowledged-write loss window, and client Sentinel/Cluster support for every consumer. | Roll replicas/Sentinels before a controlled primary failover and never lose Sentinel quorum. Test client rediscovery and Pub/Sub/WebSocket behavior. Redis requires at least [three independent Sentinels](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/) for a robust deployment and documents the [asynchronous replication loss window](https://redis.io/docs/latest/operate/oss_and_stack/management/replication/). |
| `vault` | One file-backed node, plaintext isolated listener, 1-of-1 lab unseal | Replace with Vault Integrated Storage, TLS end to end, protected audit devices, approved auto-unseal or multi-custodian ceremony, snapshots, and a load balancer. HashiCorp's maximum-resiliency reference uses **five voting nodes across three zones**, tolerating two-node or one-zone loss; a smaller quorum requires an explicitly weaker failure target. | Snapshot first, preserve Raft quorum, update/unseal/validate one follower at a time, and transfer leadership deliberately before the active node. Route using `/v1/sys/health`; do not replace members faster than Raft can stabilize. See the [Integrated Storage reference architecture](https://developer.hashicorp.com/vault/tutorials/raft/raft-reference-architecture) and [HA request behavior](https://developer.hashicorp.com/vault/docs/concepts/ha). |
| `envoy-egress` | One fixed-IP Envoy is the only workload egress identity | At least two Envoy instances on separate hosts, each with a unique fixed firewall identity and identical exact routes/SAN/CA pins. Application LBs/service discovery select only ready proxies; every host firewall still denies direct application egress. | Pre-validate the new image/config/pins, add a ready replacement, stop new selections to the old proxy, and drain connections before removal. Envoy documents [drain/hot-restart behavior](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/hot_restart.html), but cross-host endpoint registration and firewall changes remain Ansible/customer infrastructure work. |
| `lab-dns` / production DNS | One authoritative, non-recursive CoreDNS lab process bound to both test legs | The lab service remains non-HA. Production uses customer authoritative DNS with at least two authoritative servers/resolver paths in independent domains, split-view records for ADM/internal VIPs, controlled zone serials, DNSSEC if required, and no egress-listener/recursion regression. | Publish records/certificates before traffic cutover, update one authoritative server at a time, verify both views/negative answers, then retire old addresses after TTL expiry. DNS platform choice, delegation, DNSSEC keys, and resolver failover are customer blockers. |
| `volume-init` | Versioned, networkless one-shot; reruns only when absent, previously failed, definition-changed, or owner/mode-drifted | It is not an HA service. In a future profile, each stateful subsystem owns its storage initialization/migration job; quorum services must not point multiple initializers at one live data path. | Run once per new or drifted target before admitting its service. Never execute it as a broad application dependency during rolling updates. The final 2026-07-13 lab idempotence run preserved its hash/timestamps/zero exit and every long-running container; repeat that proof after later definition changes. |

## Observability plane

| Service | Current single-VM state | Minimum future topology and state | Rolling-update rule / blocker |
|---|---|---|---|
| `alloy` | One collector receives OTLP and tails this host's Docker/Vault files; local positions/WAL | Run one local file-tail agent per application host; do not have multiple agents race the same file/positions directory. For shared OTLP ingress, use at least two gateway collectors on separate hosts behind a static LB. If Alloy clustering is selected, enable it only on components that support clustering and test duplicate/loss behavior. | Roll host agents one host at a time while the other application hosts remain observable; persistent local queues/positions bound gaps on that host. Roll gateway collectors behind readiness. [Alloy clustering](https://grafana.com/docs/grafana-cloud/send-data/alloy/get-started/clustering/) is component opt-in, not automatic HA for every pipeline. |
| `prometheus` | One local TSDB and no Alertmanager/notification route | Two identical Prometheus servers on separate hosts, each scraping every target independently, with distinct external replica labels. Choose an HA query/deduplication and durable remote-storage layer (for example, a customer-operated compatible system); deploy an HA Alertmanager path if paging is required. | Reload/replace one replica at a time and keep the other scraping. Prove rule equivalence, alert deduplication, query deduplication, and remote-write backlog. The [Prometheus HA guidance](https://prometheus.io/docs/introduction/faq/#can-prometheus-be-made-highly-available) explicitly uses identical servers on separate machines. |
| `loki` | One monolithic process with local filesystem storage | Move to the current supported distributed/microservices topology with shared production object storage, ring/member discovery, replicated ingesters, and enough instances across at least three domains to maintain the chosen replication factor. Do not build new production design on deprecated Simple Scalable mode. | Follow component/ring-specific rollout order; maintain replication and wait for readiness/hand-off before removing an ingester. Compactor/backend singleton or lease semantics must be explicit. Loki documents [deployment modes](https://grafana.com/docs/loki/latest/get-started/deployment-modes/) and warns that [local filesystem storage is not HA](https://grafana.com/docs/loki/latest/configure/storage/). |
| `tempo` | One monolithic process with local filesystem blocks | Use Tempo microservices mode across independent hosts, a supported Kafka-compatible durable queue, production object storage, and redundant distributors/query components. Size replication/retention for prompt-bearing sensitive traces. | Roll stateless query/distributor tiers behind readiness; preserve Kafka quorum/retention and object storage while stateful/backend components roll according to their version guide. Tempo 3 documents [microservices prerequisites](https://grafana.com/docs/tempo/latest/set-up-for-tracing/setup-tempo/plan/) and [object-storage durability](https://grafana.com/docs/tempo/latest/reference-tempo-architecture/object-storage/). |
| `grafana` | One instance with local SQLite in `grafana_data`; oauth2-proxy plus local login | At least two Grafana instances on separate hosts behind the ADM LB, using the same HA PostgreSQL/MySQL database, secret key, plugins, and provisioning. Configure Grafana Alerting HA separately if it becomes the paging path. | Migrate SQLite and run schema migration under the documented version procedure, then roll one ready instance at a time. The shared database carries sessions, so sticky routing is not the HA mechanism. See [Grafana HA](https://grafana.com/docs/grafana/latest/setup-grafana/set-up-for-high-availability/) and [Alerting HA](https://grafana.com/docs/grafana/latest/alerting/set-up/configure-high-availability/). |
| `node-exporter` | One exporter for the one Rocky host | Run exactly one host exporter per production host and scrape all of them from both Prometheus replicas. Two exporters on one host do not make that host available. | Update one host at a time and expect/alert on a bounded metric gap for that host. Prometheus recommends [one exporter beside each monitored instance](https://prometheus.io/docs/instrumenting/writing_exporters/#deployment). |
| `cribl-mock` / external Cribl | One non-durable lab debug sink | Do not deploy the mock in production. Use the customer Cribl Stream/Cloud architecture: multiple Workers in the destination Worker Group across independent hosts, load-balanced OTLP endpoints, persistent queues where required, and—if customer-managed/entitled—primary plus standby Leaders and protected failover state. | Follow Cribl's order: update standby Leader, fail over, update former primary, then roll Worker Nodes in batches without taking them newer than the Leader. Worker loss can lose in-memory data unless persistent queues are configured. See [distributed deployment](https://docs.cribl.io/stream/deploy-distributed/), [Leader HA](https://docs.cribl.io/stream/deploy-add-second-leader/), and [HA upgrade order](https://docs.cribl.io/stream/manage-ha/). |

## Bounded future `production-ha` profile

This must be a separate architecture, not another Compose overlay on
`aigw01`. A minimum implementation plan is:

1. Place application instances on at least two independent Rocky/container
   hosts; place quorum voters across three independent domains where the
   selected state service requires them. A three-host footprint does not by
   itself satisfy the five-node Vault reference architecture.
2. Supply external ADM/internal VIPs or load balancers, authoritative DNS,
   routed private service networks, and a deterministic endpoint inventory.
   Host-local Compose bridges and service-name DNS do not span hosts.
3. Continue to render static Traefik/application load-balancer backends from
   reviewed inventory. Do not mount the Docker socket or enable broad
   label-based discovery.
4. Replace local state with customer-selected HA PostgreSQL, HA Redis, object
   storage, Kafka-compatible Tempo queue, Vault Raft storage/unseal, production
   AD/LDAP, and production Cribl endpoints before increasing application
   replicas that depend on them.
5. Encrypt every cross-host application/data path and extend the exact
   firewalld/nftables/egress identity model to each host. A replica may not gain
   direct vendor, database, telemetry, or host access merely to simplify
   discovery.
6. Render per-service readiness, drain, disruption/quorum, migration, backup,
   and rollback policy. Ansible must update one declared failure domain at a
   time and stop if capacity/quorum falls below the service contract.

## Customer infrastructure decisions that block implementation

The repository cannot safely choose these on the customer's behalf:

- number/location of physical hosts, racks/zones, latency, maintenance
  headroom, and required host/zone failure tolerance;
- orchestrator or multi-host service-registration mechanism, routed network
  ranges, VIP/load-balancer ownership, and source-IP preservation;
- PostgreSQL failover controller/managed service and synchronous versus
  asynchronous RPO;
- Redis Sentinel, Cluster, or managed service; persistence and acknowledged
  write-loss policy;
- production object storage and Kafka-compatible service for Loki/Tempo;
- Vault node count, Enterprise/community scope, KMS/HSM or custodian unseal,
  PKI, audit archive, and snapshot custody;
- production AD/LDAP servers, DNS/SRV design, bind identity, CA, sites, and
  recovery owner;
- Cribl Cloud versus on-prem licensing, Leader failover, Worker Group,
  persistent queues, TLS/client authentication, and retention;
- certificate issuer/renewal authority and secure distribution to every edge;
  and
- measurable RTO/RPO/SLO, peak/soak workload, evidence retention, and the
  acceptable behavior of each service when a dependency is degraded.

## HA and rolling-update acceptance

Do not approve the future profile from container-count screenshots. On a
production-equivalent environment, record and pass all applicable tests:

1. remove one **physical host/failure domain**, not only one container, and
   prove the declared API, login, administration, rotation, and telemetry RTO;
2. where zone loss is claimed, isolate that zone and prove quorum, fencing,
   routing, capacity, and RPO while the topology is degraded;
3. perform the exact rolling sequence for every service, including migrations,
   readiness removal, long-stream drain, and rollback;
4. prove OIDC sessions, role revocation, one-active-key enforcement, provider
   credential rotation, and audit attribution remain consistent across all
   replicas;
5. prove database, Redis, Vault, object-store, Kafka, AD, DNS, and Cribl
   failovers independently and in the combinations allowed by the failure
   model;
6. quantify duplicate/lost logs, metrics, and traces during collector/backend
   failover and keep them inside the approved evidence policy;
7. prove every replica retains the same network isolation, exact egress path,
   TLS validation, secret scope, and query/header redaction as the single-host
   profile;
8. verify no runtime component has Docker-socket access and endpoint/config
   changes are reviewable, deterministic inventory changes; and
9. complete backup/restore and disaster-recovery exercises separately—HA is
   not a backup and successful failover is not proof of recoverability.
