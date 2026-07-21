from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_ROOT = ROOT / "compose/grafana/provisioning/dashboards"


def panels(dashboard: dict) -> list[dict]:
    result: list[dict] = []
    pending = list(dashboard.get("panels", []))
    while pending:
        panel = pending.pop()
        result.append(panel)
        pending.extend(panel.get("panels", []))
    return result


class GrafanaProvisioningContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.provider = (DASHBOARD_ROOT / "dashboards.yml").read_text()
        cls.dashboard_files = sorted((DASHBOARD_ROOT / "json").glob("*.json"))
        cls.dashboards = [json.loads(path.read_text()) for path in cls.dashboard_files]
        cls.stack = (ROOT / "ansible/roles/docker_stack/tasks/main.yml").read_text()
        cls.verify = (ROOT / "ansible/roles/verify/tasks/main.yml").read_text()
        cls.compose = (ROOT / "compose/docker-compose.yml").read_text()

    def test_provider_is_immutable_and_scans_only_the_reviewed_json_directory(self) -> None:
        self.assertIn("name: AI Gateway", self.provider)
        self.assertIn("folderUid: aigw", self.provider)
        self.assertIn("allowUiUpdates: false", self.provider)
        self.assertIn("disableDeletion: false", self.provider)
        self.assertIn(
            "path: /etc/grafana/provisioning/dashboards/json", self.provider
        )
        for directory in ("alerting", "plugins"):
            self.assertTrue((DASHBOARD_ROOT.parent / directory).is_dir())
            self.assertTrue((DASHBOARD_ROOT.parent / directory / "empty.yml").is_file())

    def test_dashboard_directory_holds_exactly_the_provisioned_files(self) -> None:
        # Grafana's file provisioner reads *every* JSON file in this directory and
        # keys dashboards by uid. A stray copy (e.g. a macOS "rocky9-host 2.json")
        # therefore provisions a second dashboard under an already-claimed uid, and
        # it is silently folded into the uid->title mapping asserted below. The
        # duplicate is also hashed into AIGW_BIND_DIGEST_GRAFANA by
        # compute-bind-source-digests.py, which walks grafana/provisioning
        # recursively, so it perturbs the bind-source attestation of content that
        # the docker_stack allow-list never actually deploys. Pin the file set.
        self.assertEqual(
            {path.name for path in self.dashboard_files},
            {
                "ai-gateway-live-logs.json",
                "ai-gateway-overview.json",
                "ai-gateway-request-audit.json",
                "ai-gateway-top-projects.json",
                "ai-gateway-top-users.json",
                "edge-identity-services.json",
                "grafana-lgtm-stack.json",
                "rocky9-host.json",
            },
        )
        self.assertEqual(len(self.dashboards), 8)

    def test_exact_dashboard_inventory_is_deterministic(self) -> None:
        self.assertEqual(
            {dashboard["uid"]: dashboard["title"] for dashboard in self.dashboards},
            {
                "aigw-live-logs": "AI Gateway Live Logs",
                "aigw-overview": "AI Gateway Overview",
                "aigw-request-audit": "AI Gateway Request Audit",
                "aigw-top-projects": "AI Gateway Top Projects",
                "aigw-top-users": "AI Gateway Top Users",
                "aigw-edge-identity": "Edge, Egress and Identity Services",
                "aigw-grafana-lgtm": "Grafana LGTM Stack",
                "aigw-rocky9-host": "Rocky 9 Host (Node Exporter)",
            },
        )
        for dashboard in self.dashboards:
            self.assertIs(dashboard["editable"], False)
            self.assertIsNone(dashboard["id"])
            self.assertGreaterEqual(dashboard["schemaVersion"], 41)

    def test_panels_use_only_the_provisioned_builtin_datasource_uids(self) -> None:
        allowed = {
            ("prometheus", "prometheus"),
            ("loki", "loki"),
            # Owner-approved read-only LiteLLM spend datasource (grafana_ro).
            ("grafana-postgresql-datasource", "litellm-spend"),
        }
        observed: set[tuple[str, str]] = set()
        for dashboard in self.dashboards:
            for panel in panels(dashboard):
                references = [panel.get("datasource")]
                references.extend(target.get("datasource") for target in panel.get("targets", []))
                for reference in references:
                    if reference is None:
                        continue
                    pair = (reference.get("type"), reference.get("uid"))
                    self.assertIn(pair, allowed)
                    observed.add(pair)
            for variable in dashboard.get("templating", {}).get("list", []):
                reference = variable.get("datasource")
                if reference is not None:
                    pair = (reference.get("type"), reference.get("uid"))
                    self.assertIn(pair, allowed)
                    observed.add(pair)
        self.assertIn(("prometheus", "prometheus"), observed)
        self.assertIn(("loki", "loki"), observed)
        self.assertIn(("grafana-postgresql-datasource", "litellm-spend"), observed)

    def test_request_audit_reads_the_dedicated_loki_request_stream(self) -> None:
        """The audit surface is the Loki stream Alloy derives from
        litellm_request spans (service_name="aigw-requests"): every query
        targets that exact stream through the Loki datasource with logfmt
        field extraction, and cost/user panels aggregate its fields."""
        dashboard = next(
            item for item in self.dashboards if item["uid"] == "aigw-request-audit"
        )
        loki_targets = [
            target
            for panel in panels(dashboard)
            for target in panel.get("targets", [])
            if target.get("datasource", {}).get("uid") == "loki"
        ]
        self.assertEqual(len(loki_targets), 4)
        rendered = "\n".join(target["expr"] for target in loki_targets)
        for target in loki_targets:
            self.assertIn('{service_name="aigw-requests"', target["expr"])
            self.assertIn("| logfmt", target["expr"])
        for field in (
            "aigw_user_id",
            "aigw_user_name",
            "aigw_project_id",
            "aigw_api_key_id",
            "gen_ai_cost_total_cost",
            "count_over_time",
            "sum_over_time",
            "unwrap gen_ai_cost_total_cost",
        ):
            self.assertIn(field, rendered)
        self.assertNotIn("aigw_api_key_alias", rendered)
        self.assertNotIn("tempo", json.dumps(dashboard))

        # Label-backed filter controls: the User/Project dropdowns read the
        # bounded aigw_user_name / aigw_project_id stream labels and must be
        # wired into the requests-by-user, cost-by-project, and recent-request
        # panels; All (allValue ".*") also matches lines missing the label so
        # the panels keep working with no selection and with legacy lines.
        variables = {
            variable["name"]: variable
            for variable in dashboard["templating"]["list"]
        }
        for name, label_name in (
            ("user", "aigw_user_name"),
            ("project", "aigw_project_id"),
        ):
            variable = variables[name]
            self.assertEqual(variable["type"], "query")
            self.assertEqual(
                variable["query"],
                'label_values({service_name="aigw-requests"}, %s)' % label_name,
            )
            self.assertTrue(variable["includeAll"])
            self.assertEqual(variable["allValue"], ".*")
        filtered = [
            target["expr"]
            for target in loki_targets
            if 'aigw_user_name=~"$user"' in target["expr"]
        ]
        self.assertEqual(len(filtered), 3)
        for expr in filtered:
            self.assertIn('aigw_project_id=~"$project"', expr)

    def test_overview_queries_match_the_live_metric_schema(self) -> None:
        overview = next(item for item in self.dashboards if item["uid"] == "aigw-overview")
        expressions = {
            target["expr"]
            for panel in panels(overview)
            for target in panel.get("targets", [])
        }
        required_fragments = (
            "up",
            "traefik_service_requests_total",
            "traces_span_metrics_calls_total",
            "status_code",
            "service_name",
            "span_name",
            "traces_span_metrics_duration_milliseconds_bucket",
            "otelcol_exporter_sent_log_records_total",
            "loki_write_sent_entries_total",
        )
        rendered = "\n".join(expressions)
        for fragment in required_fragments:
            self.assertIn(fragment, rendered)

    def test_component_dashboards_use_scraped_native_metric_contracts(self) -> None:
        expected = {
            "aigw-rocky9-host": (
                "node_boot_time_seconds",
                "node_cpu_seconds_total",
                "node_memory_MemAvailable_bytes",
                "node_memory_MemTotal_bytes",
                "node_load1",
                "node_load5",
                "node_load15",
                "node_network_receive_bytes_total",
                "node_network_transmit_bytes_total",
                "node_filesystem_avail_bytes",
                "node_filesystem_size_bytes",
            ),
            "aigw-grafana-lgtm": (
                "loki_distributor_lines_received_total",
                "traces_span_metrics_calls_total",
                "otelcol_exporter_send_failed_log_records_total",
                "otelcol_exporter_send_failed_spans_total",
                "prometheus_tsdb_head_samples_appended_total",
                "otelcol_exporter_queue_size",
                "otelcol_exporter_queue_capacity",
                "loki_request_duration_seconds_bucket",
                "grafana_datasource_request_duration_seconds_bucket",
                "process_resident_memory_bytes",
            ),
            "aigw-edge-identity": (
                "traefik_service_requests_total",
                "traefik_tls_certs_not_after",
                "keycloak_credentials_password_hashing_validations_total",
                "envoy_cluster_upstream_rq_xx",
                "jvm_memory_used_bytes",
                "jvm_memory_max_bytes",
            ),
        }
        for uid, metrics in expected.items():
            dashboard = next(item for item in self.dashboards if item["uid"] == uid)
            expressions = "\n".join(
                target["expr"]
                for panel in panels(dashboard)
                for target in panel.get("targets", [])
            )
            for metric in metrics:
                self.assertIn(metric, expressions)
            self.assertNotIn("cadvisor", expressions.lower())
            self.assertNotIn("container_", expressions.lower())
            # Node Exporter is containerised and selinuxfs is not mounted into its
            # namespace; --path.rootfs does not apply to the selinux collector, which
            # resolves the mount from its own /proc/self/mountinfo. node_selinux_enabled
            # is therefore hard-pinned at 0 on this stack even though the host runs
            # Enforcing, and a panel bound to it renders a false red "Disabled". Host
            # SELinux state is gated by the Ansible verify role, not by Grafana.
            self.assertNotIn("node_selinux", expressions)
        lgtm = next(item for item in self.dashboards if item["uid"] == "aigw-grafana-lgtm")
        lgtm_queries = "\n".join(
            target["expr"]
            for panel in panels(lgtm)
            for target in panel.get("targets", [])
        )
        self.assertIn('== bool 4', lgtm_queries)
        self.assertNotIn('tempo', lgtm_queries)
        edge = next(item for item in self.dashboards if item["uid"] == "aigw-edge-identity")
        edge_queries = "\n".join(
            target["expr"]
            for panel in panels(edge)
            for target in panel.get("targets", [])
        )
        self.assertIn('== bool 4', edge_queries)

    def test_logs_dashboard_has_bounded_operational_filters_and_no_secret_query(self) -> None:
        dashboard = next(item for item in self.dashboards if item["uid"] == "aigw-live-logs")
        log_panels = [panel for panel in panels(dashboard) if panel.get("type") == "logs"]
        self.assertEqual(len(log_panels), 1)
        expression = log_panels[0]["targets"][0]["expr"]
        for label in ("service", "job", "project", "stream"):
            self.assertIn(f'{label}=~"${{{label}:regex}}"', expression)
        lowered = expression.lower()
        for forbidden in ("api_key", "authorization", "bearer", "prompt"):
            self.assertNotIn(forbidden, lowered)
        variables = {
            variable["name"]: variable
            for variable in dashboard["templating"]["list"]
        }
        # Loki rejects a selector in which every matcher can match an empty
        # string. Service is present on both Docker and Vault-audit streams,
        # while project is absent from Vault audit records. Keep service as
        # the non-empty matcher so the All view includes both data classes.
        self.assertEqual(variables["service"]["allValue"], ".+")
        self.assertEqual(variables["project"]["allValue"], ".*")

    def test_ansible_deploy_and_verify_contract_tracks_every_file(self) -> None:
        expected = {
            "grafana/provisioning/alerting/empty.yml",
            "grafana/provisioning/dashboards/dashboards.yml",
            "grafana/provisioning/dashboards/json/ai-gateway-live-logs.json",
            "grafana/provisioning/dashboards/json/ai-gateway-overview.json",
            "grafana/provisioning/dashboards/json/ai-gateway-request-audit.json",
            "grafana/provisioning/dashboards/json/ai-gateway-top-projects.json",
            "grafana/provisioning/dashboards/json/ai-gateway-top-users.json",
            "grafana/provisioning/dashboards/json/edge-identity-services.json",
            "grafana/provisioning/dashboards/json/grafana-lgtm-stack.json",
            "grafana/provisioning/dashboards/json/rocky9-host.json",
            "grafana/provisioning/plugins/empty.yml",
            "grafana/provisioning/plugins/loki-drilldown.yml",
        }
        for relative in expected:
            self.assertIn(relative, self.stack)
            self.assertIn(relative, self.verify)
        for uid in (
            "aigw-overview",
            "aigw-live-logs",
            "aigw-request-audit",
            "aigw-top-projects",
            "aigw-top-users",
            "aigw-edge-identity",
            "aigw-grafana-lgtm",
            "aigw-rocky9-host",
        ):
            self.assertIn(uid, self.verify)

    def test_ansible_removes_only_unmanaged_dashboard_artifacts_before_copy(self) -> None:
        cleanup = self.stack.split(
            "- name: Find existing Grafana dashboard artifacts", 1
        )[1].split("- name: Sync allow-listed compose configuration files", 1)[0]
        self.assertIn(
            'paths: "{{ stack_dir }}/grafana/provisioning/dashboards/json"',
            cleanup,
        )
        self.assertIn("recurse: false", cleanup)
        self.assertIn("hidden: true", cleanup)
        self.assertIn("file_type: any", cleanup)
        self.assertIn("- name: Remove unmanaged Grafana dashboard artifacts", cleanup)
        self.assertIn("state: absent", cleanup)
        self.assertIn("not (item.isreg | default(false) | bool)", cleanup)
        self.assertIn("(item.path | basename) not in", cleanup)
        for name in (
            "ai-gateway-live-logs.json",
            "ai-gateway-overview.json",
            "ai-gateway-request-audit.json",
            "ai-gateway-top-projects.json",
            "ai-gateway-top-users.json",
            "edge-identity-services.json",
            "grafana-lgtm-stack.json",
            "rocky9-host.json",
        ):
            self.assertIn(name, cleanup)
        self.assertIn("FROM resource", self.verify)
        self.assertIn("WHERE namespace = 'default'", self.verify)
        self.assertIn("\"group\" = 'dashboard.grafana.app'", self.verify)
        self.assertNotIn("FROM dashboard JOIN dashboard_provisioning", self.verify)

    def test_offline_grafana_never_runtime_downloads_optional_apps(self) -> None:
        grafana = self.compose.split("  grafana:\n", 1)[1].split(
            "  cribl-mock:\n", 1
        )[0]
        for setting in (
            "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH: /etc/grafana/provisioning/dashboards/json/ai-gateway-overview.json",
            'GF_PLUGINS_PREINSTALL_DISABLED: "true"',
            'GF_PLUGINS_PLUGIN_ADMIN_ENABLED: "false"',
            'GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED: "true"',
            'GF_ANALYTICS_REPORTING_ENABLED: "false"',
            'GF_ANALYTICS_CHECK_FOR_UPDATES: "false"',
            'GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES: "false"',
            # Plugins load only from the image-baked, root-owned vendor path;
            # Grafana's default (tmpfs-masked) plugin path stays unreferenced.
            "GF_PATHS_PLUGINS: /usr/share/aigw/grafana-plugins",
        ):
            self.assertIn(setting, grafana)
        self.assertIn(
            "/var/lib/grafana/plugins:uid=65532,gid=65532,mode=0700,noexec,nosuid,nodev",
            grafana,
        )
        volume_init = self.compose.split("  volume-init:\n", 1)[1].split(
            "  traefik-int:\n", 1
        )[0]
        self.assertNotIn("/state/grafana/plugins", volume_init)

    def test_loki_drilldown_app_is_vendored_version_and_checksum_pinned(self) -> None:
        """Air-gap contract: the sole Grafana app plugin is fetched at image
        build with a mandatory sha256, safely re-extracted by the reviewed
        stdlib-only tool, and byte-inventory asserted — never downloaded by
        Grafana at runtime."""
        dockerfile = (
            ROOT / "services/dhi-health-probe/Dockerfile.grafana"
        ).read_text()
        for required in (
            "ADD --checksum=sha256:"
            "fce6beb37d0fb2fef9b24d307a8ed9d9d1dca9309ba1f7b2370f16041eb23f4a",
            "https://grafana.com/api/plugins/grafana-lokiexplore-app/versions/2.2.1/download",
            "sha256sum -c -",
            "/out/aigw-extract-plugin /aigw/grafana-lokiexplore-app-2.2.1.zip",
            "'plugin=grafana-lokiexplore-app'",
            "'version=2.2.1'",
            "'entries=193'",
            "'files=171'",
            "'directories=22'",
            "'bytes=18091195'",
            'test "$result" = "$expected"',
            "RUN --network=none",
        ):
            self.assertIn(required, dockerfile)
        self.assertNotIn("GF_INSTALL_PLUGINS", dockerfile)
        extractor = (
            ROOT / "services/dhi-health-probe/cmd/extract-plugin/main.go"
        ).read_text()
        for required in (
            "maxEntries",
            "maxTotalBytes",
            "safeRelative",
            "os.O_WRONLY|os.O_CREATE|os.O_EXCL",
            "io.LimitReader",
            "neither a regular file nor a directory",
        ):
            self.assertIn(required, extractor)
        grafana = self.compose.split("  grafana:\n", 1)[1].split(
            "  cribl-mock:\n", 1
        )[0]
        self.assertIn("dockerfile: Dockerfile.grafana", grafana)
        self.assertIn("image: ai-gateway/dhi-grafana:13.1.0-aigw1", grafana)
        apps = (
            ROOT / "compose/grafana/provisioning/plugins/loki-drilldown.yml"
        ).read_text()
        self.assertIn("type: grafana-lokiexplore-app", apps)
        self.assertIn("disabled: false", apps)
        self.assertIn("plugin_setting", self.verify)
        self.assertIn("grafana-lokiexplore-app", self.verify)

    def test_spend_datasource_is_readonly_env_credential_and_pinned(self) -> None:
        datasources = (
            ROOT / "compose/grafana/provisioning/datasources/datasources.yml"
        ).read_text()
        for required in (
            "name: LiteLLM Spend",
            "type: grafana-postgresql-datasource",
            "uid: litellm-spend",
            "url: postgres:5432",
            "user: grafana_ro",
            "database: litellm",
            "postgresVersion: 1800",
            "password: $__env{AIGW_PG_GRAFANA_RO_PASSWORD}",
        ):
            self.assertIn(required, datasources)
        # The credential reaches Grafana only through the environment; the
        # provisioning file must never carry a literal secret, and every
        # provisioned datasource stays UI-immutable.
        self.assertEqual(datasources.count("password:"), 1)
        self.assertEqual(
            datasources.count("editable: false"), datasources.count("- name: ")
        )
        grafana = self.compose.split("  grafana:\n", 1)[1].split(
            "  cribl-mock:\n", 1
        )[0]
        self.assertIn(
            "AIGW_PG_GRAFANA_RO_PASSWORD: ${PG_GRAFANA_RO_PASSWORD:?PG_GRAFANA_RO_PASSWORD must be set}",
            grafana,
        )
        self.assertIn(
            "networks: [net-grafana, net-observability, net-db-grafana]", grafana
        )

    def test_spend_dashboards_use_bounded_top_n_over_litellm_computed_spend(self) -> None:
        """Cardinality/cost contract: cost panels read LiteLLM's own computed
        dollar `spend` (which already prices Anthropic prompt-cache reads and
        writes correctly) with bounded LIMIT top-N SQL — never an unbounded
        per-user/per-key metric label and never tokens multiplied by a flat
        price."""
        granted_tables = {
            "LiteLLM_SpendLogs",
            "LiteLLM_VerificationToken",
            "LiteLLM_UserTable",
            "LiteLLM_DailyUserSpend",
        }
        limits = {"aigw-top-projects": "LIMIT 5", "aigw-top-users": "LIMIT 10"}
        for uid, limit in limits.items():
            dashboard = next(item for item in self.dashboards if item["uid"] == uid)
            queries = [
                target["rawSql"]
                for panel in panels(dashboard)
                for target in panel.get("targets", [])
            ]
            self.assertTrue(queries)
            for query in queries:
                self.assertTrue(
                    query.startswith(("SELECT", "WITH")), query.splitlines()[0]
                )
                referenced = set(re.findall(r'"(LiteLLM_[A-Za-z]+)"', query))
                self.assertTrue(referenced)
                self.assertLessEqual(referenced, granted_tables)
                upper = query.upper()
                for forbidden in (
                    "INSERT", "UPDATE ", "DELETE", "DROP", "ALTER", "GRANT",
                    "CREATE ", "TRUNCATE", "COPY ",
                ):
                    self.assertNotIn(forbidden, upper, query)
                # Aggregate queries stay time-bounded and top-N bounded; the
                # daily cache panels aggregate a bounded daily table instead.
                if '"LiteLLM_SpendLogs"' in query:
                    self.assertIn('$__timeFilter(sl."startTime")', query)
                    self.assertIn(limit, query)
                # Prompt bodies are not stored in spend rows, and no query may
                # even reference those columns.
                for forbidden_column in ("messages", "response", "proxy_server_request"):
                    self.assertNotIn(forbidden_column, query)
            rendered = "\n".join(queries)
            self.assertIn('SUM(sl.spend)', rendered)
            self.assertNotIn("* 0.", rendered)
        users = next(item for item in self.dashboards if item["uid"] == "aigw-top-users")
        cache_queries = "\n".join(
            target["rawSql"]
            for panel in panels(users)
            for target in panel.get("targets", [])
            if "LiteLLM_DailyUserSpend" in target.get("rawSql", "")
        )
        self.assertIn("cache_read_input_tokens", cache_queries)
        self.assertIn("cache_creation_input_tokens", cache_queries)

    def test_postgres_reporting_role_is_least_privilege_and_matrix_pinned(self) -> None:
        init = (ROOT / "compose/postgres/init/01-init-databases.sh").read_text()
        for required in (
            "SELECT 'CREATE USER grafana_ro'",
            "ALTER ROLE grafana_ro WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE",
            "GRANT CONNECT ON DATABASE litellm TO grafana_ro;",
            "'LiteLLM_SpendLogs','LiteLLM_VerificationToken',",
            "'LiteLLM_UserTable','LiteLLM_DailyUserSpend'",
        ):
            self.assertIn(required, init)
        # Column-level SELECT only: the exact per-table allowlists the eight
        # provisioned dashboards query, pinned character-for-character. Each
        # list is intentionally complete — a missing column breaks a panel,
        # an extra column widens the reporting surface.
        expected_grants = {
            "LiteLLM_SpendLogs": (
                'GRANT SELECT ("api_key", "completion_tokens", "prompt_tokens", '
                '"spend", "startTime", "total_tokens", "user") '
                'ON TABLE public."LiteLLM_SpendLogs" TO grafana_ro'
            ),
            "LiteLLM_VerificationToken": (
                'GRANT SELECT ("metadata", "token") '
                'ON TABLE public."LiteLLM_VerificationToken" TO grafana_ro'
            ),
            "LiteLLM_UserTable": (
                'GRANT SELECT ("user_alias", "user_id") '
                'ON TABLE public."LiteLLM_UserTable" TO grafana_ro'
            ),
            "LiteLLM_DailyUserSpend": (
                'GRANT SELECT ("cache_creation_input_tokens", '
                '"cache_read_input_tokens", "date", "prompt_tokens") '
                'ON TABLE public."LiteLLM_DailyUserSpend" TO grafana_ro'
            ),
        }
        for grant in expected_grants.values():
            self.assertIn(grant, init)
        # An already-initialized nonproduction DB carrying the retired whole-table grant
        # must be demoted, not left in place: the fixer actively revokes the
        # table-wide SELECT and the three prompt-bearing columns before it
        # re-grants at column level.
        self.assertNotIn("GRANT SELECT ON TABLE public.%I TO grafana_ro", init)
        self.assertIn(
            "REVOKE SELECT ON TABLE public.%I FROM grafana_ro", init
        )
        self.assertIn(
            'REVOKE SELECT ("messages", "proxy_server_request", "response") '
            'ON TABLE public."LiteLLM_SpendLogs" FROM grafana_ro',
            init,
        )
        # The three prompt-bearing columns must never appear inside any GRANT —
        # not in a column list, not anywhere on a granting statement. Sweep
        # every GRANT SELECT (...) column list and assert they are absent.
        grant_column_lists = re.findall(r"GRANT SELECT \(([^)]*)\)", init)
        self.assertEqual(len(grant_column_lists), len(expected_grants))
        for column_list in grant_column_lists:
            for forbidden_column in (
                "messages", "response", "proxy_server_request",
            ):
                self.assertNotIn(forbidden_column, column_list)
        # Never a blanket or self-widening grant path for the reporting role.
        self.assertNotIn("GRANT ALL", init)
        self.assertNotIn("ALTER DEFAULT PRIVILEGES", init)
        self.assertNotIn("GRANT CONNECT ON DATABASE keycloak TO grafana_ro", init)
        self.assertNotIn("GRANT CONNECT ON DATABASE rotator TO grafana_ro", init)
        self.assertNotIn("GRANT CONNECT ON DATABASE postgres TO grafana_ro", init)
        for expected_row in (
            "- grafana_ro|keycloak|false",
            "- grafana_ro|litellm|true",
            "- grafana_ro|postgres|false",
            "- grafana_ro|rotator|false",
            "- role|grafana_ro|true",
        ):
            self.assertIn(expected_row, self.stack)
        self.assertIn("name: pg_grafana_ro_password", self.stack)

    def test_db_grafana_bridge_abi_is_synchronized(self) -> None:
        """net-db-grafana is a firewall-ABI addition: inventory topology, the
        os-prep exact-topology gate and both Compose
        attachments must move together."""
        group_vars = (ROOT / "ansible/group_vars/all.yml").read_text()
        self.assertIn(
            "{ name: net-db-grafana,    bridge: br-db-graf, subnet: 172.28.20.0/24, internal: true }",
            group_vars,
        )
        os_prep = (ROOT / "ansible/os-prep.yml").read_text()
        self.assertIn(
            '"net-db-grafana": ("br-db-graf", "172.28.20.0/24", True),', os_prep
        )
        self.assertIn("net-db-grafana:   { external: true }", self.compose)
        self.assertIn(
            "networks: [net-db-litellm, net-db-keycloak, net-db-rotator, net-db-grafana]",
            self.compose,
        )

    def test_runtime_plugin_tmpfs_contract_is_engine_normalization_neutral(self) -> None:
        """Compose v5 / Engine 29 echo the reviewed tmpfs option string
        verbatim, while older Engines normalized an implicit "rw" token into
        HostConfig.Tmpfs. The runtime verifier must therefore require every
        security-bearing plugin tmpfs option plus the absence of "ro" (which
        proves writability on both renderings) and must never require an
        Engine-normalized "rw" literal."""
        plugin_contract = self.verify.split("required_plugin_options = {", 1)[1].split(
            "hardened ephemeral plugin tmpfs contract is missing", 1
        )[0]
        for required in (
            '"noexec",',
            '"nosuid",',
            '"nodev",',
            '"uid=65532",',
            '"gid=65532",',
            '"mode=0700",',
            'or "ro" in plugin_options',
        ):
            self.assertIn(required, plugin_contract)
        self.assertNotIn('"rw"', plugin_contract)
        # No runtime assertion in the verify role may require a literal
        # normalized "rw" set element again.
        self.assertNotIn('"rw",', self.verify)


if __name__ == "__main__":
    unittest.main()
