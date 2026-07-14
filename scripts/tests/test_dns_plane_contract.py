from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DnsPlaneContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.group_vars = (ROOT / "ansible/group_vars/all.yml").read_text()
        cls.lab_vars = (
            ROOT / "ansible/inventory/host_vars/lab-aigw01.yml"
        ).read_text()
        cls.site = (ROOT / "ansible/site.yml").read_text()
        cls.stack = (
            ROOT / "ansible/roles/docker_stack/tasks/main.yml"
        ).read_text()
        cls.compose = (ROOT / "compose/docker-compose.yml").read_text()
        cls.platform_compose = (
            ROOT / "compose/docker-compose.platform-dns.yml"
        ).read_text()
        cls.lab_compose = (ROOT / "compose/docker-compose.lab.yml").read_text()
        cls.dns_overlay = (
            ROOT
            / "ansible/roles/docker_stack/templates/docker-compose.dns.yml.j2"
        ).read_text()
        cls.env_template = (
            ROOT / "ansible/roles/docker_stack/templates/env.j2"
        ).read_text()
        cls.env_example = (ROOT / "compose/.env.example").read_text()
        cls.iptables = (
            ROOT
            / "ansible/roles/firewalld_zones/templates/docker-user-rules.sh.j2"
        ).read_text()
        cls.nft = (
            ROOT
            / "ansible/roles/firewalld_zones/templates/aigw-host-input-rules.sh.j2"
        ).read_text()
        cls.verify = (
            ROOT / "ansible/roles/verify/tasks/main.yml"
        ).read_text()
        cls.stack_only = (ROOT / "ansible/deploy-stack-only.yml").read_text()

    def test_legacy_shared_resolver_contract_is_gone(self) -> None:
        checked = "\n".join(
            [self.group_vars, self.lab_vars, self.site, self.compose,
             self.dns_overlay, self.env_example, self.iptables, self.nft]
        ).lower()
        self.assertNotIn("container_dns_server", checked)
        self.assertNotIn("aigw_container_dns_server", checked)
        self.assertIn("aigw_internal_dns_servers", self.group_vars.lower())
        self.assertIn("aigw_egress_dns_servers", self.group_vars.lower())

    def test_one_canonical_flag_controls_dns_runtime_and_policy(self) -> None:
        ansible_sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "ansible").rglob("*")
            if path.is_file() and path.suffix in {".yml", ".j2"}
        )
        self.assertNotIn("lab_dns_enabled", ansible_sources)
        for source in (self.stack, self.iptables, self.nft):
            self.assertIn("platform_authoritative_dns_enabled", source)
        self.assertIn("  lab-dns:", self.platform_compose)
        self.assertNotIn("  lab-dns:", self.lab_compose)
        self.assertIn("docker-compose.platform-dns.yml", self.stack)

    def test_lab_compose_argv_activates_the_literal_lab_profile(self) -> None:
        selector = self.stack.split(
            "aigw_compose_cli_overlay_args:", 1
        )[1].split("\n\n", 1)[0]
        self.assertIn("+ (['--profile', 'lab-ad']", selector)
        self.assertNotIn("regex_replace", selector)
        self.assertNotIn("\\\\1", selector)

    def test_compose_file_env_value_cannot_trim_into_compose_profiles(self) -> None:
        compose_file_lines = [
            line for line in self.env_template.splitlines()
            if line.startswith("COMPOSE_FILE=")
        ]
        self.assertEqual(
            compose_file_lines,
            ["COMPOSE_FILE={{ aigw_env_compose_files | join(':') }}"],
        )
        self.assertNotIn("{%", compose_file_lines[0])
        self.assertIn("\nCOMPOSE_PROFILES=lab-ad\n", self.env_template)

    def test_resolver_inputs_are_bounded_unique_and_disjoint(self) -> None:
        for contract in (
            "internal_dns_servers | length >= 1",
            "internal_dns_servers | length <= 3",
            "egress_dns_servers | length >= 1",
            "egress_dns_servers | length <= 3",
            "internal_dns_servers | unique | length == internal_dns_servers | length",
            "egress_dns_servers | unique | length == egress_dns_servers | length",
            "internal_dns_servers | intersect(egress_dns_servers) | length == 0",
        ):
            self.assertIn(contract, self.site)
        self.assertIn("[nic_adm, nic_internal]", self.site)
        self.assertIn("'dev ' ~ (nic_egress | regex_escape)", self.site)

    def test_runtime_overlay_assigns_only_envoy_to_internet_dns(self) -> None:
        hardening_services = set(
            re.findall(
                r"(?m)^  ([a-z0-9][a-z0-9-]+):\n(?:.*\n){0,8}?    <<: \*hardening$",
                self.compose,
            )
        )
        resolver_blocks = re.findall(
            r"\{% for service in \[(.*?)\] %\}", self.dns_overlay, re.DOTALL
        )
        self.assertEqual(len(resolver_blocks), 2)
        internal_names = set(
            re.findall(r"'([a-z0-9][a-z0-9-]+)'", resolver_blocks[0])
        )
        isolated_names = set(
            re.findall(r"'([a-z0-9][a-z0-9-]+)'", resolver_blocks[1])
        )
        self.assertEqual(
            internal_names,
            {"traefik-int", "traefik-adm", "alloy", "cribl-mock"},
        )
        self.assertFalse(internal_names & isolated_names)
        self.assertEqual(
            internal_names | isolated_names,
            hardening_services - {"envoy-egress"},
        )
        self.assertIn('dns: ["127.0.0.1"]', self.dns_overlay)
        envoy = self.dns_overlay.split("  envoy-egress:", 1)[1]
        self.assertIn("{% for resolver in egress_dns_servers %}", envoy)
        self.assertNotIn("internal_dns_servers", envoy)
        self.assertNotIn("dns:", self.compose.split("x-hardening:", 1)[1].split("services:", 1)[0])

    def test_internal_dns_clients_have_only_reviewed_noninternet_routes(self) -> None:
        sections = {
            "traefik-int": self.compose.split("  traefik-int:", 1)[1].split(
                "  traefik-adm:", 1
            )[0],
            "traefik-adm": self.compose.split("  traefik-adm:", 1)[1].split(
                "  oauth2-proxy:", 1
            )[0],
            "alloy": self.compose.split("  alloy:", 1)[1].split(
                "  prometheus:", 1
            )[0],
            "cribl-mock": self.compose.split("  cribl-mock:", 1)[1].split(
                "\nvolumes:\n", 1
            )[0],
        }
        self.assertIn("net-int-edge", sections["traefik-int"])
        self.assertIn("net-adm", sections["traefik-adm"])
        self.assertIn("net-internal", sections["alloy"])
        self.assertIn("net-internal", sections["cribl-mock"])
        for section in sections.values():
            self.assertNotIn("net-egress", section)

    def test_firewalls_pin_internet_dns_to_envoy_and_egress_nic(self) -> None:
        for source in (self.iptables, self.nft):
            self.assertIn("for resolver in egress_dns_servers", source)
            self.assertIn("envoy_egress_ip", source)
            self.assertIn("nic_egress", source)
            self.assertIn("--dport 53" if source is self.iptables else "dport 53", source)
            self.assertIn(
                "net.name in ['net-adm', 'net-internal', 'net-int-edge']",
                source,
            )
            self.assertNotIn(
                "net.name not in ['net-egress', 'net-lab-dns']", source
            )
        self.assertIn("-d {{ resolver }}/32 -o {{ nic_egress }}", self.iptables)
        self.assertIn('oifname "{{ nic_egress }}" ip saddr {{ envoy_egress_ip }}', self.nft)

    def test_platform_dns_has_exact_reply_rules_before_cross_bridge_drop(self) -> None:
        iptables_reply = (
            "-A DOCKER-USER -i br-lab-dns -o {{ net.bridge }} "
            "-s {{ lab_dns_ip }}/32 -p udp --sport 53 -m conntrack "
            "--ctstate ESTABLISHED,RELATED --ctdir REPLY -j RETURN"
        )
        nft_reply = (
            'iifname "br-lab-dns" oifname "{{ net.bridge }}" '
            "ip saddr {{ lab_dns_ip }} udp sport 53 ct state "
            "established,related ct direction reply accept"
        )
        iptables_tcp_reply = iptables_reply.replace(
            "-p udp --sport 53", "-p tcp --sport 53"
        )
        nft_tcp_reply = nft_reply.replace(" udp sport 53", " tcp sport 53")
        self.assertIn(iptables_reply, self.iptables)
        self.assertIn(iptables_tcp_reply, self.iptables)
        self.assertIn(nft_reply, self.nft)
        self.assertIn(nft_tcp_reply, self.nft)
        self.assertLess(
            self.iptables.index(iptables_reply),
            self.iptables.index(
                "-A DOCKER-USER -i {{ net.bridge }} -o br+ -j DROP"
            ),
        )
        self.assertLess(
            self.nft.index(nft_reply),
            self.nft.index(
                'iifname { {% for net in docker_networks %}'
            ),
        )
        physical_drop = (
            'iifname "{{ nic_internal }}" oifname "{{ nic_egress }}" drop'
        )
        self.assertLess(self.nft.index(physical_drop), self.nft.index(nft_reply))

    def test_platform_dns_ingress_gate_does_not_reject_envoy_egress_dns(self) -> None:
        gate = self.verify.split(
            "- name: Platform DNS DNAT is source-scoped in DOCKER-USER", 1
        )[1].split("\n- name:", 1)[0]
        self.assertIn(
            " -i ' ~ (nic_egress | regex_escape) ~ ' -o br\\\\+",
            gate,
        )
        self.assertNotIn(
            "'(?m).*' ~ (nic_egress | regex_escape) ~ '.*--dport 53",
            gate,
        )

    def test_native_forward_fallback_drops_unmanaged_docker_bridges(self) -> None:
        forward = self.nft.split("chain container_forward", 1)[1]
        self.assertIn('iifname "docker0" drop', forward)
        self.assertIn('iifname "br-*" drop', forward)
        self.assertLess(
            forward.index('iifname "{{ _egress_net.bridge }}" oifname "{{ nic_egress }}"'),
            forward.index('iifname "docker0" drop'),
        )

    def test_authoritative_views_are_split_and_non_recursive(self) -> None:
        core = (
            ROOT
            / "ansible/roles/docker_stack/templates/Corefile.authoritative.j2"
        ).read_text()
        self.assertIn("view adm", core)
        self.assertIn("view internal", core)
        self.assertEqual(core.count("health 127.0.0.1:8080"), 1)
        self.assertIn("rcode NXDOMAIN", core)
        self.assertNotRegex(core, r"(?m)^\s*forward(?:\s|$)")
        internal = (
            ROOT
            / "ansible/roles/docker_stack/templates/db.aigw.internal.j2"
        ).read_text()
        adm = (
            ROOT
            / "ansible/roles/docker_stack/templates/db.aigw.internal.adm.j2"
        ).read_text()
        for name in ("api", "portal", "auth"):
            self.assertRegex(internal, rf"(?m)^{name}\s+IN A\s+{{{{ eth2_ip }}}}$")
        for admin_only in (
            "admin",
            "admin-portal",
            "litellm-admin",
            "grafana",
            "prometheus",
            "vault",
            "chat",
        ):
            self.assertNotRegex(internal, rf"(?m)^{admin_only}\s+IN A")
        self.assertRegex(adm, r"(?m)^auth\s+IN A \{\{ eth1_ip \}\}$")
        self.assertRegex(adm, r"(?m)^portal\s+IN A \{\{ eth2_ip \}\}$")

    def test_verify_exercises_routable_and_isolated_resolver_modes(self) -> None:
        live_modes = self.verify.split(
            "- name: Verify live containers retain their exact resolver modes",
            1,
        )[1].split("\n- name:", 1)[0]
        self.assertIn('["127.0.0.1"]', live_modes)
        self.assertIn("envoy-egress", live_modes)
        self.assertIn("internal_dns_servers | to_json", live_modes)
        self.assertIn("egress_dns_servers | to_json", live_modes)

        isolated = self.verify.split(
            "- name: Preserve embedded service discovery for an upstream-DNS-isolated backend",
            1,
        )[1].split("\n- name:", 1)[0]
        self.assertIn('"{{ compose_project_name }}-litellm-1"', isolated)
        self.assertIn('"postgres", 5432', isolated)
        self.assertIn("socket.getaddrinfo", isolated)

        edge = self.verify.split(
            "- name: Resolve the authoritative zone from each routable edge resolver path",
            1,
        )[1].split("\n- name:", 1)[0]
        self.assertIn("nsenter", edge)
        self.assertIn('"dns.{{ aigw_domain }}"', edge)
        self.assertIn('"{{ eth2_ip }}"', edge)
        self.assertIn("product(internal_dns_servers)", edge)
        self.assertIn("when: platform_authoritative_dns_enabled | bool", edge)

    def test_stack_only_fails_before_resolver_firewall_drift_mutates_services(self) -> None:
        task = self.stack_only.split(
            "- name: Preflight — require the current internal resolver firewall tuples",
            1,
        )[1].split("\n    - name:", 1)[0]
        for marker in (
            "stack_only_du.stdout",
            "stack_only_host_input.stdout",
            "br-lab-dns",
            "lab_dns_ip",
            "--sport 53",
            "ct direction reply accept",
            "not (('-i br-lab-dns' in stack_only_du.stdout)",
            "not (('iifname \"br-lab-dns\"' in stack_only_host_input.stdout)",
            'loop: "{{ internal_dns_servers }}"',
        ):
            self.assertIn(marker, task)
        self.assertLess(
            self.stack_only.index("require the current internal resolver firewall tuples"),
            self.stack_only.index("  roles:"),
        )

    def test_oidc_discovery_keeps_docker_service_alias_precedence(self) -> None:
        self.assertIn("embedded 127.0.0.11 service-discovery resolver", self.dns_overlay)
        adm = self.compose.split("  traefik-adm:", 1)[1].split("  oauth2-proxy:", 1)[0]
        self.assertIn('aliases: ["auth.${DOMAIN}", "chat.${DOMAIN}"]', adm)
        webui = self.compose.split("  open-webui:", 1)[1].split("  keycloak:", 1)[0]
        self.assertIn("networks: [net-chat]", webui)
        portal = self.compose.split("  dev-portal:", 1)[1].split("  admin-portal:", 1)[0]
        self.assertIn('OIDC_INTERNAL_ISSUER: "http://keycloak:8080/realms/aigw"', portal)

    def test_pinned_coredns_plugins_are_runtime_gated(self) -> None:
        self.assertIn("Inventory the pinned CoreDNS runtime plugins", self.stack)
        self.assertIn("loop: [cache, errors, file, health, template, view]", self.stack)
        self.assertIn("ai-gateway/lab-dns:1.14.4", self.stack)


if __name__ == "__main__":
    unittest.main()
