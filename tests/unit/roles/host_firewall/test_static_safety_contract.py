from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
ROLE_ROOT = REPOSITORY_ROOT / "roles" / "host_firewall"
MOLECULE_ROOT = REPOSITORY_ROOT / "molecule" / "host-firewall-basic"
TRANSACTION = (ROLE_ROOT / "files" / "firewall_transaction.py").read_text()


class HostFirewallStaticSafetyTests(unittest.TestCase):
    def test_role_never_flushes_or_lists_the_whole_ruleset(self) -> None:
        role_text = "\n".join(
            path.read_text()
            for path in ROLE_ROOT.rglob("*")
            if path.is_file() and path.suffix not in {".pyc"}
        )
        self.assertNotIn("flush ruleset", role_text)
        self.assertNotIn('"list", "ruleset"', role_text)
        self.assertNotIn("list\n      - ruleset", role_text)

    def test_one_static_program_owns_all_productive_transactions(self) -> None:
        templates = {path.name for path in (ROLE_ROOT / "templates").glob("*")}
        self.assertNotIn("apply.sh.j2", templates)
        self.assertNotIn("confirm.sh.j2", templates)
        self.assertNotIn("rollback.sh.j2", templates)
        for function in ("apply_transaction", "confirm_transaction", "rollback_transaction"):
            self.assertIn(f"def {function}(", TRANSACTION)
        self.assertIn("fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)", TRANSACTION)

    def test_apply_snapshot_stage_watchdog_and_apply_share_one_lock_scope(self) -> None:
        apply = TRANSACTION.split("def apply_transaction", maxsplit=1)[1].split(
            "def stage_confirmation", maxsplit=1
        )[0]
        lock = apply.index('with transaction_scope(config, action="apply"):')
        snapshot = apply.index("read_nft_policy_state", lock)
        stage = apply.index("write_exclusive(paths[key]", snapshot)
        metadata = apply.index('write_exclusive(paths["metadata"]', stage)
        watchdog = apply.index('systemctl(config, "enable", "--now"', metadata)
        mutation = apply.index('label="candidate nftables apply"', watchdog)
        self.assertLess(lock, snapshot)
        self.assertLess(snapshot, stage)
        self.assertLess(stage, metadata)
        self.assertLess(metadata, watchdog)
        self.assertLess(watchdog, mutation)

    def test_confirmation_rehashes_every_asset_before_and_after_watchdog_stop(self) -> None:
        confirm = TRANSACTION.split("def confirm_transaction", maxsplit=1)[1].split(
            "def validate_explicit_rollback_request", maxsplit=1
        )[0]
        first_rehash = confirm.index("validate_metadata_and_assets")
        first_root = confirm.index("validate_pending_persistence", first_rehash)
        readback = confirm.index("read_nft_policy_state", first_root)
        stop = confirm.index('systemctl(config, "stop"', readback)
        rollback_recheck = confirm.index("require_rollback_service_quiescent", stop)
        second_rehash = confirm.index("validate_metadata_and_assets", rollback_recheck)
        second_root = confirm.index("validate_pending_persistence", second_rehash)
        final_readback = confirm.index("read_nft_policy_state", second_root)
        persistent_write = confirm.index("atomic_replace(config.persistent_include", final_readback)
        self.assertLess(first_rehash, first_root)
        self.assertLess(first_root, readback)
        self.assertLess(readback, stop)
        self.assertLess(stop, rollback_recheck)
        self.assertLess(rollback_recheck, second_rehash)
        self.assertLess(second_rehash, second_root)
        self.assertLess(second_root, final_readback)
        self.assertLess(final_readback, persistent_write)

    def test_table_absence_uses_successful_json_inventory_not_return_code_one(self) -> None:
        state_reader = TRANSACTION.split("def read_nft_table_state", maxsplit=1)[1].split(
            "def path_components", maxsplit=1
        )[0]
        self.assertIn('"--json", "list", "tables"', state_reader)
        self.assertIn("second nftables table inventory", state_reader)
        self.assertNotIn("returncode == 1", state_reader)

    def test_all_paths_and_full_parent_chains_have_explicit_rejection_logic(self) -> None:
        self.assertIn("ensure_distinct_paths(self.configured_paths())", TRANSACTION)
        self.assertIn("transaction file, program, persistence, and unit paths must be pairwise distinct", TRANSACTION)
        self.assertIn("symbolic links are prohibited in secure path chains", TRANSACTION)
        self.assertIn("secure path component is group/world writable", TRANSACTION)
        self.assertIn("secure path component is not root-owned", TRANSACTION)

    def test_static_units_execute_only_the_single_transaction_program(self) -> None:
        confirmation = (ROLE_ROOT / "templates" / "confirm.service.j2").read_text()
        rollback = (ROLE_ROOT / "templates" / "rollback.service.j2").read_text()
        timer = (ROLE_ROOT / "templates" / "rollback.timer.j2").read_text()
        self.assertIn("host_firewall_transaction_program_argv", confirmation)
        self.assertIn(" confirm", confirmation)
        self.assertIn("host_firewall_transaction_program_argv", rollback)
        self.assertIn("rollback --watchdog", rollback)
        self.assertIn("Before={{ host_firewall_confirmation_service_name }}", rollback)
        self.assertIn("Persistent=true", timer)
        self.assertNotIn("WantedBy=multi-user.target", rollback)

    def test_persistence_root_is_read_only_and_never_an_ansible_destination(self) -> None:
        confirmation = (ROLE_ROOT / "templates" / "confirm.service.j2").read_text()
        rollback = (ROLE_ROOT / "templates" / "rollback.service.j2").read_text()
        preflight = (ROLE_ROOT / "tasks" / "persistence_preflight.yml").read_text()
        role_tasks = "\n".join(path.read_text() for path in (ROLE_ROOT / "tasks").glob("*.yml"))
        self.assertIn("ReadOnlyPaths={{ host_firewall_persistent_root_config_path }}", confirmation)
        self.assertIn("ReadOnlyPaths={{ host_firewall_persistent_root_config_path }}", rollback)
        self.assertIn("exact include directive", preflight)
        self.assertIn("select('equalto', host_firewall_persistent_include_directive)", preflight)
        self.assertNotIn('dest: "{{ host_firewall_persistent_root_config_path }}"', role_tasks)

    def test_setup_installs_static_assets_only_through_the_shared_lock_routine(self) -> None:
        setup = (ROLE_ROOT / "tasks" / "setup.yml").read_text()
        self.assertNotIn("ansible.builtin.copy:", setup)
        self.assertNotIn("ansible.builtin.template:", setup)
        self.assertIn("validate-setup", setup)
        self.assertIn("install-runtime", setup)
        installer = TRANSACTION.split("def install_runtime", maxsplit=1)[1].split(
            "def validate_root_include", maxsplit=1
        )[0]
        self.assertIn('with transaction_scope(config, action="install-runtime"):', installer)
        self.assertIn("if os.path.lexists(config.active_path)", installer)

    def test_global_check_mode_forces_real_nft_validation_without_setup(self) -> None:
        check = (ROLE_ROOT / "tasks" / "check.yml").read_text()
        main = (ROLE_ROOT / "tasks" / "main.yml").read_text()
        self.assertIn("check_mode: false", check)
        self.assertIn("host_firewall_check_result.skipped", check)
        self.assertIn("host_firewall_action == 'apply'", main)
        self.assertIn("not ansible_check_mode", main)

    def test_egress_is_default_drop_and_every_capability_is_separate(self) -> None:
        policy = (ROLE_ROOT / "templates" / "host-firewall.nft.j2").read_text()
        defaults = (ROLE_ROOT / "defaults" / "main.yml").read_text()
        egress_assert = (ROLE_ROOT / "tasks" / "egress_assert.yml").read_text()
        self.assertIn("chain output", policy)
        self.assertIn("policy drop", policy)
        self.assertIn("host_firewall_egress_policy.functions", policy)
        for function in (
            "dns_udp",
            "dns_tcp",
            "ntp",
            "atlas_loki",
            "bootstrap_https",
            "https_proxy",
        ):
            self.assertIn(f"  {function}:", defaults)
        self.assertIn("temporary, never-confirmable public exception", egress_assert)
        self.assertIn("CIS baseline requires IPv6", egress_assert)
        self.assertIn(
            "meta skuid {{ ansible_facts.getent_passwd["
            "host_firewall_forward_proxy_egress.owner_username][1] | int }}",
            policy,
        )
        self.assertIn("not host_firewall_egress_policy.functions.bootstrap_https.enabled", egress_assert)
        self.assertIn("not host_firewall_egress_policy.functions.https_proxy.enabled", egress_assert)
        self.assertNotIn("  bootstrap_http:", defaults)

    def test_forward_proxy_egress_validates_types_and_local_account_before_render(self) -> None:
        egress = (ROLE_ROOT / "tasks" / "egress_assert.yml").read_text()
        main = (ROLE_ROOT / "tasks" / "main.yml").read_text()
        policy = (ROLE_ROOT / "templates" / "host-firewall.nft.j2").read_text()
        defaults = (ROLE_ROOT / "defaults" / "main.yml").read_text()
        self.assertIn("host_firewall_forward_proxy_egress.interface is string", egress)
        self.assertIn("host_firewall_forward_proxy_egress.owner_username is string", egress)
        self.assertIn("host_firewall_forward_proxy_access.destination_ipv4 is string", egress)
        self.assertIn("host_firewall_forward_proxy_client_access is mapping", egress)
        self.assertIn("item.value.modes == ['hardened']", egress)
        self.assertIn(
            "item.value.destination_ipv4\n"
            "        == host_firewall_observed_container_bridge_gateways_ipv4[item.value.interface]",
            egress,
        )
        self.assertIn(
            'iifname "{{ client.value.interface }}" ip saddr {{ client.value.source_ipv4 }}',
            policy,
        )
        self.assertIn("host_firewall_container_dns_access.destination_ipv4 is string", egress)
        self.assertIn("host_firewall_observed_container_bridge_gateways_ipv4 is mapping", egress)
        self.assertIn("map('extract', host_firewall_observed_container_bridge_gateways_ipv4)", egress)
        self.assertIn("udp dport 53 ct state new accept", policy)
        self.assertIn("tcp dport 53 ct state new accept", policy)
        self.assertIn("host_firewall_container_dns_access", defaults)
        self.assertIn("host_firewall_forward_proxy_client_access", defaults)
        self.assertIn("host_firewall_observed_container_bridge_gateways_ipv4", defaults)
        verify = (MOLECULE_ROOT / "verify.yml").read_text()
        self.assertIn("distinct selected bridge gateways were rejected", verify)
        self.assertIn("matching selected bridge gateways render successfully", verify)
        readme = (ROLE_ROOT / "README.md").read_text()
        self.assertIn("each selected\n  managed container bridge interface", readme)
        self.assertIn("Unselected managed bridges do not require evidence", readme)
        self.assertIn("ansible.builtin.getent:", egress)
        self.assertIn("database: passwd", egress)
        self.assertIn("service: files", egress)
        self.assertIn("in ansible_facts.getent_passwd", egress)
        self.assertIn(
            "ansible_facts.getent_passwd[host_firewall_forward_proxy_egress.owner_username][1]",
            egress,
        )
        self.assertIn("is match('^[0-9]+\\Z')", egress)
        self.assertIn(
            "ansible_facts.getent_passwd[host_firewall_forward_proxy_egress.owner_username][1]\n"
            "        == '13'",
            egress,
        )
        self.assertIn(
            "ansible_facts.getent_passwd[host_firewall_forward_proxy_egress.owner_username][2]\n"
            "        == '13'",
            egress,
        )
        self.assertIn("selectattr('value.1', 'equalto', '13')", egress)
        self.assertIn("== [host_firewall_forward_proxy_egress.owner_username]", egress)
        self.assertIn(
            "in ['/usr/sbin/nologin', '/sbin/nologin', '/bin/false']",
            egress,
        )
        self.assertIn("Root remains the trusted host boundary", egress)
        self.assertLess(
            main.index("import_tasks: egress_assert.yml"),
            main.index("import_tasks: render.yml"),
        )

        negative = (MOLECULE_ROOT / "verify-forward-proxy-identity.tasks.yml.inc").read_text()
        verify = (MOLECULE_ROOT / "verify.yml").read_text()
        for case in ("wrong UID", "wrong GID", "login-capable shell", "duplicate UID"):
            self.assertIn(f"name: {case}", verify)
        self.assertIn("Attempt to render with the invalid local proxy identity", negative)
        self.assertIn(
            "Require the exact local forward proxy account before rendering nftables",
            negative,
        )

    def test_closed_metadata_binds_action_mode_readback_policy_and_egress(self) -> None:
        for field in (
            '"action"',
            '"mode"',
            '"approved_readback_sha256"',
            '"policy_fingerprint"',
            '"egress_policy_sha256"',
            '"egress_status"',
            '"apply_authorization_sha256"',
            '"apply_verification_sha256"',
            '"verifier_sha256"',
            '"persistent_root_sha256"',
        ):
            self.assertIn(field, TRANSACTION)
        self.assertIn("static transaction asset changed", TRANSACTION)

    def test_same_source_is_rendered_through_separate_management_sets(self) -> None:
        policy = (ROLE_ROOT / "templates" / "host-firewall.nft.j2").read_text()
        self.assertIn("{{ function.key }}_sources_v4", policy)
        self.assertNotIn("{{ function.key }}_sources_v6", policy)
        self.assertNotIn("management_sources_v4", policy)

    def test_ipv4_only_candidate_allows_only_family_agnostic_loopback(self) -> None:
        policy = (ROLE_ROOT / "templates" / "host-firewall.nft.j2").read_text()
        self.assertNotIn("ip6 ", policy)
        self.assertNotIn("nfproto ipv6", policy)
        self.assertIn('iifname "lo" accept', policy)
        self.assertIn('oifname "lo" accept', policy)
        self.assertNotIn("\n        ct state { established, related } accept", policy)
        self.assertIn("meta nfproto ipv4 ct state { established, related } accept", policy)

    def test_host_policy_and_cis_control_ipv6_without_provider_dependency(self) -> None:
        assertions = (ROLE_ROOT / "tasks" / "assert.yml").read_text()
        egress = (ROLE_ROOT / "tasks" / "egress_assert.yml").read_text()
        self.assertNotIn("provider IPv6 filter", assertions)
        self.assertIn("host_firewall_cis_ipv6_required", egress)
        self.assertIn("Observed IPv6 addresses receive no allow", egress)

    def test_one_terminal_record_prevents_contradictory_outcomes(self) -> None:
        paths = TRANSACTION.split("def transaction_paths", maxsplit=1)[1].split("def load_active", maxsplit=1)[0]
        self.assertIn('"terminal": "terminal.json"', paths)
        self.assertNotIn('"confirmation":', paths)
        self.assertNotIn('"rollback":', paths)
        rollback = TRANSACTION.split("def rollback_locked", maxsplit=1)[1].split(
            "def rollback_transaction", maxsplit=1
        )[0]
        self.assertIn("validate_static=not watchdog", rollback)
        self.assertIn("load_terminal(paths)", rollback)
        self.assertIn("authoritative confirmation outcome", rollback)

    def test_rollback_record_closes_restored_state_and_explicit_authorization(self) -> None:
        rollback = TRANSACTION.split("def rollback_locked", maxsplit=1)[1].split(
            "def rollback_transaction", maxsplit=1
        )[0]
        for field in (
            '"restored_runtime_state"',
            '"restored_readback_sha256"',
            '"restored_persistent_state"',
            '"restored_persistent_sha256"',
            '"authorization_claim_id"',
            '"authorization_sha256"',
            '"authorization_verification_sha256"',
        ):
            self.assertIn(field, rollback)

    def test_hung_commands_and_stale_locks_cannot_outlive_the_watchdog(self) -> None:
        defaults = (ROLE_ROOT / "defaults" / "main.yml").read_text()
        rollback_unit = (ROLE_ROOT / "templates" / "rollback.service.j2").read_text()
        self.assertIn("timeout=effective_timeout", TRANSACTION)
        self.assertIn("transaction_budget_seconds", TRANSACTION)
        self.assertIn("LOCK_EX | fcntl.LOCK_NB", TRANSACTION)
        self.assertIn("lock wait exceeded", TRANSACTION)
        self.assertIn("host_firewall_command_timeout_seconds", defaults)
        self.assertIn("Restart=on-failure", rollback_unit)
        self.assertIn("StartLimitBurst=4", rollback_unit)

    def test_terminal_and_active_directory_entries_are_durably_ordered(self) -> None:
        self.assertIn("def fsync_directory(", TRANSACTION)
        self.assertIn("fsync_directory(path.parent)", TRANSACTION)
        finalizer = TRANSACTION.split("def write_terminal_disable_watchdog_and_clear_active", maxsplit=1)[1].split(
            "def exclusive_transaction_lock", maxsplit=1
        )[0]
        write = finalizer.index("write_exclusive(terminal_path")
        disable = finalizer.index('systemctl(config, "disable", "--now"')
        unlink = finalizer.index("durable_unlink(config.active_path)")
        self.assertLess(write, disable)
        self.assertLess(disable, unlink)


if __name__ == "__main__":
    unittest.main()
