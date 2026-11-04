"""Offline behavioral coverage for the clear-research enrichment workflow.

Only selected AST sections are executed, with synthetic event tables and fake
services. Script startup, working-directory changes, and database writes never
run. DSHIELD_WORKFLOW_SCRIPT can select another copy of the same workflow.
"""

import ast
import ipaddress
import logging
import os
import sys
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pandas as pd


class _ProviderError(RuntimeError):
    pass


class _RateLimit(_ProviderError):
    def __init__(self, retry_at):
        self.retry_at = retry_at
        super().__init__("provider cooldown")


class _Resource:
    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


class _Workflow:
    def __init__(self, path):
        self.path = path
        self.nodes = ast.parse(path.read_text(encoding="utf-8"), filename=str(path)).body

    def assignment(self, name):
        return next(
            index for index, node in enumerate(self.nodes)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        )

    def run(self, nodes, namespace):
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(self.path), "exec"), namespace)

    def helpers(self, namespace):
        self.run([
            node for node in self.nodes
            if isinstance(node, ast.FunctionDef)
            and node.name in ("_prepare_source_ips", "_shodan_ipv4_addresses",
                              "_optional_feed", "_get_feed_text")
        ], namespace)

    def dns(self, namespace):
        start = self.assignment("ips")
        end = self.assignment("lookups") + 4  # lookup table and three source joins
        self.run(self.nodes[start:end], namespace)

    def label_join(self, lookup_name, namespace):
        start = self.assignment(lookup_name)
        self.run(self.nodes[start:start + 4], namespace)

    def isc_labels(self, namespace):
        self.run(self.nodes[self.assignment("isc_researchers"):self.assignment("asn_mmdb")], namespace)

    def metadata(self, namespace):
        start = self.assignment("asn_mmdb")
        end = next(
            index for index, node in enumerate(self.nodes[start:], start)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "insert_df"
        )
        self.run(self.nodes[start:end], namespace)

    def outputs(self, namespace):
        self.run([
            node for node in self.nodes
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "insert_df"
        ], namespace)


class TestEnrichmentWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default = Path(__file__).resolve().parents[2] / "examples" / "clear_research_ips.py"
        cls.workflow = _Workflow(Path(os.environ.get("DSHIELD_WORKFLOW_SCRIPT", default)))

    def setUp(self):
        def ptr_results(ips, **kwargs):
            # Simulate threads completing in a different order from their input.
            return iter([
                {"ip": ip, "reverse_dns": "ptr-" + ip, "status": "ok",
                 "fetched_at": 100.0, "expires_at": 200.0}
                for ip in reversed(ips)
            ])

        self.enrichment = SimpleNamespace(
            EnrichmentCache=Mock(side_effect=lambda path: _Resource()),
            EnrichmentError=_ProviderError,
            EnrichmentRateLimitError=_RateLimit,
            iter_reverse_dns=Mock(side_effect=ptr_results),
            isc_research_threats=Mock(return_value=pd.DataFrame()),
            isc_ipinfo=Mock(side_effect=lambda ip, email, **kwargs: {ip: {"as": "64500"}}),
            load_iptoasn_database=Mock(return_value=object()),
            get_iptoasn_data=Mock(),
            get_geoip_asn=Mock(),
            get_shodan_domain=Mock(return_value=None),
            extract_subnets=Mock(return_value=[]),
            censys_networks=Mock(return_value=[]),
            binary_edge_minions=Mock(return_value=[]),
        )
        self.requests = SimpleNamespace(Session=Mock(side_effect=_Resource), get=Mock())
        self.sql = SimpleNamespace(insert_df=Mock())
        self.environment = {}
        self.namespace = {
            "pd": pd, "ipaddress": ipaddress, "logging": logging, "Path": Path,
            "ExitStack": ExitStack, "os": SimpleNamespace(environ=self.environment),
            "requests": self.requests,
            "dshield_parser": SimpleNamespace(utils=SimpleNamespace(enrichment=self.enrichment, sql=self.sql)),
            "time": SimpleNamespace(time=Mock(return_value=111.0)),
            "enrichment_sources": [], "date": "test-run",
            "email": "analyst@example.org", "shodan_api": "",
            "cache_path": Path("offline-enrichment.sqlite"),
            "start_date": "2024-01-01", "end_date": "2024-01-31",
        }
        self.workflow.helpers(self.namespace)
        self.namespace.update(self.frames())

    @staticmethod
    def frames():
        return {
            "web_data": pd.DataFrame({
                "ipv4": ["8.8.8.8", "1.1.1.1", "8.8.8.8"],
                "event_id": [1, 2, 3], "count": [7, 11, 13],
                "user-agent": ["test", None, "LeakIX/1.0"], "url": ["/", "/", "/"],
            }),
            "cowrie_data": pd.DataFrame({
                "ipv4": ["1.1.1.1", "2001:4860:4860:0:0:0:0:8888"],
                "event_id": [4, 5], "count": [17, 19],
            }),
            "firewall_data": pd.DataFrame({
                "ipv4": ["9.9.9.9", "8.8.8.8", "10.0.0.1"],
                "event_id": [6, 7, 8], "count": [23, 29, 31],
            }),
        }

    def event_counts(self):
        return {
            name: frame[["event_id", "count"]].sort_values("event_id").reset_index(drop=True)
            for name, frame in self.namespace.items()
            if name in ("web_data", "cowrie_data", "firewall_data")
        }

    def assert_event_counts_unchanged(self, before):
        for name, expected in before.items():
            actual = self.namespace[name][["event_id", "count"]].sort_values("event_id").reset_index(drop=True)
            pd.testing.assert_frame_equal(actual, expected)
            self.assertEqual(actual["count"].sum(), expected["count"].sum())

    def test_dns_uses_all_sources_once_and_joins_by_ip_not_completion_order(self):
        before = self.event_counts()
        self.workflow.dns(self.namespace)
        expected = ["1.1.1.1", "10.0.0.1", "2001:4860:4860::8888", "8.8.8.8", "9.9.9.9"]
        self.assertEqual(self.enrichment.iter_reverse_dns.call_args.args[0], expected)
        self.assertEqual(self.namespace["lookups"]["ipv4"].tolist(), list(reversed(expected)))
        self.assertTrue(self.namespace["lookups"]["ipv4"].is_unique)
        for name in before:
            for row in self.namespace[name].itertuples():
                self.assertEqual(row.reverse_dns, "ptr-" + row.ipv4)
        self.assert_event_counts_unchanged(before)

    def test_duplicate_scanner_research_and_isc_labels_do_not_multiply_counts(self):
        before = self.event_counts()
        self.workflow.dns(self.namespace)
        self.namespace["scanners"] = pd.DataFrame({
            "ipv4": ["8.8.8.8"] * 3,
            "mass_scanner": ["Scanner B", "Scanner A", "Scanner A"],
        })
        self.workflow.label_join("scanner_lookup", self.namespace)
        self.namespace["research_data"] = pd.DataFrame({
            "ipv4": ["8.8.8.8"] * 3,
            "Research Organization": ["LeakIX", "Censys", "Censys"],
        })
        self.workflow.label_join("research_lookup", self.namespace)
        self.enrichment.isc_research_threats.return_value = pd.DataFrame({
            "ipv4": ["8.8.8.8"] * 3,
            "type": ["type-b", "type-a", "type-a"],
            "added": ["2024-01-03", "2024-01-01", "2024-01-02"],
            "lastseen": ["2024-01-07", "2024-01-09", "2024-01-08"],
        })
        self.workflow.isc_labels(self.namespace)
        self.workflow.metadata(self.namespace)
        self.assert_event_counts_unchanged(before)
        self.assertTrue(self.namespace["ip_data"]["ipv4"].is_unique)
        self.assertEqual(len(self.namespace["ip_data"]), 5)
        selected = self.namespace["web_data"].query("ipv4 == '8.8.8.8'").iloc[0]
        self.assertEqual(selected["mass_scanner"], "Scanner A | Scanner B")
        self.assertEqual(selected["Research Organization"], "Censys | LeakIX")
        self.assertEqual(selected["isc_researcher"], "type-a | type-b")
        self.assertEqual(selected["isc_added"], "2024-01-01")
        self.assertEqual(selected["isc_lastseen"], "2024-01-09")

    def test_empty_tables_and_empty_feeds_keep_schema_without_provider_calls(self):
        for name in self.frames():
            self.namespace[name] = self.namespace[name].iloc[:0].copy()
        self.workflow.dns(self.namespace)
        self.namespace["scanners"] = pd.DataFrame(columns=["ipv4", "mass_scanner"])
        self.workflow.label_join("scanner_lookup", self.namespace)
        self.namespace["research_data"] = pd.DataFrame(columns=["ipv4", "Research Organization"])
        self.workflow.label_join("research_lookup", self.namespace)
        self.workflow.isc_labels(self.namespace)
        self.workflow.metadata(self.namespace)
        self.assertEqual(self.namespace["ip_data"].shape[0], 0)
        self.enrichment.isc_ipinfo.assert_not_called()
        for name in self.frames():
            self.assertTrue(self.namespace[name].empty)
            self.assertIn("enrichment_status", self.namespace[name])

    def test_empty_isc_feed_and_missing_optional_fields_preserve_events(self):
        for response in (
            pd.DataFrame(),
            pd.DataFrame({"ipv4": ["8.8.8.8"], "type": ["research"]}),
        ):
            with self.subTest(columns=response.columns.tolist()):
                self.namespace.update(self.frames())
                before = self.event_counts()
                self.enrichment.isc_research_threats.return_value = response
                self.workflow.isc_labels(self.namespace)
                self.assert_event_counts_unchanged(before)
                self.assertTrue(self.namespace["web_data"]["isc_added"].isna().all())
                self.assertTrue(self.namespace["web_data"]["isc_lastseen"].isna().all())

    def test_invalid_source_addresses_fail_with_table_and_row_context(self):
        prepare = self.namespace["_prepare_source_ips"]
        for value in (None, pd.NA, float("nan"), True, 123, "example.org", "fe80::1%eth0"):
            with self.subTest(ip=value):
                source = pd.DataFrame({"ipv4": [value]}, index=[42])
                with self.assertRaisesRegex(ValueError, "Invalid source IP in web at row 42"):
                    prepare({"web": source})
        with self.assertRaisesRegex(ValueError, "web source data requires an ipv4 column"):
            prepare({"web": pd.DataFrame()})
        with self.assertRaisesRegex(TypeError, "web source data must be a pandas DataFrame"):
            prepare({"web": None})

    def test_deferred_and_failed_isc_lookups_preserve_one_row_per_ip(self):
        self.workflow.dns(self.namespace)
        before = self.event_counts()

        def isc(ip, email, **kwargs):
            if ip == "1.1.1.1":
                raise _RateLimit(500.0)
            if ip == "9.9.9.9":
                raise _ProviderError("temporary provider failure")
            return {ip: {"as": "64500", "updated": "2024-01-01"}}

        self.enrichment.isc_ipinfo.side_effect = isc
        with self.assertLogs(level="WARNING"):
            self.workflow.metadata(self.namespace)
        table = self.namespace["ip_data"].set_index("ipv4")
        self.assertTrue(table.index.is_unique)
        self.assertEqual(len(table), 5)
        self.assertEqual(table.loc["1.1.1.1", "enrichment_status"], "deferred")
        self.assertEqual(table.loc["1.1.1.1", "enrichment_retry_at"], 500.0)
        self.assertEqual(table.loc["9.9.9.9", "enrichment_status"], "error")
        self.assertEqual(table.loc["10.0.0.1", "enrichment_status"], "non_global")
        self.assertEqual(table.loc["8.8.8.8", "updated"], "2024-01-01")
        self.assertTrue(table["enrichment_fetched_at"].isna().all())
        self.assertEqual(self.enrichment.isc_ipinfo.call_count, 4)
        called_ips = [call.args[0] for call in self.enrichment.isc_ipinfo.call_args_list]
        self.assertEqual(len(called_ips), len(set(called_ips)))
        self.assertNotIn("10.0.0.1", called_ips)
        self.assert_event_counts_unchanged(before)

    def test_existing_isc_fetch_timestamp_is_preserved(self):
        self.workflow.dns(self.namespace)
        self.enrichment.isc_ipinfo.side_effect = lambda ip, email, **kw: {
            ip: {"fetched_at": 123.0, "updated": "2024-01-01"}
        }
        self.workflow.metadata(self.namespace)
        table = self.namespace["ip_data"].set_index("ipv4")
        self.assertEqual(table.loc["8.8.8.8", "enrichment_fetched_at"], 123.0)

    def test_iptoasn_loads_once_without_isc_or_synthetic_country_as_size(self):
        self.workflow.dns(self.namespace)
        self.environment["DSHIELD_IPTOASN_FILE"] = "local-iptoasn.tsv"
        self.enrichment.get_iptoasn_data.side_effect = lambda ip, db: {
            "source": "iptoasn", "status": "ok", "fetched_at": 100.0,
            "asn": 64500, "asn_organization": "Example network", "source_country": "US",
            "range_start": ip, "range_end": ip,
        }
        self.workflow.metadata(self.namespace)
        self.enrichment.load_iptoasn_database.assert_called_once_with("local-iptoasn.tsv")
        self.enrichment.isc_ipinfo.assert_not_called()
        self.assertEqual(self.enrichment.get_iptoasn_data.call_count, 4)
        table = self.namespace["ip_data"].set_index("ipv4")
        row = table.loc["8.8.8.8"]
        self.assertEqual(row["enrichment_source"], "iptoasn")
        self.assertEqual(row["source_country"], "US")
        self.assertEqual(row["asn_range_start"], "8.8.8.8")
        self.assertEqual(row["asn_range_end"], "8.8.8.8")
        for field in ("ascountry", "assize", "network", "updated"):
            self.assertTrue(pd.isna(row[field]), field)

    def test_local_missing_address_keeps_status_without_fabricated_metadata(self):
        self.workflow.dns(self.namespace)
        self.environment["DSHIELD_IPTOASN_FILE"] = "local-iptoasn.tsv"
        self.enrichment.get_iptoasn_data.side_effect = lambda ip, db: {
            "source": "iptoasn", "status": "not_found", "fetched_at": 100.0,
        }
        self.workflow.metadata(self.namespace)
        row = self.namespace["ip_data"].set_index("ipv4").loc["8.8.8.8"]
        self.assertEqual(row["enrichment_status"], "not_found")
        self.assertEqual(row["enrichment_fetched_at"], 100.0)
        for field in ("as", "asname", "ascountry", "assize", "network", "updated"):
            self.assertTrue(pd.isna(row[field]), field)
        self.enrichment.isc_ipinfo.assert_not_called()

    def test_maxmind_reader_is_reused_and_closed(self):
        self.workflow.dns(self.namespace)
        self.environment["DSHIELD_ASN_MMDB"] = "local-asn.mmdb"
        reader = _Resource()
        package = types.ModuleType("geoip2")
        package.database = types.ModuleType("geoip2.database")
        package.database.Reader = Mock(return_value=reader)
        self.enrichment.get_geoip_asn.side_effect = lambda ip, **kwargs: {
            "source": "maxmind_asn", "status": "ok", "fetched_at": 100.0,
            "asn": 64500, "asn_organization": "Example network", "lookup_network": "8.8.8.0/24",
        }
        with patch.dict(sys.modules, {"geoip2": package, "geoip2.database": package.database}):
            self.workflow.metadata(self.namespace)
        package.database.Reader.assert_called_once_with("local-asn.mmdb")
        self.assertTrue(reader.closed)
        self.assertEqual(self.enrichment.get_geoip_asn.call_count, 4)
        for call in self.enrichment.get_geoip_asn.call_args_list:
            self.assertIs(call.kwargs["reader"], reader)
        self.enrichment.isc_ipinfo.assert_not_called()
        row = self.namespace["ip_data"].set_index("ipv4").loc["8.8.8.8"]
        self.assertEqual(row["network"], "8.8.8.0/24")
        self.assertTrue(pd.isna(row["assize"]))
        self.assertTrue(pd.isna(row["ascountry"]))

    def test_conflicting_local_providers_fail_before_opening_resources(self):
        self.environment.update({"DSHIELD_ASN_MMDB": "local-asn.mmdb", "DSHIELD_IPTOASN_FILE": "local.tsv"})
        with self.assertRaisesRegex(ValueError, "Set only one"):
            self.workflow.metadata(self.namespace)
        self.enrichment.EnrichmentCache.assert_not_called()
        self.requests.Session.assert_not_called()

    def test_optional_shodan_responses_and_non_address_records_are_safe(self):
        extract = self.namespace["_shodan_ipv4_addresses"]
        for payload in (None, {}, {"data": None}, {"data": []}):
            with self.subTest(payload=payload):
                self.assertEqual(extract(payload), [])
        payload = {"data": [
            {"value": "1.1.1.1"}, {"value": "1.1.1.1"}, {"value": "8.8.8.8"},
            {"value": "2001:db8::1"}, {"value": "example.org"}, {"value": None},
            {"value": True}, {}, None, "bad record",
        ]}
        self.assertEqual(extract(payload), ["1.1.1.1", "8.8.8.8"])

    def test_leakix_and_onyphe_are_independent_and_ua_match_is_case_insensitive(self):
        self.namespace["research_data"] = pd.DataFrame()
        self.namespace["shodan_api"] = "test-value"
        self.enrichment.get_shodan_domain.side_effect = lambda domain, key: {
            "leakix.org": None,
            "onyphe.net": {"data": [{"value": "9.9.9.9"}]},
        }[domain]
        start, end = self.workflow.assignment("leakix_ips"), self.workflow.assignment("recyber_ips")
        with self.assertLogs(level="WARNING"):
            self.workflow.run(self.workflow.nodes[start:end], self.namespace)
        research = self.namespace["research_data"]
        self.assertEqual(research.loc[research["Research Organization"] == "LeakIX", "ipv4"].tolist(), ["8.8.8.8"])
        self.assertEqual(research.loc[research["Research Organization"] == "Onyphe", "ipv4"].tolist(), ["9.9.9.9"])

    def test_credentials_are_read_from_environment_with_empty_defaults(self):
        nodes = [self.workflow.nodes[self.workflow.assignment(name)] for name in ("email", "shodan_api")]
        self.workflow.run(nodes, self.namespace)
        self.assertEqual(self.namespace["email"], "")
        self.assertEqual(self.namespace["shodan_api"], "")
        self.environment.update({"DSHIELD_CONTACT_EMAIL": "analyst@example.org", "SHODAN_API_KEY": "test-value"})
        self.workflow.run(nodes, self.namespace)
        self.assertEqual(self.namespace["email"], "analyst@example.org")
        self.assertEqual(self.namespace["shodan_api"], "test-value")

    def test_direct_feed_requests_have_timeouts_and_check_http_status(self):
        response = _Resource()
        response.text = ""
        response.raise_for_status = Mock(side_effect=RuntimeError("HTTP failure"))
        self.requests.get.return_value = response
        with self.assertRaisesRegex(RuntimeError, "HTTP failure"):
            self.namespace["_get_feed_text"]("https://example.org/feed")
        self.requests.get.assert_called_once()
        timeout = self.requests.get.call_args.kwargs["timeout"]
        self.assertTrue(all(value > 0 for value in timeout))
        response.raise_for_status.assert_called_once_with()
        self.assertTrue(response.closed)

    def test_optional_feed_failures_preserve_ua_evidence_and_write_availability(self):
        self.namespace["web_data"].loc[0, "user-agent"] = "CensysInspect/1.0"
        self.namespace["web_data"].loc[1, "user-agent"] = "InternetMeasurement/1.0"
        self.workflow.dns(self.namespace)
        before = self.event_counts()
        self.enrichment.censys_networks.side_effect = _ProviderError("sensitive-provider-message")
        self.enrichment.binary_edge_minions.side_effect = _ProviderError("sensitive-provider-message")
        self.requests.get.side_effect = RuntimeError("sensitive-provider-message")
        self.enrichment.isc_research_threats.side_effect = _RateLimit(500.0)
        self.environment["DSHIELD_IPTOASN_FILE"] = "local-iptoasn.tsv"
        self.enrichment.get_iptoasn_data.side_effect = lambda ip, db: {
            "source": "iptoasn", "status": "ok", "fetched_at": 100.0,
        }
        with self.assertLogs(level="WARNING") as captured:
            # Run each real source section with providers failing. The UA-derived
            # addresses must survive even when the corresponding feed is absent.
            for start, end in (
                ("mass_scanners", "scanner_lookup"),
                ("censys_ips", "alphastrike_networks"),
                ("internetmeasurement_ips", "ipip_ips"),
            ):
                self.workflow.run(
                    self.workflow.nodes[self.workflow.assignment(start):self.workflow.assignment(end)],
                    self.namespace,
                )
            self.workflow.label_join("scanner_lookup", self.namespace)
            self.workflow.label_join("research_lookup", self.namespace)
            self.workflow.isc_labels(self.namespace)
        self.workflow.metadata(self.namespace)
        self.workflow.outputs(self.namespace)
        self.assert_event_counts_unchanged(before)
        table = self.namespace["enrichment_sources"].set_index("source")
        self.assertEqual(table.loc["isc_researchers", "status"], "deferred")
        self.assertEqual(table.loc["isc_researchers", "retry_at"], 500.0)
        for name in ("censys", "binaryedge", "maltrail", "internet_measurement"):
            self.assertEqual(table.loc[name, "status"], "error")
        self.assertTrue((table["checked_at"] == 111.0).all())
        self.assertNotIn("sensitive-provider-message", table.to_json())
        self.assertNotIn("sensitive-provider-message", "\n".join(captured.output))
        web = self.namespace["web_data"].set_index("event_id")
        self.assertEqual(web.loc[1, "Research Organization"], "Censys")
        self.assertEqual(web.loc[2, "Research Organization"], "Internet Measurement")
        self.assertTrue(web["isc_researcher"].isna().all())
        self.assertTrue(web["mass_scanner"].isna().all())
        self.enrichment.isc_ipinfo.assert_not_called()
        self.assertEqual(self.enrichment.get_iptoasn_data.call_count, 4)
        outputs = {call.args[2]: call.args[1] for call in self.sql.insert_df.call_args_list}
        self.assertEqual(set(outputs), {
            "web", "cowrie", "firewall", "mass_scanners", "public_researcher_data",
            "isc_researchers", "enrichment_sources",
        })
        pd.testing.assert_frame_equal(outputs["enrichment_sources"], self.namespace["enrichment_sources"])

    def test_missing_shodan_key_is_skipped_not_reported_as_negative(self):
        self.namespace["research_data"] = pd.DataFrame()
        start, end = self.workflow.assignment("leakix_ips"), self.workflow.assignment("recyber_ips")
        with self.assertLogs(level="WARNING"):
            self.workflow.run(self.workflow.nodes[start:end], self.namespace)
        self.enrichment.get_shodan_domain.assert_not_called()
        statuses = self.namespace["enrichment_sources"]
        self.assertEqual(len(statuses), 2)
        self.assertTrue(all(row["status"] == "skipped" for row in statuses))
        self.assertTrue(all(row["error"] == "missing_api_key" for row in statuses))
        research = self.namespace["research_data"]
        self.assertEqual(research["Research Organization"].tolist(), ["LeakIX"])

    def test_unavailable_and_invalid_optional_response_shapes_are_unknown(self):
        optional = self.namespace["_optional_feed"]
        with self.assertLogs(level="WARNING"):
            self.assertEqual(optional("no_result", lambda: None, []), [])
            self.assertEqual(optional("wrong_shape", lambda: {}, []), [])
        rows = self.namespace["enrichment_sources"]
        self.assertEqual(rows[0]["status"], "unavailable")
        self.assertEqual(rows[1]["status"], "error")
        self.assertEqual(rows[1]["error"], "TypeError")


if __name__ == "__main__":
    unittest.main()
