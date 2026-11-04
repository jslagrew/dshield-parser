"""Offline integration tests through the supported enrichment import path."""

import importlib.util
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import dns.exception
import requests

import dshield_parser
from dshield_parser.utils import enrichment


SOURCE_ROOT = Path(__file__).resolve().parents[2]
CONTACT = "enrichment-tests@example.test"


def response(body, *, status=200, content_type="application/json"):
    """An actual Requests response with an already received fixture body."""
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = content_type
    result._content = body.encode("utf-8") if isinstance(body, str) else body
    result._content_consumed = True
    return result


class PtrAnswer(list):
    def __init__(self, hostname="host.example."):
        super().__init__([SimpleNamespace(target=hostname)])
        self.expiration = time.time() + 120


class PublicEnrichmentTests(unittest.TestCase):
    def test_base_import_and_local_reader_work_without_geoip_extra(self):
        # A fresh interpreter catches eager optional imports even when another
        # test has previously imported geoip2 in this process.
        script = textwrap.dedent("""
            import importlib.abc
            import sys
            from types import SimpleNamespace

            class NoGeoip(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == 'geoip2' or fullname.startswith('geoip2.'):
                        raise ModuleNotFoundError('geoip2 intentionally unavailable')
                    return None

            sys.meta_path.insert(0, NoGeoip())
            import dshield_parser
            from dshield_parser.utils import enrichment
            assert dshield_parser.__version__
            assert 'geoip2' not in sys.modules
            reader = SimpleNamespace(asn=lambda ip: SimpleNamespace(
                autonomous_system_number=64500,
                autonomous_system_organization='Fixture',
                network='192.0.2.0/24',
            ))
            assert enrichment.get_geoip_asn('192.0.2.1', reader=reader)['asn'] == 64500
            try:
                enrichment.get_geoip_asn('192.0.2.1', 'unused.mmdb')
            except ImportError as exc:
                assert 'dshield-parser[geoip]' in str(exc), str(exc)
            else:
                raise AssertionError('missing geoip2 must explain the optional extra')
        """)
        completed = subprocess.run(
            [sys.executable, "-c", script], cwd=SOURCE_ROOT,
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipUnless((SOURCE_ROOT / "setup.py").is_file(), "requires source checkout")
    def test_package_metadata_uses_imported_version_and_keeps_geoip_optional(self):
        with patch("setuptools.setup") as setup:
            runpy.run_path(str(SOURCE_ROOT / "setup.py"), run_name="__main__")
        metadata = setup.call_args.kwargs
        self.assertEqual(metadata["version"], dshield_parser.__version__)
        self.assertRegex(dshield_parser.__version__, r"^\d+\.\d+\.\d+$")
        self.assertTrue(any(value.startswith("dnspython") for value in metadata["install_requires"]))
        self.assertFalse(any(value.startswith("geoip2") for value in metadata["install_requires"]))
        self.assertTrue(any(value.startswith("geoip2") for value in metadata["extras_require"]["geoip"]))

    def test_public_iptoasn_load_and_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip2asn.tsv"
            path.write_text(
                "192.0.2.0\t192.0.2.255\t64500\tUS\tFixture Network\n"
                "2001:db8::\t2001:db8::ffff\t64501\tCA\tIPv6 Fixture\n",
                encoding="utf-8",
            )
            database = enrichment.load_iptoasn_database(path)
            path.unlink()  # The public lookup must use the loaded reusable index.
            result = enrichment.get_iptoasn_data("2001:0DB8::1", database)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ip"], "2001:db8::1")
        self.assertEqual(result["asn"], 64501)
        self.assertEqual(result["source_country"], "CA")

    def test_public_dns_structured_result_and_legacy_string_share_cache(self):
        resolver = SimpleNamespace(
            enrichment_cache_identity="public-api-dns",
            resolve_address=Mock(return_value=PtrAnswer()),
        )
        with enrichment.EnrichmentCache(":memory:") as cache:
            result = enrichment.get_reverse_dns_info(
                "192.0.2.1", resolver=resolver, cache=cache, lifetime=0.25
            )
            legacy = enrichment.get_reverse_dns("192.0.2.1", resolver=resolver, cache=cache)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(legacy, "host.example")
        resolver.resolve_address.assert_called_once_with(
            "192.0.2.1", lifetime=0.25, raise_on_no_answer=False
        )

    def test_legacy_dns_failure_remains_empty_string_without_hiding_status(self):
        resolver = SimpleNamespace(
            enrichment_cache_identity="public-api-dns-timeout",
            resolve_address=Mock(side_effect=dns.exception.Timeout()),
        )
        with enrichment.EnrichmentCache(":memory:") as cache:
            with self.assertLogs(level="WARNING"):
                self.assertEqual(enrichment.get_reverse_dns(
                    "192.0.2.1", resolver=resolver, cache=cache
                ), "")
            self.assertEqual(enrichment.get_reverse_dns_info(
                "192.0.2.1", resolver=resolver, cache=cache
            )["status"], "timeout")
        self.assertEqual(resolver.resolve_address.call_count, 1)

    def test_public_dns_batch_is_unique_and_propagates_programmer_errors(self):
        resolver = SimpleNamespace(
            enrichment_cache_identity="public-api-batch",
            resolve_address=Mock(return_value=PtrAnswer()),
        )
        results = list(enrichment.iter_reverse_dns(
            ["192.0.2.1", "192.0.2.1", "2001:db8::1", "2001:0db8::1"],
            max_workers=2, resolver=resolver,
        ))
        self.assertEqual({item["ip"] for item in results}, {"192.0.2.1", "2001:db8::1"})
        self.assertEqual(len(results), 2)
        resolver.resolve_address.side_effect = TypeError("invalid custom resolver")
        with self.assertRaisesRegex(TypeError, "invalid custom resolver"):
            list(enrichment.iter_reverse_dns(["192.0.2.2"], resolver=resolver))

    def test_public_rdap_and_whois_alias_use_exact_ip_cache(self):
        payload = {
            "objectClassName": "ip network", "handle": "FIXTURE-NET",
            "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "country": "US", "entities": [{
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.test"]]],
            }],
        }
        session = Mock(spec=requests.Session)
        session.get.side_effect = [response(json.dumps(payload)), response(json.dumps(payload))]
        options = {"email": CONTACT, "session": session,
                   "bootstrap": {"8.8.8.0/24": "https://registry.example/rdap/"}}
        with enrichment.EnrichmentCache(":memory:") as cache:
            first = enrichment.get_rdap_data("8.8.8.8", cache=cache, **options)
            alias = enrichment.get_whois_data("8.8.8.8", cache=cache, **options)
            neighbor = enrichment.get_rdap_data("8.8.8.9", cache=cache, **options)
        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["network"]["handle"], "FIXTURE-NET")
        self.assertEqual(first["abuse_contacts"], ["abuse@example.test"])
        self.assertFalse(first["cache_hit"])
        self.assertTrue(alias["cache_hit"])
        self.assertFalse(neighbor["cache_hit"])
        self.assertEqual(session.get.call_count, 2)
        session.close.assert_not_called()

    def test_public_isc_legacy_fields_and_cache(self):
        session = Mock(spec=requests.Session)
        session.get.return_value = response(
            "<ip><number>8.8.8.8</number><as>15169</as><asname>GOOGLE</asname>"
            "<network>8.8.8.0/24</network><weblogs><count>5</count></weblogs></ip>",
            content_type="application/xml",
        )
        with enrichment.EnrichmentCache(":memory:") as cache:
            first = enrichment.isc_ipinfo("8.8.8.8", CONTACT, session=session, cache=cache)
            second = enrichment.isc_ipinfo("8.8.8.8", CONTACT, session=session, cache=cache)
        self.assertFalse(first["8.8.8.8"]["cache_hit"])
        self.assertTrue(second["8.8.8.8"]["cache_hit"])
        self.assertEqual(
            {key: value for key, value in first["8.8.8.8"].items() if key != "cache_hit"},
            {key: value for key, value in second["8.8.8.8"].items() if key != "cache_hit"},
        )
        self.assertEqual(first["8.8.8.8"]["asname"], "GOOGLE")
        self.assertEqual(first["8.8.8.8"]["weblog_count"], "5")
        self.assertIsNone(first["8.8.8.8"]["asabusecontact"])
        session.get.assert_called_once()
        session.close.assert_not_called()

    def test_public_feed_download_preserves_provider_text(self):
        session = Mock(spec=requests.Session)
        body = b"# fixture feed\n8.8.8.8\t12\n"
        session.get.return_value = response(body, content_type="text/plain")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "daily_sources.txt"
            result = enrichment.download_isc_feed(
                "daily_sources", path, email=CONTACT, session=session, max_bytes=1024
            )
            self.assertEqual(path.read_bytes(), body)
        self.assertEqual(result["status"], "downloaded")
        session.close.assert_not_called()

    def test_empty_research_feed_has_joinable_schema_and_date_fallback(self):
        session = Mock(spec=requests.Session)
        session.get.side_effect = [
            response("<threatcategory/>", content_type="application/xml"),
            response(
                "<threatcategory><research><ipv4>192.0.2.1</ipv4>"
                "<date>2026-11-01</date><type>fixture</type>"
                "</research></threatcategory>", content_type="application/xml",
            ),
        ]
        with patch.object(enrichment._http.requests, "Session", return_value=session):
            empty = enrichment.isc_research_threats(CONTACT)
            populated = enrichment.isc_research_threats(CONTACT)
        self.assertTrue(empty.empty)
        self.assertEqual(list(empty.columns), ["ipv4", "added", "lastseen", "type"])
        self.assertEqual(populated.iloc[0]["added"], "2026-11-01")
        self.assertEqual(populated.iloc[0]["ipv4"], "192.0.2.1")
        self.assertIsNone(populated.iloc[0]["lastseen"])
        self.assertEqual(session.close.call_count, 2)

    def test_useragent_lookup_quotes_dynamic_path_components(self):
        user_agent = "Example Scanner/1.0?mode=full#fragment"
        for day, encoded_day in (
            (7, "7"),
            ("2026/11/04?x#y", "2026%2F11%2F04%3Fx%23y"),
        ):
            with self.subTest(day=day):
                with patch.object(enrichment._http, "request_get") as request:
                    request.return_value.__enter__.return_value = response('{"hits": 3}')
                    result = enrichment.isc_webhoneypot_useragents(user_agent, day, CONTACT)
                request.assert_called_once_with(
                    "https://isc.sans.edu/api/webhoneypotreportsbyua/"
                    "Example%20Scanner%2F1.0%3Fmode%3Dfull%23fragment/"
                    f"{encoded_day}?json",
                    email=CONTACT, stream=True,
                )
                self.assertEqual(result, {"hits": 3})

    def test_shodan_without_key_needs_neither_sdk_nor_network(self):
        enrichment.get_shodan_host.cache_clear()
        enrichment.get_shodan_domain.cache_clear()
        with patch.dict(sys.modules, {"shodan": None}):
            with patch("requests.Session.request", side_effect=AssertionError("network is forbidden")):
                for key in (None, ""):
                    with self.subTest(key=key):
                        self.assertIsNone(enrichment.get_shodan_host("192.0.2.1", key))
                        self.assertEqual(enrichment.get_shodan_domain("example.test", key), {"data": []})
        enrichment.get_shodan_host.cache_clear()
        enrichment.get_shodan_domain.cache_clear()

    @unittest.skipUnless(importlib.util.find_spec("geoip2") is not None, "requires optional geoip2 SDK")
    def test_real_geoip_sdk_models_match_public_wrappers(self):
        # Exercise geoip2 Reader's real database-type checks and model objects;
        # replace only the binary-file backend, without downloading a database.
        from geoip2.database import Reader

        for kind, data, lookup, expected_key, expected_value in (
            ("GeoLite2-ASN", {"autonomous_system_number": 64500,
                              "autonomous_system_organization": "Fixture"},
             enrichment.get_geoip_asn, "asn", 64500),
            ("GeoLite2-Country", {"country": {"iso_code": "CA"},
                                  "registered_country": {"iso_code": "US"}},
             enrichment.get_geoip_country, "geo_country", "CA"),
            ("GeoIP2-City", {"country": {"iso_code": "GB"},
                             "registered_country": {"iso_code": "US"}},
             enrichment.get_geoip_country, "geo_country", "GB"),
        ):
            with self.subTest(database=kind):
                backend = Mock()
                backend.metadata.return_value = SimpleNamespace(
                    database_type=kind, build_epoch=1700000000
                )
                backend.get_with_prefix_len.return_value = (data, 24)
                with patch("maxminddb.open_database", return_value=backend):
                    with Reader("fixture.mmdb") as reader:
                        result = lookup("192.0.2.1", reader=reader)
                        self.assertEqual(result["status"], "ok")
                        self.assertEqual(result[expected_key], expected_value)
                        self.assertEqual(result["lookup_network"], "192.0.2.0/24")
                        self.assertEqual(result["dataset_type"], kind)
                        backend.get_with_prefix_len.return_value = (None, 24)
                        self.assertEqual(lookup("192.0.2.1", reader=reader)["status"], "not_found")
                        backend.close.assert_not_called()
                backend.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
