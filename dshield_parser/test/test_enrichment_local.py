"""Offline coverage for reusable local enrichment database lookups."""

import gzip
import ipaddress
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dshield_parser.utils._enrichment_local import (
    get_geoip_asn,
    get_geoip_country,
    get_iptoasn_data,
    load_iptoasn_database,
)


class AddressNotFoundError(Exception):
    pass


def fake_geoip_modules(reader_factory=None):
    package = types.ModuleType("geoip2")
    database = types.ModuleType("geoip2.database")
    database.Reader = reader_factory
    errors = types.ModuleType("geoip2.errors")
    errors.AddressNotFoundError = AddressNotFoundError
    package.database = database
    package.errors = errors
    return {"geoip2": package, "geoip2.database": database, "geoip2.errors": errors}


def fake_asn_reader():
    return SimpleNamespace(
        asn=Mock(return_value=SimpleNamespace(
            autonomous_system_number=64500,
            autonomous_system_organization="Example network",
            network=ipaddress.ip_network("2001:db8::/32"),
        )),
        metadata=Mock(return_value=SimpleNamespace(
            build_epoch=1700000000,
            database_type="GeoLite2-ASN",
        )),
        close=Mock(),
    )


def fake_country_reader():
    return SimpleNamespace(
        country=Mock(return_value=SimpleNamespace(
            country=SimpleNamespace(iso_code="CA"),
            registered_country=SimpleNamespace(iso_code="US"),
            traits=SimpleNamespace(network=ipaddress.ip_network("192.0.2.0/24")),
        )),
        metadata=Mock(return_value=SimpleNamespace(
            build_epoch=1700000000,
            database_type="GeoLite2-Country",
        )),
        close=Mock(),
    )


class TestMaxMindEnrichment(unittest.TestCase):
    def test_asn_reuses_reader_and_canonicalizes_ip(self):
        reader = fake_asn_reader()
        with patch("dshield_parser.utils._enrichment_local.time.time", return_value=1730000000.5):
            first = get_geoip_asn("2001:0DB8:0:0:0:0:0:1", reader=reader)
            second = get_geoip_asn(ipaddress.ip_address("2001:db8::2"), reader=reader)
        self.assertEqual(first["ip"], "2001:db8::1")
        self.assertEqual(first["source"], "maxmind_asn")
        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["asn"], 64500)
        self.assertEqual(first["asn_organization"], "Example network")
        self.assertEqual(first["lookup_network"], "2001:db8::/32")
        self.assertEqual(first["fetched_at"], 1730000000.5)
        self.assertFalse(first["cache_hit"])
        self.assertEqual(first["dataset_build_epoch"], 1700000000)
        self.assertEqual(first["dataset_type"], "GeoLite2-ASN")
        self.assertIsNone(first["dataset_path"])
        self.assertEqual(second["ip"], "2001:db8::2")
        reader.asn.assert_any_call("2001:db8::1")
        self.assertEqual(reader.asn.call_count, 2)
        reader.close.assert_not_called()

    def test_country_keeps_geography_and_registration_distinct(self):
        reader = fake_country_reader()
        result = get_geoip_country("192.0.2.1", reader=reader)
        self.assertEqual(result["geo_country"], "CA")
        self.assertEqual(result["registered_country"], "US")
        self.assertEqual(result["source"], "maxmind_country")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["lookup_network"], "192.0.2.0/24")
        reader.close.assert_not_called()

    def test_country_accepts_city_database_using_city_method(self):
        reader = fake_country_reader()
        reader.metadata.return_value.database_type = "GeoLite2-City"
        reader.city = Mock(return_value=reader.country.return_value)
        result = get_geoip_country("192.0.2.1", reader=reader)
        self.assertEqual(result["geo_country"], "CA")
        reader.city.assert_called_once_with("192.0.2.1")
        reader.country.assert_not_called()

    def test_missing_addresses_return_not_found(self):
        with patch.dict(sys.modules, fake_geoip_modules()):
            for lookup, reader, method, key in (
                (get_geoip_asn, fake_asn_reader(), "asn", "asn"),
                (get_geoip_country, fake_country_reader(), "country", "geo_country"),
            ):
                with self.subTest(method=method):
                    getattr(reader, method).side_effect = AddressNotFoundError("No record")
                    result = lookup("192.0.2.1", reader=reader)
                    self.assertEqual(result["status"], "not_found")
                    self.assertIsNone(result[key])
                    self.assertIsNone(result["lookup_network"])
                    self.assertEqual(result["dataset_build_epoch"], 1700000000)
                    reader.close.assert_not_called()

    def test_zero_asn_is_not_found(self):
        reader = fake_asn_reader()
        reader.asn.return_value.autonomous_system_number = 0
        result = get_geoip_asn("192.0.2.1", reader=reader)
        self.assertEqual(result["status"], "not_found")
        self.assertIsNone(result["asn"])

    def test_owned_reader_is_closed_after_success(self):
        reader = fake_asn_reader()
        factory = Mock(return_value=reader)
        with patch.dict(sys.modules, fake_geoip_modules(factory)):
            result = get_geoip_asn("192.0.2.1", "example.mmdb")
        factory.assert_called_once_with(str(Path("example.mmdb").resolve()))
        self.assertEqual(result["dataset_path"], str(Path("example.mmdb").resolve()))
        reader.close.assert_called_once_with()

    def test_owned_reader_is_closed_after_failure(self):
        reader = fake_asn_reader()
        reader.asn.side_effect = RuntimeError("Corrupt database")
        with patch.dict(sys.modules, fake_geoip_modules(Mock(return_value=reader))):
            with self.assertRaisesRegex(RuntimeError, "Corrupt database"):
                get_geoip_asn("192.0.2.1", "example.mmdb")
        reader.close.assert_called_once_with()

    def test_owned_reader_is_closed_after_address_not_found(self):
        reader = fake_asn_reader()
        reader.asn.side_effect = AddressNotFoundError("No record")
        with patch.dict(sys.modules, fake_geoip_modules(Mock(return_value=reader))):
            result = get_geoip_asn("192.0.2.1", "example.mmdb")
        self.assertEqual(result["status"], "not_found")
        reader.close.assert_called_once_with()

    def test_unrelated_reader_failures_propagate_without_closing_supplied_reader(self):
        reader = fake_asn_reader()
        reader.asn.side_effect = RuntimeError("Wrong database")
        with self.assertRaisesRegex(RuntimeError, "Wrong database"):
            get_geoip_asn("192.0.2.1", reader=reader)
        reader.close.assert_not_called()

    def test_supplied_reader_does_not_require_optional_dependency(self):
        reader = fake_asn_reader()
        with patch.dict(sys.modules, {"geoip2": None, "geoip2.database": None, "geoip2.errors": None}):
            self.assertEqual(get_geoip_asn("192.0.2.1", reader=reader)["asn"], 64500)

    def test_missing_dependency_explains_install_extra(self):
        with patch.dict(sys.modules, {"geoip2": None, "geoip2.database": None}):
            with self.assertRaisesRegex(ImportError, r"dshield-parser\[geoip\]"):
                get_geoip_asn("192.0.2.1", "example.mmdb")

    def test_reader_or_path_is_required_and_ambiguous_inputs_are_rejected(self):
        for lookup in (get_geoip_asn, get_geoip_country):
            with self.subTest(lookup=lookup.__name__):
                with self.assertRaisesRegex(ValueError, "database_path"):
                    lookup("192.0.2.1")
                with self.assertRaisesRegex(ValueError, "not both"):
                    lookup("192.0.2.1", "example.mmdb", reader=fake_asn_reader())

    def test_invalid_addresses_do_not_query_reader(self):
        reader = fake_asn_reader()
        for value in ("bad", "256.1.1.1", "example.com", "fe80::1%eth0", True, 1, None):
            with self.subTest(ip=value), self.assertRaises(ValueError):
                get_geoip_asn(value, reader=reader)
        reader.asn.assert_not_called()

    def test_missing_metadata_and_optional_country_fields_are_allowed(self):
        reader = SimpleNamespace(country=Mock(return_value=SimpleNamespace()))
        result = get_geoip_country("192.0.2.1", reader=reader)
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["geo_country"])
        self.assertIsNone(result["registered_country"])
        self.assertIsNone(result["dataset_build_epoch"])
        self.assertIsNone(result["lookup_network"])


class TestIPtoASNEnrichment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ip2asn.tsv"

    def load(self, contents, compressed=False):
        if compressed:
            self.path = self.path.with_suffix(".tsv.gz")
            with gzip.open(self.path, "wt", encoding="utf-8") as stream:
                stream.write(contents)
        else:
            self.path.write_text(contents, encoding="utf-8")
        return load_iptoasn_database(self.path)

    def test_inclusive_boundaries_and_gaps(self):
        database = self.load(
            "192.0.2.1\t192.0.2.7\t64500\tUS\tFirst network\n"
            "192.0.2.9\t192.0.2.20\t64501\tCA\tSecond network\n"
        )
        for ip in ("192.0.2.1", "192.0.2.7"):
            with self.subTest(ip=ip):
                result = get_iptoasn_data(ip, database)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["asn"], 64500)
                self.assertEqual(result["range_start"], "192.0.2.1")
                self.assertEqual(result["range_end"], "192.0.2.7")
                self.assertEqual(result["source_country"], "US")
                self.assertEqual(result["asn_organization"], "First network")
                self.assertNotIn("lookup_network", result)
        self.assertEqual(get_iptoasn_data("192.0.2.9", database)["asn"], 64501)
        self.assertEqual(get_iptoasn_data("192.0.2.20", database)["asn"], 64501)
        for ip in ("192.0.2.0", "192.0.2.8", "192.0.2.21", "2001:db8::1"):
            with self.subTest(ip=ip):
                result = database.lookup(ip)
                self.assertEqual(result["status"], "not_found")
                self.assertIsNone(result["asn"])
                self.assertIsNone(result["range_start"])

    def test_integer_ipv4_endpoints_include_full_unsigned_bounds(self):
        database = self.load(
            "0\t0\t64500\tUS\tLow boundary\n"
            "4294967295\t4294967295\t64501\tGB\tHigh boundary\n"
        )
        self.assertEqual(database.lookup("0.0.0.0")["asn"], 64500)
        high = database.lookup("255.255.255.255")
        self.assertEqual(high["asn"], 64501)
        self.assertEqual(high["range_start"], "255.255.255.255")

    def test_gzip_combined_file_and_ipv6_boundaries(self):
        database = self.load(
            "192.0.2.1\t192.0.2.1\t64500\tUS\tIPv4 network\n"
            "::\t::1\t64501\tDE\tLow IPv6\n"
            "2001:db8::1\t2001:db8::ff\t64502\tJP\tIPv6 network\n"
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\tffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\t64503\tCA\tHigh IPv6\n",
            compressed=True,
        )
        self.assertEqual(database.range_count, 4)
        self.assertEqual(database.lookup("192.0.2.1")["asn"], 64500)
        self.assertEqual(database.lookup("::")["asn"], 64501)
        self.assertEqual(database.lookup("::1")["range_start"], "::")
        self.assertEqual(database.lookup("::2")["status"], "not_found")
        for ip in ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::ff"):
            with self.subTest(ip=ip):
                result = database.lookup(ip)
                self.assertEqual(result["asn"], 64502)
                self.assertEqual(result["range_end"], "2001:db8::ff")
        self.assertEqual(database.lookup("2001:db8::100")["status"], "not_found")
        self.assertEqual(database.lookup("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")["asn"], 64503)

    def test_gzip_is_detected_without_filename_suffix(self):
        with gzip.open(self.path, "wt", encoding="utf-8") as stream:
            stream.write("192.0.2.0\t192.0.2.255\t64500\tUS\tExample\n")
        self.assertEqual(load_iptoasn_database(self.path).lookup("192.0.2.1")["asn"], 64500)

    def test_ipv6_only_file_and_canonical_ip_objects(self):
        database = self.load("2001:db8::\t2001:db8::ffff\t64500\tUS\tIPv6 only\n")
        result = database.lookup(ipaddress.IPv6Address("2001:0DB8::1"))
        self.assertEqual(result["ip"], "2001:db8::1")
        self.assertEqual(result["asn"], 64500)
        self.assertEqual(database.lookup("192.0.2.1")["status"], "not_found")

    def test_as_zero_is_unallocated(self):
        database = self.load("192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n")
        result = database.lookup("192.0.2.1")
        self.assertEqual(result["status"], "not_found")
        self.assertIsNone(result["asn"])
        self.assertIsNone(result["source_country"])

    def test_dataset_provenance_is_retained_without_rereading_file(self):
        database = self.load("192.0.2.0\t192.0.2.255\t64500\tUS\tExample\n")
        original_stat = self.path.stat()
        self.path.unlink()
        with patch("dshield_parser.utils._enrichment_local.time.time", return_value=1730000000.5):
            result = database.lookup("192.0.2.1")
        self.assertEqual(result["asn"], 64500)
        self.assertEqual(result["dataset_path"], str(self.path.resolve()))
        self.assertEqual(result["dataset_mtime"], original_stat.st_mtime)
        self.assertEqual(result["dataset_mtime_ns"], original_stat.st_mtime_ns)
        self.assertEqual(result["dataset_size_bytes"], original_stat.st_size)
        self.assertEqual(result["source"], "iptoasn")
        self.assertEqual(result["fetched_at"], 1730000000.5)
        self.assertFalse(result["cache_hit"])

    def test_bom_comments_empty_lines_and_adjacent_ranges(self):
        database = self.load(
            "\ufeff# Source file\n\n"
            "192.0.2.0\t192.0.2.1\t64500\t\t\n"
            "192.0.2.2\t192.0.2.3\t64501\tUS\tAdjacent\n"
        )
        result = database.lookup("192.0.2.1")
        self.assertIsNone(result["source_country"])
        self.assertIsNone(result["asn_organization"])
        self.assertEqual(database.lookup("192.0.2.2")["asn"], 64501)

    def test_overlapping_ranges_are_rejected(self):
        for last in (
            "192.0.2.7\t192.0.2.9\t64501\tUS\tOverlap\n",
            "192.0.2.1\t192.0.2.2\t64501\tUS\tDuplicate start\n",
        ):
            with self.subTest(last=last), self.assertRaisesRegex(ValueError, "line 2: overlapping"):
                self.load("192.0.2.1\t192.0.2.7\t64500\tUS\tFirst\n" + last)
        with self.assertRaisesRegex(ValueError, "overlapping IPv6"):
            self.load(
                "2001:db8::1\t2001:db8::ff\t64500\tUS\tFirst\n"
                "2001:db8::f\t2001:db8::fff\t64501\tUS\tOverlap\n"
            )

    def test_out_of_order_ranges_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "sorted by start address"):
            self.load(
                "192.0.2.10\t192.0.2.11\t64500\tUS\tLater\n"
                "192.0.2.1\t192.0.2.2\t64501\tUS\tEarlier\n"
            )

    def test_malformed_rows_and_bounds_are_rejected_with_line_number(self):
        rows = (
            "192.0.2.1\t192.0.2.2\t64500\tUS",  # missing description
            "192.0.2.1\t192.0.2.2\t64500\tUS\tExample\textra",
            "invalid\t192.0.2.2\t64500\tUS\tExample",
            "192.0.2.2\t192.0.2.1\t64500\tUS\tReversed",
            "192.0.2.1\t2001:db8::1\t64500\tUS\tMixed",
            "-1\t1\t64500\tUS\tNegative",
            "4294967296\t4294967297\t64500\tUS\tToo large",
            "192.0.2.1\t192.0.2.2\tAS64500\tUS\tNot numeric",
            "192.0.2.1\t192.0.2.2\t-1\tUS\tNegative ASN",
            "192.0.2.1\t192.0.2.2\t4294967296\tUS\tToo large ASN",
            "fe80::1%eth0\tfe80::2%eth0\t64500\tUS\tScoped",
        )
        for row in rows:
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "line 2:"):
                self.load("# Header\n" + row + "\n")

    def test_empty_and_missing_databases_are_reported(self):
        with self.assertRaises(FileNotFoundError):
            load_iptoasn_database(self.path)
        for contents in ("", "\n# Only comments\n"):
            with self.subTest(contents=contents), self.assertRaisesRegex(ValueError, "no address ranges"):
                self.load(contents)

    def test_invalid_gzip_and_text_encodings_are_reported(self):
        gzip_path = self.path.with_suffix(".gz")
        gzip_path.write_bytes(b"not a gzip file")
        with self.assertRaisesRegex(ValueError, "Cannot decode IPtoASN"):
            load_iptoasn_database(gzip_path)
        self.path.write_bytes(b"\xff\x00")
        with self.assertRaisesRegex(ValueError, "Cannot decode IPtoASN"):
            load_iptoasn_database(self.path)

    def test_truncated_gzip_is_reported(self):
        complete = gzip.compress(b"192.0.2.1\t192.0.2.2\t64500\tUS\tExample\n")
        self.path.write_bytes(complete[:-8])
        with self.assertRaisesRegex(ValueError, "Cannot decode IPtoASN"):
            load_iptoasn_database(self.path)

    def test_lookup_requires_valid_literal_and_preloaded_index(self):
        database = self.load("192.0.2.1\t192.0.2.2\t64500\tUS\tExample\n")
        for value in ("invalid", "example.com", "fe80::1%eth0", 1, True, None):
            with self.subTest(ip=value), self.assertRaises(ValueError):
                database.lookup(value)
        with self.assertRaisesRegex(TypeError, "load_iptoasn_database"):
            get_iptoasn_data("192.0.2.1", self.path)


if __name__ == "__main__":
    unittest.main()
