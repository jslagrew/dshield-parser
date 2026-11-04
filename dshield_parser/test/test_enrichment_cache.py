"""Offline tests for the shared enrichment cache."""

import concurrent.futures
import math
from pathlib import Path
import sqlite3
import tempfile
import unittest

from dshield_parser.utils._enrichment_cache import EnrichmentCache


class EnrichmentCacheTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.cache = EnrichmentCache(":memory:", clock=lambda: self.now)
        self.addCleanup(self.cache.close)

    def test_ttl_absolute_expiry_and_defensive_copies(self):
        source = {"items": ["first"]}
        self.cache.put("dns", "key", source, ttl=10)
        source["items"].append("changed")
        first = self.cache.get("dns", "key")
        self.assertEqual(first, {"items": ["first"]})
        first["items"].append("changed again")
        self.assertEqual(self.cache.get("dns", "key"), {"items": ["first"]})
        self.now = 110.0
        self.assertIsNone(self.cache.get("dns", "key"))
        self.cache.put("dns", "key", {"fresh": True}, expires_at=111)
        self.assertEqual(self.cache.get("dns", "key"), {"fresh": True})
        self.now = 111
        self.assertIsNone(self.cache.get("dns", "key"))

    def test_upsert_and_namespace_isolation(self):
        self.cache.put("dns", "same", {"n": 1}, ttl=10)
        self.cache.put("dns", "same", {"n": 2}, ttl=30)
        self.cache.put("rdap", "same", {"n": 3}, ttl=10)
        self.assertEqual(self.cache.get("dns", "same"), {"n": 2})
        self.assertEqual(self.cache.get("rdap", "same"), {"n": 3})
        self.assertIsNone(self.cache.get("dns", "missing"))

    def test_disk_cache_survives_close_and_never_duplicates_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subdirectory" / "cache.sqlite"
            with EnrichmentCache(path, clock=lambda: self.now) as cache:
                cache.put("dns", "ip", {"old": True}, ttl=20)
                cache.put("dns", "ip", {"new": True}, ttl=30)
            with EnrichmentCache(path, clock=lambda: self.now) as cache:
                self.assertEqual(cache.get("dns", "ip"), {"new": True})
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM enrichment_cache"
                ).fetchone()[0], 1)
                self.assertEqual(connection.execute(
                    "PRAGMA journal_mode"
                ).fetchone()[0], "wal")

    def test_multiple_threads_share_memory_connection(self):
        def worker(number):
            key = str(number)
            self.cache.put("workers", key, {"number": number}, ttl=10)
            self.assertEqual(self.cache.get("workers", key), {"number": number})
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(worker, range(80)))
        self.assertEqual(self.cache.get("workers", "79"), {"number": 79})

    def test_independent_instances_share_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.sqlite"
            with EnrichmentCache(path) as first, EnrichmentCache(path) as second:
                first.put("dns", "shared", {"written": 1}, ttl=30)
                self.assertEqual(second.get("dns", "shared"), {"written": 1})
                second.put("dns", "shared", {"written": 2}, ttl=30)
                self.assertEqual(first.get("dns", "shared"), {"written": 2})

    def test_expired_and_zero_ttl_are_not_fresh(self):
        self.cache.put("dns", "zero", {}, ttl=0)
        self.cache.put("dns", "past", {}, expires_at=99)
        self.assertIsNone(self.cache.get("dns", "zero"))
        self.assertIsNone(self.cache.get("dns", "past"))

    def test_invalid_expirations_and_values(self):
        for kwargs in ({}, {"ttl": 1, "expires_at": 101}, {"ttl": -1},
                       {"ttl": math.nan}, {"expires_at": math.inf}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.cache.put("dns", "key", {}, **kwargs)
        for duration in (True, "5"):
            with self.subTest(duration=duration), self.assertRaises(TypeError):
                self.cache.put("dns", "key", {}, ttl=duration)
        with self.assertRaises(TypeError):
            self.cache.put("dns", "key", [], ttl=10)
        with self.assertRaises(ValueError):
            self.cache.put("dns", "key", {"n": math.nan}, ttl=10)
        with self.assertRaises(TypeError):
            self.cache.put("dns", "key", {"n": object()}, ttl=10)

    def test_close_is_idempotent_and_prevents_future_use(self):
        self.cache.close()
        self.cache.close()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            self.cache.get("dns", "key")
        with self.assertRaisesRegex(RuntimeError, "closed"):
            self.cache.put("dns", "key", {}, ttl=10)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            self.cache.__enter__()


if __name__ == "__main__":
    unittest.main()
