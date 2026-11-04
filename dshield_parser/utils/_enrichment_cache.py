"""Small, explicit, persistent cache shared by enrichment providers."""

import json
import math
import os
import sqlite3
import threading
import time
from pathlib import Path


class EnrichmentCache:
    """Store JSON dictionaries in SQLite until their individual expiration.

    ``path`` is an explicit database filename (or ``":memory:"``). Instances may
    be shared by worker threads; independent instances may open the same file.
    ``clock`` is an optional callable returning UTC Unix seconds, mainly useful
    when testing expiration. Close the cache, or use it as a context manager,
    once its workers have finished.
    """

    def __init__(self, path, *, clock=time.time):
        if not callable(clock):
            raise TypeError("clock must be callable")
        path = os.fspath(path)
        if not isinstance(path, str) or not path:
            raise ValueError("path must be a nonempty filename or ':memory:'")
        if path != ":memory:":
            path = str(Path(path).expanduser())
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            path, timeout=30.0, check_same_thread=False
        )
        try:
            # The single locked connection also makes :memory: useful to workers.
            # WAL lets other processes read a file while a lookup is being saved.
            if path != ":memory:":
                self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS enrichment_cache ("
                "namespace TEXT NOT NULL, cache_key TEXT NOT NULL, "
                "expires_at REAL NOT NULL, value TEXT NOT NULL, "
                "PRIMARY KEY (namespace, cache_key))"
            )
            self._connection.commit()
        except BaseException:
            self._connection.close()
            self._connection = None
            raise

    @staticmethod
    def _validate_key(namespace, key):
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("namespace must be a nonempty string")
        if not isinstance(key, str):
            raise TypeError("key must be a string")

    def _open_connection(self):
        if self._connection is None:
            raise RuntimeError("EnrichmentCache is closed")
        return self._connection

    def get(self, namespace, key):
        """Return an independent dictionary for an unexpired entry, else None."""
        self._validate_key(namespace, key)
        with self._lock:
            connection = self._open_connection()
            row = connection.execute(
                "SELECT expires_at, value FROM enrichment_cache "
                "WHERE namespace = ? AND cache_key = ?",
                (namespace, key),
            ).fetchone()
            if row is None:
                return None
            if row[0] <= self._clock():
                # Include the observed expiration so another cache instance's
                # replacement cannot be deleted between SELECT and DELETE.
                with connection:
                    connection.execute(
                        "DELETE FROM enrichment_cache WHERE namespace = ? "
                        "AND cache_key = ? AND expires_at = ?",
                        (namespace, key, row[0]),
                    )
                return None
            return json.loads(row[1])

    def put(self, namespace, key, value, *, ttl=None, expires_at=None):
        """Save a dict using exactly one expiration form, in UTC Unix seconds.

        A zero TTL or an expiration in the past is accepted, but never produces
        a fresh entry. Nonfinite times and non-JSON values are rejected.
        """
        self._validate_key(namespace, key)
        if not isinstance(value, dict):
            raise TypeError("cache values must be JSON dictionaries")
        if (ttl is None) == (expires_at is None):
            raise ValueError("provide exactly one of ttl or expires_at")
        duration = ttl if ttl is not None else expires_at
        if isinstance(duration, bool) or not isinstance(duration, (int, float)):
            raise TypeError("expiration must be a finite number")
        if not math.isfinite(duration):
            raise ValueError("expiration must be finite")
        if ttl is not None:
            if ttl < 0:
                raise ValueError("ttl must be nonnegative")
            expires_at = self._clock() + ttl
        if not math.isfinite(expires_at):
            raise ValueError("expiration must be finite")
        # Encoding before saving detaches the cache from future caller mutations.
        payload = json.dumps(value, allow_nan=False, separators=(",", ":"))
        with self._lock:
            connection = self._open_connection()
            with connection:
                connection.execute(
                    "INSERT INTO enrichment_cache "
                    "(namespace, cache_key, expires_at, value) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(namespace, cache_key) DO UPDATE SET "
                    "expires_at = excluded.expires_at, value = excluded.value",
                    (namespace, key, float(expires_at), payload),
                )

    def close(self):
        """Close the connection; repeated closes are harmless."""
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def __enter__(self):
        with self._lock:
            self._open_connection()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
