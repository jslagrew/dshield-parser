# Changelog

## 0.2.0 — 2026-11-04

### Added

- Local GeoLite2 ASN and GeoLite2/GeoIP2 Country/City lookup functions, with an
  optional `geoip` installation extra and reusable reader support.
- Validated, reusable IPv4/IPv6 IPtoASN TSV/gzip indexes and binary-search lookups.
- Selective authoritative RDAP lookups with IANA bootstrap, bounded referrals,
  returned contact extraction, and exact-query caching. The former
  `get_whois_data` placeholder now delegates to RDAP.
- Thread-safe SQLite enrichment cache with independent provider namespaces,
  record expiration, persistent cooldowns, and context-manager cleanup.
- Structured PTR results and bounded DNS batch iteration, including authoritative
  negative TTLs, short transient-failure cooldowns, and resolver-specific cache keys.
- Atomic, size-limited ISC `daily_sources` and `threatintel` feed downloads.
- Offline enrichment regression tests, Linux/Windows CI, usage documentation,
  and release tag/version verification before PyPI publishing.

### Corrected

- ISC IP lookups now use explicit timeouts and bounded retries. Rate limits raise
  `EnrichmentRateLimitError` with retry timing instead of sleeping indefinitely.
  Missing optional fields and malformed 429 responses are handled safely.
- Related ISC/scanner HTTP helpers no longer retry forever; contact User-Agent
  interpolation is corrected for the ISC intel helper, and user-agent lookup
  paths correctly encode spaces and reserved URL characters.
- Legacy `get_reverse_dns` retains its string result while using bounded DNS
  resolution and correct exception handling.
- Example PTR processing covers all three log sources and uses public result
  interfaces. Completed DNS results are persistently cached.
- Example IP metadata is unique by IP, with validated joins. Multiple scanner
  labels are aggregated before joining, preserving raw label tables.
- Onyphe records are labeled `Onyphe`; actual LeakIX records remain `LeakIX`.
- Example credentials are read from environment variables; absent optional
  Shodan configuration skips its lookups safely.
- Optional scanner/researcher feed failures no longer stop local ASN enrichment.
  Source availability and retry timing are recorded separately in the
  `enrichment_sources` table, preserving unknown labels and UA evidence.

### Migration

- New ASN providers are opt-in through function calls or example configuration.
  MaxMind database files and IPtoASN downloads are supplied by the caller.
- Catch `EnrichmentRateLimitError` and defer work until `retry_at`. Live provider
  failures are visible instead of causing an unbounded wait.
- The updated example uses the new SQLite cache and does not automatically import
  `ip_lookups.txt`, whose entries lack reliable fetch/expiration timestamps.
- Geolocation, registry country, ASN country, lookup range, and ASN size remain
  separate concepts. Fields unavailable from a provider are left empty.
- The package version is maintained in `dshield_parser/_version.py` and exposed as
  `dshield_parser.__version__`; `setup.py` reads that same value.

See [IP enrichment and migration examples](docs/IP-ENRICHMENT.md).
