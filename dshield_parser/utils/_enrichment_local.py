"""Offline enrichment from caller-managed MaxMind and IPtoASN databases.

Database downloads and refreshes are deliberately left to the caller. Reuse a
MaxMind reader or an :class:`IPtoASNDatabase` for batches of addresses; opening or
parsing the database for every event defeats the benefit of a local lookup.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import os
import time
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
PathLike = str | os.PathLike[str]
_MAX_IPV4 = (1 << 32) - 1
_MAX_ASN = (1 << 32) - 1


def _canonical_ip(value: str | IPAddress) -> IPAddress:
    """Require an IP literal rather than interpreting an integer as IPv4."""
    if not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise ValueError("ip must be an IPv4 or IPv6 address literal")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value!r}") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("Scoped IPv6 addresses are not supported by enrichment databases")
    return address


def _base_result(address: IPAddress, source: str) -> dict[str, Any]:
    return {
        "ip": str(address),
        "source": source,
        "status": "not_found",
        "fetched_at": time.time(),
        "cache_hit": False,
    }


def _is_address_not_found(error: Exception) -> bool:
    # A supplied reader may work without geoip2 being installed. Import its
    # exception class only when a lookup fails, and preserve unrelated errors.
    try:
        from geoip2.errors import AddressNotFoundError
    except ImportError:
        return False
    return isinstance(error, AddressNotFoundError)


def _get_geoip_data(
    ip: str | IPAddress,
    database_path: PathLike | None,
    reader: Any,
    database_kind: str,
) -> dict[str, Any]:
    address = _canonical_ip(ip)
    if database_path is not None and reader is not None:
        raise ValueError("Provide either database_path or reader, not both")
    owned_reader = reader is None
    path = None
    if owned_reader:
        if database_path is None:
            raise ValueError("Provide a local database_path or an open MaxMind reader")
        path = str(Path(database_path).expanduser().resolve())
        try:
            from geoip2.database import Reader
        except ImportError as exc:
            raise ImportError(
                "MaxMind lookups require the optional geoip dependency; "
                "install it with: pip install 'dshield-parser[geoip]'"
            ) from exc
        reader = Reader(path)

    result = _base_result(address, f"maxmind_{database_kind}")
    result.update({
        "dataset_path": path,
        "dataset_build_epoch": None,
        "dataset_type": None,
        "lookup_network": None,
    })
    if database_kind == "asn":
        result.update({"asn": None, "asn_organization": None})
    else:
        result.update({"geo_country": None, "registered_country": None})

    try:
        metadata_method = getattr(reader, "metadata", None)
        if callable(metadata_method):
            metadata = metadata_method()
            result["dataset_build_epoch"] = getattr(metadata, "build_epoch", None)
            result["dataset_type"] = getattr(metadata, "database_type", None)
        method = database_kind
        if database_kind == "country" and result["dataset_type"] in (
            "GeoLite2-City", "GeoIP2-City"
        ):
            method = "city"
        try:
            record = getattr(reader, method)(str(address))
        except Exception as exc:
            if _is_address_not_found(exc):
                return result
            raise
        if database_kind == "asn":
            asn = getattr(record, "autonomous_system_number", None)
            if asn in (None, 0):
                return result
            result.update({
                "asn": asn,
                "asn_organization": getattr(record, "autonomous_system_organization", None),
            })
            network = getattr(record, "network", None)
        else:
            result.update({
                "geo_country": getattr(getattr(record, "country", None), "iso_code", None),
                "registered_country": getattr(
                    getattr(record, "registered_country", None), "iso_code", None
                ),
            })
            network = getattr(getattr(record, "traits", None), "network", None)
        result["lookup_network"] = str(network) if network is not None else None
        result["status"] = "ok"
        return result
    finally:
        if owned_reader:
            reader.close()


def get_geoip_asn(
    ip: str | IPAddress,
    database_path: PathLike | None = None,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Look up an ASN in a local GeoLite2 ASN MMDB database.

    Supply exactly one of ``database_path`` or ``reader``. An open reader is
    reusable and remains owned by the caller; a reader opened here is closed
    after the lookup. ``lookup_network`` is the database's matched network,
    not a claim about the currently announced BGP prefix. A missing address
    returns ``status='not_found'``; invalid IPs and unreadable, corrupt, or
    incompatible databases raise their underlying exceptions.

    ``dataset_build_epoch`` is the MMDB build time when available. For a
    caller-supplied reader, ``dataset_path`` is unknown and is ``None``.
    """
    return _get_geoip_data(ip, database_path, reader, "asn")


def get_geoip_country(
    ip: str | IPAddress,
    database_path: PathLike | None = None,
    *,
    reader: Any = None,
) -> dict[str, Any]:
    """Look up countries in a local GeoLite2/GeoIP2 Country or City MMDB.

    ``geo_country`` describes the country located by the database, whereas
    ``registered_country`` describes the country of the registered network.
    They may differ. Reader ownership, errors, and provenance behave as in
    :func:`get_geoip_asn`. No database download or remote lookup is performed.
    """
    return _get_geoip_data(ip, database_path, reader, "country")


@dataclass(frozen=True, slots=True)
class _ASNRange:
    start: int
    end: int
    asn: int
    country: str | None
    organization: str | None


@dataclass(frozen=True, slots=True)
class IPtoASNDatabase:
    """An immutable in-memory index created by :func:`load_iptoasn_database`.

    Reuse this object for an entire enrichment batch. Loading reads the file
    once; lookups use binary search without reopening or rescanning it. The
    stored modification time and size describe the file at load time and do
    not claim to be the upstream dataset's creation time.
    """

    dataset_path: str
    dataset_mtime: float
    dataset_mtime_ns: int
    dataset_size_bytes: int
    _ipv4_ranges: tuple[_ASNRange, ...]
    _ipv4_starts: tuple[int, ...]
    _ipv6_ranges: tuple[_ASNRange, ...]
    _ipv6_starts: tuple[int, ...]

    @property
    def range_count(self) -> int:
        """Number of indexed ranges, including unallocated AS0 ranges."""
        return len(self._ipv4_ranges) + len(self._ipv6_ranges)

    def lookup(self, ip: str | IPAddress) -> dict[str, Any]:
        """Return the same result as :func:`get_iptoasn_data`."""
        return get_iptoasn_data(ip, self)


def _range_endpoint(value: str) -> IPAddress:
    if value.isascii() and value.isdigit():
        integer = int(value)
        if integer > _MAX_IPV4:
            raise ValueError(
                "integer range endpoints must be IPv4 values between 0 and 4294967295; "
                "use IPv6 address notation for IPv6 ranges"
            )
        return ipaddress.IPv4Address(integer)
    return _canonical_ip(value)


def _read_iptoasn_ranges(
    stream: io.TextIOBase,
    path: Path,
) -> tuple[list[_ASNRange], list[_ASNRange]]:
    ranges: dict[int, list[_ASNRange]] = {4: [], 6: []}
    for line_number, line in enumerate(stream, 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            columns = line.rstrip("\r\n").split("\t")
            if len(columns) != 5:
                raise ValueError(
                    "expected five tab-separated columns: range_start, range_end, "
                    "AS_number, country_code, AS_description"
                )
            start_text, end_text, asn_text, country, organization = (
                column.strip() for column in columns
            )
            start_address = _range_endpoint(start_text)
            end_address = _range_endpoint(end_text)
            if start_address.version != end_address.version:
                raise ValueError("range endpoints must use the same IP version")
            start, end = int(start_address), int(end_address)
            if start > end:
                raise ValueError("range start must be less than or equal to range end")
            if not asn_text.isascii() or not asn_text.isdigit():
                raise ValueError("AS_number must be an unsigned integer")
            asn = int(asn_text)
            if asn > _MAX_ASN:
                raise ValueError("AS_number must be between 0 and 4294967295")
            family_ranges = ranges[start_address.version]
            if family_ranges:
                previous = family_ranges[-1]
                if start < previous.start:
                    raise ValueError(
                        f"IPv{start_address.version} ranges must be sorted by start address"
                    )
                if start <= previous.end:
                    raise ValueError(f"overlapping IPv{start_address.version} ranges")
            family_ranges.append(_ASNRange(
                start=start,
                end=end,
                asn=asn,
                country=country or None,
                organization=organization or None,
            ))
        except ValueError as exc:
            raise ValueError(f"Invalid IPtoASN database {path} at line {line_number}: {exc}") from exc
    if not ranges[4] and not ranges[6]:
        raise ValueError(f"IPtoASN database {path} contains no address ranges")
    return ranges[4], ranges[6]


def load_iptoasn_database(path: PathLike) -> IPtoASNDatabase:
    """Read and index an IPtoASN TSV or gzip-compressed TSV file once.

    Supports IPv4, IPv6, and combined files, including integer IPv4 endpoints.
    Rows contain ``range_start``, ``range_end``, ``AS_number``, ``country_code``,
    and ``AS_description``. Blank lines and ``#`` comments are ignored. Ranges
    must be ordered by start within each IP family and cannot overlap; gaps
    are allowed. Invalid, empty, or truncated datasets raise ``ValueError``.

    This function never downloads a dataset. Call it again after replacing
    the local file to use a refreshed version. Existing index objects retain
    the data and file metadata they loaded.
    """
    database_path = Path(path).expanduser().resolve()
    with database_path.open("rb") as raw:
        file_info = os.fstat(raw.fileno())
        magic = raw.read(2)
        raw.seek(0)
        compressed = magic == b"\x1f\x8b" or database_path.suffix.lower() == ".gz"
        binary = gzip.GzipFile(fileobj=raw, mode="rb") if compressed else raw
        try:
            with io.TextIOWrapper(binary, encoding="utf-8-sig") as stream:
                ipv4_ranges, ipv6_ranges = _read_iptoasn_ranges(stream, database_path)
                final_info = os.fstat(raw.fileno())
                if (file_info.st_mtime_ns, file_info.st_size) != (
                    final_info.st_mtime_ns, final_info.st_size
                ):
                    raise ValueError(
                        f"IPtoASN database {database_path} changed while loading; retry with a stable file"
                    )
        except (UnicodeError, OSError, EOFError) as exc:
            raise ValueError(f"Cannot decode IPtoASN database {database_path}: {exc}") from exc

    return IPtoASNDatabase(
        dataset_path=str(database_path),
        dataset_mtime=file_info.st_mtime,
        dataset_mtime_ns=file_info.st_mtime_ns,
        dataset_size_bytes=file_info.st_size,
        _ipv4_ranges=tuple(ipv4_ranges),
        _ipv4_starts=tuple(row.start for row in ipv4_ranges),
        _ipv6_ranges=tuple(ipv6_ranges),
        _ipv6_starts=tuple(row.start for row in ipv6_ranges),
    )


def get_iptoasn_data(ip: str | IPAddress, database: IPtoASNDatabase) -> dict[str, Any]:
    """Return ASN data from a previously loaded IPtoASN database.

    ``range_start`` and ``range_end`` preserve the source's inclusive interval;
    the interval may not be a single network or an exact BGP announcement.
    ``source_country`` preserves IPtoASN's country field and is not asserted
    to be geolocation or an ISC/RDAP registration-country equivalent. Gaps,
    missing IP families, and AS0/unallocated intervals return ``not_found``.
    """
    address = _canonical_ip(ip)
    if not isinstance(database, IPtoASNDatabase):
        raise TypeError("database must be returned by load_iptoasn_database(path)")
    result = _base_result(address, "iptoasn")
    result.update({
        "dataset_path": database.dataset_path,
        "dataset_mtime": database.dataset_mtime,
        "dataset_mtime_ns": database.dataset_mtime_ns,
        "dataset_size_bytes": database.dataset_size_bytes,
        "asn": None,
        "asn_organization": None,
        "source_country": None,
        "range_start": None,
        "range_end": None,
    })
    if address.version == 4:
        ranges, starts = database._ipv4_ranges, database._ipv4_starts
        address_type = ipaddress.IPv4Address
    else:
        ranges, starts = database._ipv6_ranges, database._ipv6_starts
        address_type = ipaddress.IPv6Address
    integer = int(address)
    position = bisect_right(starts, integer) - 1
    if position < 0:
        return result
    row = ranges[position]
    if integer > row.end or row.asn == 0:
        return result
    result.update({
        "status": "ok",
        "asn": row.asn,
        "asn_organization": row.organization,
        "source_country": row.country,
        "range_start": str(address_type(row.start)),
        "range_end": str(address_type(row.end)),
    })
    return result
