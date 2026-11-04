"""Bounded HTTP enrichment with explicit cache and provider cooldown support.

Timestamps are UTC Unix seconds.  A caller-owned requests.Session is never
closed here; sessions created by this module are closed after each operation.
The cache protocol is EnrichmentCache.get(namespace, key) / put(..., ttl=...).
"""

from contextlib import contextmanager
from email.utils import parsedate_to_datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import re
import tempfile
import threading
import time
from urllib.parse import unquote, urljoin, urlsplit
import xml.etree.ElementTree as ET

import requests


DEFAULT_TIMEOUT = (3.05, 10)
ISC_FEEDS = {
    "daily_sources": "https://feeds.dshield.org/feeds/daily_sources",
    "threatintel": "https://isc.sans.edu/feeds/threatintel.txt",
}
_BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
_COOLDOWNS = {}
_BOOTSTRAPS = {}
_FEED_DOWNLOADS = {}
_STATE_LOCK = threading.Lock()
_TRANSIENT_STATUS = {500, 502, 503, 504}
_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_PUBLIC_HEADERS = {
    "accept", "accept-encoding", "accept-language", "user-agent", "connection",
    "cache-control", "if-none-match", "if-modified-since", "range",
}


class _PublicRedirectAuth(requests.auth.AuthBase):
    """Remove credentials after Session defaults and cookies are prepared."""

    def __call__(self, prepared_request):
        for name in list(prepared_request.headers):
            if name.lower() not in _PUBLIC_HEADERS:
                del prepared_request.headers[name]
        return prepared_request


class EnrichmentError(RuntimeError):
    """An expected provider, transport, or response parsing failure."""


class EnrichmentRateLimitError(EnrichmentError):
    """A provider cooldown; defer work until retry_at instead of sleeping."""

    def __init__(self, origin, retry_after, *, retry_at=None):
        self.origin = origin
        self.retry_after = max(0.0, float(retry_after))
        self.retry_at = (time.time() + self.retry_after
                         if retry_at is None else float(retry_at))
        super().__init__(
            f"{origin} is rate limited; retry in {self.retry_after:.0f} seconds"
        )


class EnrichmentHTTPError(EnrichmentError):
    """An HTTP failure after the bounded retry policy has been applied."""

    def __init__(self, status_code, url):
        self.status_code = status_code
        self.url = url
        super().__init__(f"HTTP {status_code} from {url}")


def _canonical_ip(value):
    if not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise ValueError("ip must be an IPv4 or IPv6 address literal")
    address = ipaddress.ip_address(value)
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("Scoped IPv6 addresses are not supported by HTTP enrichment")
    return address


def _positive_number(value, name):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0):
        raise ValueError(f"{name} must be a positive finite number")
    return value


def _validate_request_options(email, timeout, max_attempts):
    if (not isinstance(email, str) or not re.fullmatch(r"[^@\s]+@[^@\s]+", email)):
        raise ValueError("email must be a contact email address without whitespace")
    values = timeout if isinstance(timeout, tuple) else (timeout,)
    if isinstance(timeout, tuple) and len(timeout) != 2:
        raise ValueError("timeout must be a positive number or (connect, read) pair")
    for value in values:
        _positive_number(value, "timeout")
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= 10:
        raise ValueError("max_attempts must be an integer from 1 to 10")


def _safe_url(url):
    """Require HTTPS without credentials, fragments, or private literal hosts."""
    if not isinstance(url, str) or any(ord(char) < 33 for char in url):
        raise EnrichmentError("Invalid enrichment URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise EnrichmentError("Invalid enrichment URL") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or port not in (None, 443)):
        raise EnrichmentError("Enrichment requests require an HTTPS URL on port 443")
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith((".localhost", ".local")):
        raise EnrichmentError("Private enrichment endpoints are not supported")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise EnrichmentError("Private enrichment endpoints are not supported")
    return url


def _origin(url):
    parsed = urlsplit(_safe_url(url))
    host = parsed.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}"


def _check_cooldown(origin, cache):
    now = time.time()
    with _STATE_LOCK:
        retry_at = _COOLDOWNS.get(origin, 0)
        if retry_at <= now:
            _COOLDOWNS.pop(origin, None)
    if cache is not None:
        record = cache.get("http:cooldown", origin)
        if record:
            retry_at = max(retry_at, float(record.get("retry_at", 0)))
    if retry_at > now:
        raise EnrichmentRateLimitError(origin, retry_at - now, retry_at=retry_at)


def _retry_after(response, body):
    header = response.headers.get("Retry-After", "").strip()
    if header:
        try:
            seconds = float(header)
            if math.isfinite(seconds) and seconds >= 0:
                return seconds
        except ValueError:
            pass
        try:
            parsed = parsedate_to_datetime(header)
            if parsed.tzinfo is not None:
                return max(0.0, parsed.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            pass
    # ISC sometimes sends only an HTML error, without Retry-After.
    match = re.search(rb"try\s+again\s+after\s+(\d+)\s+seconds", body, re.I)
    return float(match.group(1)) if match else 300.0


def _limited_error_body(response):
    try:
        result = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                result.extend(chunk[:16384 - len(result)])
                if len(result) >= 16384:
                    break
        return bytes(result)
    except requests.RequestException:
        return b""


def _record_cooldown(response, origin, cache):
    delay = _retry_after(response, _limited_error_body(response))
    retry_at = time.time() + delay
    with _STATE_LOCK:
        retry_at = max(retry_at, _COOLDOWNS.get(origin, 0))
        _COOLDOWNS[origin] = retry_at
    if cache is not None and retry_at > time.time():
        cache.put("http:cooldown", origin, {"retry_at": retry_at}, expires_at=retry_at)
    raise EnrichmentRateLimitError(origin, retry_at - time.time(), retry_at=retry_at)


@contextmanager
def request_get(url, *, email, session=None, cache=None,
                timeout=DEFAULT_TIMEOUT, max_attempts=3, headers=None,
                stream=False, max_redirects=5, strip_credentials=False):
    """Yield a response, then close it and any internally created session.

    Use ``with request_get(url, email=contact) as response: ...``. Transport
    errors and 500/502/503/504 retry at most max_attempts times per URL, with
    short capped backoff. A 429 (or a 503 with Retry-After) immediately raises
    EnrichmentRateLimitError and starts an origin-wide cooldown. Other HTTP
    failures are terminal. Redirects must stay HTTPS and are capped. Cross-origin
    redirects remove authentication, cookies, and custom headers after Session
    defaults are applied; the original Session is not modified.
    """
    _validate_request_options(email, timeout, max_attempts)
    if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects must be an integer from 0 to 10")
    url = _safe_url(url)
    request_headers = dict(headers or {})
    # Always identify the client, even when callers add Accept or other headers.
    request_headers = {key: value for key, value in request_headers.items()
                       if key.lower() != "user-agent"}
    request_headers["User-Agent"] = f"dshield-parser (contact: {email})"
    owned = session is None
    client = requests.Session() if owned else session
    response = None
    visited = set()
    try:
        for redirect_count in range(max_redirects + 1):
            if url in visited:
                raise EnrichmentError("Enrichment redirect loop")
            visited.add(url)
            origin = _origin(url)
            for attempt in range(max_attempts):
                _check_cooldown(origin, cache)
                try:
                    options = {"headers": request_headers, "timeout": timeout,
                               "allow_redirects": False, "stream": stream}
                    if strip_credentials:
                        options["auth"] = _PublicRedirectAuth()
                    response = client.get(url, **options)
                except (requests.ConnectionError, requests.Timeout) as exc:
                    if attempt + 1 == max_attempts:
                        raise EnrichmentError(f"Request to {url} failed after {max_attempts} attempts") from exc
                except requests.RequestException as exc:
                    raise EnrichmentError(f"Request to {url} failed") from exc
                else:
                    status = response.status_code
                    if status == 429 or (status == 503 and response.headers.get("Retry-After")):
                        _record_cooldown(response, origin, cache)
                    if status not in _TRANSIENT_STATUS or attempt + 1 == max_attempts:
                        break
                    response.close()
                    response = None
                time.sleep(min(0.5 * (2 ** attempt) + random.uniform(0, 0.25), 4.0))
            status = response.status_code
            if status in _REDIRECT_STATUS:
                location = response.headers.get("Location")
                if not location or redirect_count == max_redirects:
                    raise EnrichmentError("Missing redirect target or enrichment redirect limit exceeded")
                next_url = _safe_url(urljoin(url, location))
                strip_credentials = strip_credentials or _origin(next_url) != origin
                url = next_url
                response.close()
                response = None
                continue
            if not 200 <= status < 300:
                raise EnrichmentHTTPError(status, url)
            # The original URL is available on real requests responses; this
            # attribute also makes redirected source provenance unambiguous.
            response.enrichment_url = url
            yield response
            return
    finally:
        if response is not None:
            response.close()
        if owned:
            client.close()


def _response_length(response):
    value = response.headers.get("Content-Length")
    if value is None:
        return None
    try:
        declared = int(value)
        if declared < 0:
            raise ValueError("Negative response length")
        return declared
    except (ValueError, TypeError) as exc:
        raise EnrichmentError("Provider returned an invalid Content-Length") from exc


def _read_body(response, max_bytes):
    declared = _response_length(response)
    if declared is not None and declared > max_bytes:
        raise EnrichmentError(f"Response exceeds {max_bytes} byte limit")
    body = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                if len(body) + len(chunk) > max_bytes:
                    raise EnrichmentError(f"Response exceeds {max_bytes} byte limit")
                body.extend(chunk)
    except requests.RequestException as exc:
        raise EnrichmentError("Response body could not be downloaded") from exc
    if (declared is not None and not response.headers.get("Content-Encoding")
            and len(body) != declared):
        raise EnrichmentError("Provider response body does not match Content-Length")
    return bytes(body)


def _json_payload(response):
    body = _read_body(response, 8 * 1024 * 1024)
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise EnrichmentError("Provider returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise EnrichmentError("Provider JSON must be an object")
    return payload


def isc_ipinfo(ip, email, *, session=None, cache=None, timeout=DEFAULT_TIMEOUT,
               max_attempts=3, cache_ttl=86400):
    """Return legacy ISC fields, with bounded requests and optional TTL caching.

    Missing or empty optional XML fields are None. The IP record also contains
    fetched_at, expires_at and cache_hit metadata. A provider cooldown is raised to the
    caller; this function never sleeps for ISC's five-minute throttle interval.
    """
    _validate_request_options(email, timeout, max_attempts)
    _positive_number(cache_ttl, "cache_ttl")
    address = str(_canonical_ip(ip))
    if cache is not None:
        cached = cache.get("isc:ip", address)
        if cached is not None:
            cached[address]["cache_hit"] = True
            return cached
    with request_get(
        f"https://isc.sans.edu/api/ip/{address}", email=email, session=session,
        cache=cache, timeout=timeout, max_attempts=max_attempts, stream=True,
        headers={"Accept": "application/xml, text/xml"},
    ) as response:
        body = _read_body(response, 1024 * 1024)
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise EnrichmentError("ISC returned invalid or empty XML") from exc
    # A well-formed HTML error page must not be cached as an empty IP result.
    if root.tag.lower() != "ip" or not root.findtext("number"):
        raise EnrichmentError("ISC response does not contain an IP information record")
    try:
        returned_address = str(_canonical_ip(root.findtext("number").strip()))
    except ValueError as exc:
        raise EnrichmentError("ISC response contains an invalid IP address") from exc
    if returned_address != address:
        raise EnrichmentError("ISC response IP does not match the requested address")
    fields = {
        name: (root.findtext(name) or "").strip() or None for name in (
            "number", "count", "attacks", "maxdate", "mindate", "updated",
            "comment", "maxrisk", "asabusecontact", "as", "asname",
            "ascountry", "assize", "network",
        )
    }
    for output, element in {
        "weblog_count": "count", "weblog_avgauthors": "avgauthors",
        "weblog_avgurls": "avgurls", "weblog_avguseragents": "avguser_agents",
        "weblog_firstseen": "firstseen", "lastseen": "lastseen",
    }.items():
        fields[output] = (root.findtext(f"weblogs/{element}") or "").strip() or None
    now = time.time()
    fields.update(number=address, fetched_at=now, expires_at=now + cache_ttl, cache_hit=False)
    result = {address: fields}
    if cache is not None:
        cache.put("isc:ip", address, result, expires_at=fields["expires_at"])
    return result


def _load_bootstrap(version, bootstrap, *, email, session, cache, timeout, max_attempts):
    if bootstrap is not None:
        if isinstance(bootstrap, dict):
            return bootstrap
        try:
            with open(bootstrap, "rb") as source:
                payload = json.load(source)
        except (OSError, ValueError, TypeError) as exc:
            raise EnrichmentError("Could not read RDAP bootstrap JSON") from exc
        if not isinstance(payload, dict):
            raise EnrichmentError("RDAP bootstrap JSON must be an object")
        return payload
    if cache is not None:
        cached = cache.get("rdap:bootstrap", str(version))
        if cached is not None:
            return cached
    with _STATE_LOCK:
        remembered = _BOOTSTRAPS.get(version)
    if remembered is not None and remembered[0] > time.time():
        return remembered[1]
    with request_get(
        _BOOTSTRAP_URLS[version], email=email, session=session, cache=cache,
        timeout=timeout, max_attempts=max_attempts, stream=True,
        headers={"Accept": "application/json"}, strip_credentials=True,
    ) as response:
        payload = _json_payload(response)
    if not isinstance(payload.get("services"), list):
        raise EnrichmentError("IANA bootstrap does not contain services")
    with _STATE_LOCK:
        _BOOTSTRAPS[version] = (time.time() + 604800, payload)
    if cache is not None:
        cache.put("rdap:bootstrap", str(version), payload, ttl=604800)
    return payload


def _rdap_endpoint(address, bootstrap):
    services = bootstrap.get("services")
    if services is None:
        services = [([prefix], [urls] if isinstance(urls, str) else urls)
                    for prefix, urls in bootstrap.items()]
    if not isinstance(services, (list, tuple)):
        raise EnrichmentError("RDAP bootstrap services must be a list")
    best = None
    try:
        for prefixes, urls in services:
            if not isinstance(prefixes, (list, tuple)) or not isinstance(urls, (list, tuple)):
                raise ValueError("Malformed service")
            for prefix in prefixes:
                network = ipaddress.ip_network(prefix, strict=False)
                if network.version != address.version or address not in network:
                    continue
                for base in urls:
                    if not isinstance(base, str) or not base.startswith("https://"):
                        continue
                    _safe_url(base)
                    if best is None or network.prefixlen > best[0]:
                        best = (network.prefixlen, base)
                    break
    except (ValueError, TypeError) as exc:
        raise EnrichmentError("Invalid RDAP bootstrap service") from exc
    if best is None:
        raise EnrichmentError("No HTTPS RDAP service matches this IP address")
    return urljoin(best[1].rstrip("/") + "/", f"ip/{address}")


def _rdap_referral(payload, address):
    links = payload.get("links", [])
    if not isinstance(links, list):
        return None
    for link in links:
        if not isinstance(link, dict) or link.get("rel") != "related":
            continue
        media_type = str(link.get("type", "application/rdap+json")).split(";", 1)[0].strip()
        if media_type != "application/rdap+json":
            continue
        href = link.get("href")
        if not isinstance(href, str):
            continue
        # Follow only an explicit referral for this exact IP. Parent networks,
        # entities, ASN records and arbitrary related links are not referrals.
        try:
            parsed = urlsplit(href)
        except ValueError as exc:
            raise EnrichmentError("Invalid RDAP referral URL") from exc
        if parsed.query or "/ip/" not in parsed.path:
            continue
        suffix = unquote(parsed.path.rsplit("/ip/", 1)[1]).rstrip("/")
        try:
            same_ip = ipaddress.ip_address(suffix) == address
        except ValueError:
            continue
        if same_ip:
            return _safe_url(href)
    return None


def _abuse_contacts(entities):
    contacts = []
    stack = [(item, 0) for item in entities]
    while stack:
        entity, depth = stack.pop()
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", [])
        if isinstance(roles, list) and "abuse" in roles:
            card = entity.get("vcardArray", [])
            if isinstance(card, list) and len(card) == 2 and isinstance(card[1], list):
                for prop in card[1]:
                    if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "email":
                        values = prop[3] if isinstance(prop[3], list) else [prop[3]]
                        contacts.extend(value for value in values if isinstance(value, str))
        children = entity.get("entities", [])
        if depth < 10 and isinstance(children, list):
            stack.extend((item, depth + 1) for item in children)
    return sorted(set(contacts))


def get_rdap_data(ip, *, email, session=None, cache=None, bootstrap=None,
                  timeout=DEFAULT_TIMEOUT, max_attempts=3, cache_ttl=604800):
    """Fetch the authoritative registry record for one IP, without ASN queries.

    bootstrap may be an IANA-style object, a prefix-to-HTTPS-base-URL mapping,
    or a path to either JSON form. Returned network country is a registry
    attribute, not geolocation. Only entities already in the reply are exposed.
    Cache entries are keyed by exact request URL, never by returned subnet.
    """
    _validate_request_options(email, timeout, max_attempts)
    _positive_number(cache_ttl, "cache_ttl")
    address = _canonical_ip(ip)
    now = time.time()
    if not address.is_global:
        return {"ip": str(address), "source": "rdap", "status": "not_global",
                "fetched_at": now, "expires_at": None, "cache_hit": False,
                "network": None, "entities": [], "abuse_contacts": [], "raw": None}
    routing = _load_bootstrap(address.version, bootstrap, email=email,
                              session=session, cache=cache, timeout=timeout,
                              max_attempts=max_attempts)
    initial_url = _rdap_endpoint(address, routing)
    if cache is not None:
        cached = cache.get("rdap:ip", initial_url)
        if cached is not None:
            cached["cache_hit"] = True
            return cached
    url = initial_url
    visited = set()
    payload = None
    for referral_count in range(6):
        if url in visited:
            raise EnrichmentError("RDAP referral loop")
        visited.add(url)
        try:
            with request_get(
                url, email=email, session=session, cache=cache, timeout=timeout,
                max_attempts=max_attempts, stream=True,
                headers={"Accept": "application/rdap+json"},
                strip_credentials=_origin(url) != _origin(initial_url),
            ) as response:
                payload = _json_payload(response)
                source_url = response.enrichment_url
        except EnrichmentHTTPError as exc:
            if exc.status_code != 404:
                raise
            now = time.time()
            result = {"ip": str(address), "source": exc.url, "status": "not_found",
                      "fetched_at": now, "expires_at": now + min(cache_ttl, 300),
                      "cache_hit": False, "network": None, "entities": [],
                      "abuse_contacts": [], "raw": None}
            if cache is not None:
                cache.put("rdap:ip", initial_url, result, expires_at=result["expires_at"])
            return result
        referral = _rdap_referral(payload, address)
        if referral is None or referral == source_url:
            break
        if referral_count == 5:
            raise EnrichmentError("RDAP referral limit exceeded")
        visited.add(source_url)
        url = referral
    if payload.get("objectClassName") != "ip network":
        raise EnrichmentError("RDAP response is not an IP network record")
    try:
        start = ipaddress.ip_address(payload["startAddress"])
        end = ipaddress.ip_address(payload["endAddress"])
        if start.version != address.version or end.version != address.version or not start <= address <= end:
            raise ValueError("RDAP range does not contain requested address")
    except (KeyError, ValueError, TypeError) as exc:
        raise EnrichmentError("RDAP response has an invalid IP network range") from exc
    entities = payload.get("entities", [])
    if not isinstance(entities, list):
        raise EnrichmentError("RDAP entities must be a list")
    now = time.time()
    result = {
        "ip": str(address), "source": source_url, "status": "ok",
        "fetched_at": now, "expires_at": now + cache_ttl, "cache_hit": False,
        "network": {key: payload.get(key) for key in (
            "handle", "name", "startAddress", "endAddress", "ipVersion",
            "country", "type", "parentHandle",
        )},
        "entities": entities, "abuse_contacts": _abuse_contacts(entities), "raw": payload,
    }
    if cache is not None:
        cache.put("rdap:ip", initial_url, result, expires_at=result["expires_at"])
    return result


def _reject_feed_error(prefix, content_type):
    text = prefix.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if ("text/html" in content_type.lower()
            or "application/json" in content_type.lower()
            or re.match(rb'\{\s*"(?:error|errors)"\s*:', text)
            or re.search(rb"<(?:!doctype\s+html|html|body|head)(?:\s|>)", text)
            or re.match(rb"(?:error\b|too many requests\b|service unavailable\b|access denied\b)", text)):
        raise EnrichmentError("ISC feed response is an HTML or error page")


def download_isc_feed(feed, destination, *, email, session=None, cache=None,
                      timeout=DEFAULT_TIMEOUT, max_attempts=3,
                      max_bytes=256 * 1024 * 1024):
    """Atomically download a supported ISC feed, at most once/hour per path.

    Feed text is preserved verbatim; this does not assume or parse a feed
    schema. Download timestamps are scoped to both the feed and destination.
    A failed request or incomplete body leaves the last good file intact.
    """
    _validate_request_options(email, timeout, max_attempts)
    if feed not in ISC_FEEDS:
        raise ValueError(f"feed must be one of: {', '.join(ISC_FEEDS)}")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    destination = Path(destination).expanduser().resolve()
    key = f"{feed}:{destination}"
    metadata = cache.get("isc:feed", key) if cache is not None else None
    if metadata is None:
        with _STATE_LOCK:
            metadata = _FEED_DOWNLOADS.get(key)
    if metadata and time.time() - metadata["fetched_at"] < 3600 and destination.is_file():
        stat = destination.stat()
        if metadata.get("size") == stat.st_size and metadata.get("mtime_ns") == stat.st_mtime_ns:
            return dict(metadata, status="cached")
    source_url = ISC_FEEDS[feed]
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with request_get(
            source_url, email=email, session=session, cache=cache, timeout=timeout,
            max_attempts=max_attempts, stream=True, headers={"Accept": "text/plain"},
        ) as response:
            declared = _response_length(response)
            if declared is not None and declared > max_bytes:
                raise EnrichmentError(f"Feed exceeds {max_bytes} byte limit")
            prefix = bytearray()
            size = 0
            with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{destination.name}.",
                                             suffix=".tmp", dir=destination.parent,
                                             delete=False) as output:
                temporary_path = Path(output.name)
                try:
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        size += len(chunk)
                        if size > max_bytes:
                            raise EnrichmentError(f"Feed exceeds {max_bytes} byte limit")
                        if len(prefix) < 16384:
                            prefix.extend(chunk[:16384 - len(prefix)])
                            _reject_feed_error(prefix, response.headers.get("Content-Type", ""))
                        output.write(chunk)
                except requests.RequestException as exc:
                    raise EnrichmentError("ISC feed download was interrupted") from exc
                if size == 0:
                    raise EnrichmentError("ISC feed is empty")
                if (declared is not None and not response.headers.get("Content-Encoding")
                        and size != declared):
                    raise EnrichmentError("ISC feed body does not match Content-Length")
                output.flush()
                os.fsync(output.fileno())
            if destination.exists():
                os.chmod(temporary_path, destination.stat().st_mode & 0o777)
            os.replace(temporary_path, destination)
            temporary_path = None
        stat = destination.stat()
        metadata = {
            "feed": feed, "source": source_url, "path": str(destination),
            "fetched_at": time.time(), "status": "downloaded", "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }
        with _STATE_LOCK:
            _FEED_DOWNLOADS[key] = metadata
        if cache is not None:
            cache.put("isc:feed", key, metadata, ttl=3600)
        return dict(metadata)
    except OSError as exc:
        raise EnrichmentError(f"Could not save ISC feed to {destination}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
