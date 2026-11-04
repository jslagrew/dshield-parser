"""Bounded PTR lookups with DNS TTLs and optional persistent caching."""

import copy
import hashlib
import ipaddress
import json
import math
import time
import threading
import uuid
import weakref
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import dns.exception
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.resolver


_CACHE_NAMESPACE = "reverse-dns-v1"
_CUSTOM_IDENTITIES = weakref.WeakKeyDictionary()
_IDENTITY_LOCK = threading.Lock()


def _number(value, name, *, allow_zero=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite number")
    if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
        qualifier = "nonnegative" if allow_zero else "positive"
        raise ValueError(f"{name} must be finite and {qualifier}")


def _address(value):
    if not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise TypeError("ip must be an IPv4 or IPv6 address")
    address = ipaddress.ip_address(value)
    if getattr(address, "scope_id", None) is not None:
        raise ValueError("scoped IPv6 addresses cannot be used for PTR lookups")
    return str(address)


def _configured_resolver(resolver, timeout, lifetime):
    if resolver is None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = lifetime
        resolver.cache = dns.resolver.LRUCache()
    elif isinstance(resolver, dns.resolver.Resolver):
        # Configuration is not thread-safe. A shallow copy owns these timing
        # settings while safely sharing the supplied resolver's TTL-aware cache.
        resolver = copy.copy(resolver)
        resolver.timeout = timeout
        resolver.lifetime = lifetime
    return resolver


def _resolver_identity(resolver):
    """Separate DNS views and transports without persisting nameserver details."""
    if isinstance(resolver, dns.resolver.Resolver):
        configuration = {
            "class": f"{type(resolver).__module__}.{type(resolver).__qualname__}",
            "nameservers": [
                {
                    "endpoint": str(server),
                    "hostname": getattr(server, "hostname", None),
                    "bootstrap_address": getattr(server, "bootstrap_address", None),
                }
                for server in resolver.nameservers
            ],
            "port": resolver.port,
            "nameserver_ports": resolver.nameserver_ports,
            "edns": resolver.edns,
            "ednsflags": resolver.ednsflags,
            "ednsoptions": [str(option) for option in (resolver.ednsoptions or ())],
            "flags": resolver.flags,
            "keyname": str(resolver.keyname),
            "keyalgorithm": str(resolver.keyalgorithm),
        }
        identity = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
    else:
        # Custom resolvers can expose a stable identity for cross-run caching.
        # Without it, scope cache entries to that instance instead of accidentally
        # sharing responses between unrelated private DNS implementations.
        identity = getattr(resolver, "enrichment_cache_identity", None)
        if identity is None:
            with _IDENTITY_LOCK:
                try:
                    identity = _CUSTOM_IDENTITIES.get(resolver)
                    if identity is None:
                        identity = uuid.uuid4().hex
                        _CUSTOM_IDENTITIES[resolver] = identity
                except TypeError:
                    # An unhashable/non-weak-referenceable custom resolver must
                    # supply an identity to opt into reusable persistent entries.
                    identity = uuid.uuid4().hex
        elif not isinstance(identity, str) or not identity:
            raise ValueError("enrichment_cache_identity must be a nonempty string")
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _negative_ttl(response):
    """RFC 2308 negative TTL, capped by any alias TTL in this response."""
    if response is None or response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return None
    ttls = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.SOA:
            ttls.extend(min(rrset.ttl, record.minimum) for record in rrset)
    if not ttls:
        return None
    ttls.extend(
        rrset.ttl for rrset in response.answer
        if rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME)
    )
    return max(0, min(ttls))


def _negative_expiration(responses, fetched_at, answer=None):
    ttls = [_negative_ttl(response) for response in responses]
    # A bare negative response has no defensible persistent TTL. In particular,
    # dnspython's missing-SOA fallback must not become a multi-year cache entry.
    if not ttls or any(ttl is None for ttl in ttls):
        return fetched_at
    expires_at = fetched_at + min(ttls)
    if answer is not None:
        # Cached Answers retain their original expiration. Do not renew them
        # for another full TTL simply because the record was read from memory.
        expiration = getattr(answer, "expiration", None)
        if isinstance(expiration, (int, float)) and math.isfinite(expiration):
            expires_at = min(expires_at, expiration)
    return expires_at


def _discard_unbounded_negative(resolver, response, rdtype):
    # dnspython can retain a negative answer with no SOA for its sentinel maximum
    # TTL. Do not let that in-memory fallback bypass our persistent-cache rule.
    if (isinstance(resolver, dns.resolver.Resolver) and resolver.cache is not None
            and response is not None and response.question):
        question = response.question[0]
        resolver.cache.flush((question.name, rdtype, question.rdclass))


def _lookup(ip, resolver, identity, cache, lifetime, failure_ttl):
    key = f"{identity}:{ip}"
    if cache is not None:
        cached = cache.get(_CACHE_NAMESPACE, key)
        if cached is not None:
            cached["cache_hit"] = True
            return cached

    ptr_names = []
    error = None
    try:
        answer = resolver.resolve_address(
            ip, lifetime=lifetime, raise_on_no_answer=False
        )
        fetched_at = time.time()
        ptr_names = list(dict.fromkeys(str(record.target).rstrip(".") for record in answer))
        if ptr_names:
            status = "ok"
            expiration = getattr(answer, "expiration", fetched_at)
            expires_at = (
                float(expiration)
                if isinstance(expiration, (int, float)) and math.isfinite(expiration)
                else fetched_at
            )
        else:
            status = "no_ptr"
            response = getattr(answer, "response", None)
            expires_at = _negative_expiration([response], fetched_at, answer)
            if _negative_ttl(response) is None:
                _discard_unbounded_negative(resolver, response, dns.rdatatype.PTR)
    except dns.resolver.NXDOMAIN as exc:
        fetched_at = time.time()
        status = "nxdomain"
        # Non-parametrized NXDOMAIN exceptions have no authoritative TTL.
        responses = exc.kwargs.get("responses", {})
        expirations = []
        for qname, response in responses.items():
            cached_answer = None
            if isinstance(resolver, dns.resolver.Resolver) and resolver.cache is not None:
                cached_answer = resolver.cache.get(
                    (qname, dns.rdatatype.ANY, dns.rdataclass.IN)
                )
            expirations.append(_negative_expiration(
                [response], fetched_at, cached_answer
            ))
            if _negative_ttl(response) is None:
                _discard_unbounded_negative(resolver, response, dns.rdatatype.ANY)
        expires_at = min(expirations) if expirations else fetched_at
    except dns.resolver.NoAnswer as exc:
        fetched_at = time.time()
        status = "no_ptr"
        response = exc.kwargs.get("response")
        expires_at = _negative_expiration([response], fetched_at)
        if _negative_ttl(response) is None:
            _discard_unbounded_negative(resolver, response, dns.rdatatype.PTR)
    except dns.exception.Timeout as exc:
        fetched_at = time.time()
        status = "timeout"
        error = str(exc)
        expires_at = fetched_at + failure_ttl
    except (dns.resolver.NoNameservers, dns.resolver.NoResolverConfiguration, OSError) as exc:
        fetched_at = time.time()
        status = "resolver_error"
        error = str(exc)
        expires_at = fetched_at + failure_ttl

    result = {
        "ip": ip,
        "source": "dns",
        "status": status,
        "ptr_names": ptr_names,
        "reverse_dns": ptr_names[0] if ptr_names else "",
        "fetched_at": float(fetched_at),
        "expires_at": float(expires_at),
        "cache_hit": False,
    }
    if error is not None:
        result["error"] = error
    if cache is not None and expires_at > fetched_at:
        cache.put(_CACHE_NAMESPACE, key, result, expires_at=expires_at)
    return result


def get_reverse_dns_info(
    ip, *, resolver=None, cache=None, timeout=1.0, lifetime=3.0, failure_ttl=60
):
    """Resolve one IP's PTR records with a real total DNS lookup deadline.

    Pass an ``EnrichmentCache`` to persist results across runs. Positive and
    authoritative negative answers retain DNS TTLs. Timeouts and resolver
    failures use a separate ``failure_ttl`` cooldown (zero disables it), and
    remain distinguishable from confirmed absence of PTR records.

    A supplied dnspython Resolver is copied before applying timing settings; its
    shared cache and nameservers are retained. A custom resolver must implement
    ``resolve_address(ip, lifetime=..., raise_on_no_answer=False)`` and honor the
    lifetime itself. It may supply a stable ``enrichment_cache_identity`` string
    to reuse persistent responses across instances. Configure resolvers before
    sharing them between workers. Programmer errors propagate to the caller.
    """
    _number(timeout, "timeout")
    _number(lifetime, "lifetime")
    _number(failure_ttl, "failure_ttl", allow_zero=True)
    ip = _address(ip)
    resolver = _configured_resolver(resolver, timeout, lifetime)
    return _lookup(ip, resolver, _resolver_identity(resolver), cache, lifetime, failure_ttl)


def iter_reverse_dns(
    ips, *, max_workers=16, resolver=None, cache=None,
    timeout=1.0, lifetime=3.0, failure_ttl=60
):
    """Yield completed PTR results with at most ``max_workers`` jobs in flight.

    Inputs are canonicalized and deduplicated lazily, including IPv6 spellings.
    Completion order is unspecified. Each result is saved before it is yielded,
    so restarting a partially completed batch reuses fresh persistent entries.
    The seen-address set grows with distinct inputs; queued futures do not.
    Closing the generator cancels unstarted work and waits for active lookups,
    whose resolver lifetime bounds their DNS work.
    """
    if isinstance(max_workers, bool) or not isinstance(max_workers, int):
        raise TypeError("max_workers must be a positive integer")
    if max_workers < 1:
        raise ValueError("max_workers must be a positive integer")
    _number(timeout, "timeout")
    _number(lifetime, "lifetime")
    _number(failure_ttl, "failure_ttl", allow_zero=True)
    resolver = _configured_resolver(resolver, timeout, lifetime)
    identity = _resolver_identity(resolver)
    inputs = iter(ips)
    seen = set()
    exhausted = False
    executor = ThreadPoolExecutor(max_workers=max_workers)
    pending = set()
    try:
        while pending or not exhausted:
            while len(pending) < max_workers and not exhausted:
                try:
                    ip = _address(next(inputs))
                except StopIteration:
                    exhausted = True
                    break
                if ip in seen:
                    continue
                seen.add(ip)
                pending.add(executor.submit(
                    _lookup, ip, resolver, identity, cache, lifetime, failure_ttl
                ))
            if pending:
                completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    yield future.result()
    finally:
        # Do not leave queued DNS work alive if a caller stops reading results.
        executor.shutdown(wait=True, cancel_futures=True)
