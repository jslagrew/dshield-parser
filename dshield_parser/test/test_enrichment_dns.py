"""DNS behavior tests: fixtures only, with no live DNS or Internet requests."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import dns.exception
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.rcode
import dns.resolver
import dns.reversename
import dns.rrset

from dshield_parser.utils._enrichment_cache import EnrichmentCache
from dshield_parser.utils._enrichment_dns import get_reverse_dns_info, iter_reverse_dns


IP = "192.0.2.1"


def response_for(ip=IP, names=None, *, nxdomain=False, soa_ttl=120, minimum=60, alias_ttl=None):
    name = dns.reversename.from_address(ip)
    response = dns.message.make_response(dns.message.make_query(name, "PTR"))
    if nxdomain:
        response.set_rcode(dns.rcode.NXDOMAIN)
    if names:
        response.answer.append(dns.rrset.from_text(name, 120, "IN", "PTR", *names))
    elif soa_ttl is not None:
        response.authority.append(dns.rrset.from_text(
            "2.0.192.in-addr.arpa.", soa_ttl, "IN", "SOA",
            f"ns.example. hostmaster.example. 1 3600 600 86400 {minimum}",
        ))
    if alias_ttl is not None:
        response.answer.insert(0, dns.rrset.from_text(
            name, alias_ttl, "IN", "CNAME", "alias.example."
        ))
    response.index = None
    return response


def answer_for(ip=IP, names=None, **kwargs):
    response = response_for(ip, names, **kwargs)
    return dns.resolver.Answer(
        response.question[0].name, dns.rdatatype.PTR, dns.rdataclass.IN, response
    )


class FakeResolver:
    def __init__(self, result=None, error=None, identity="test-view"):
        self.result = result
        self.error = error
        self.calls = []
        self.enrichment_cache_identity = identity

    def resolve_address(self, ip, **kwargs):
        self.calls.append((ip, kwargs))
        if self.error is not None:
            raise self.error
        return self.result


class ReverseDnsTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.clock = patch("dshield_parser.utils._enrichment_dns.time.time", lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.cache = EnrichmentCache(":memory:", clock=lambda: self.now)
        self.addCleanup(self.cache.close)

    def test_positive_names_preserve_expiration_and_cache_copies(self):
        answer = answer_for(names=["host.example.", "other.example."])
        answer.expiration = 1015.0
        resolver = FakeResolver(answer)
        result = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache, lifetime=2)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["reverse_dns"], "host.example")
        self.assertEqual(result["ptr_names"], ["host.example", "other.example"])
        self.assertEqual(result["expires_at"], 1015)
        self.assertEqual(result["fetched_at"], 1000)
        self.assertFalse(result["cache_hit"])
        self.assertEqual(resolver.calls, [(IP, {"lifetime": 2, "raise_on_no_answer": False})])
        result["ptr_names"].append("mutation")
        self.now = 1005
        cached = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
        self.assertTrue(cached["cache_hit"])
        self.assertEqual(cached["expires_at"], 1015)
        self.assertNotIn("mutation", cached["ptr_names"])
        self.now = 1015
        get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
        self.assertEqual(len(resolver.calls), 2)

    def test_nxdomain_negative_ttl_uses_soa_minimum(self):
        response = response_for(nxdomain=True, soa_ttl=120, minimum=30)
        error = dns.resolver.NXDOMAIN(
            qnames=[response.question[0].name],
            responses={response.question[0].name: response},
        )
        resolver = FakeResolver(error=error)
        result = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
        self.assertEqual(result["status"], "nxdomain")
        self.assertEqual(result["expires_at"], 1030)
        self.assertEqual(result["reverse_dns"], "")
        self.assertEqual(result["ptr_names"], [])
        self.assertTrue(get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)["cache_hit"])

    def test_negative_alias_ttl_caps_soa(self):
        response = response_for(nxdomain=True, alias_ttl=7)
        error = dns.resolver.NXDOMAIN(
            qnames=[response.question[0].name],
            responses={response.question[0].name: response},
        )
        result = get_reverse_dns_info(IP, resolver=FakeResolver(error=error))
        self.assertEqual(result["expires_at"], 1007)

    def test_no_ptr_uses_original_answer_expiration(self):
        answer = answer_for(soa_ttl=45, minimum=60)
        answer.expiration = 1009
        result = get_reverse_dns_info(IP, resolver=FakeResolver(answer), cache=self.cache)
        self.assertEqual(result["status"], "no_ptr")
        self.assertEqual(result["expires_at"], 1009)

    def test_noanswer_exception_keeps_negative_status(self):
        response = response_for(soa_ttl=20)
        result = get_reverse_dns_info(
            IP, resolver=FakeResolver(error=dns.resolver.NoAnswer(response=response))
        )
        self.assertEqual(result["status"], "no_ptr")
        self.assertEqual(result["expires_at"], 1020)

    def test_missing_soa_does_not_persist_negative_answer(self):
        resolvers = [
            FakeResolver(answer_for(soa_ttl=None)),
            FakeResolver(error=dns.resolver.NXDOMAIN()),
            FakeResolver(error=dns.resolver.NoAnswer(response=response_for(soa_ttl=None))),
        ]
        for resolver in resolvers:
            resolver.enrichment_cache_identity = str(id(resolver))
            with self.subTest(resolver=resolver):
                first = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
                second = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
                self.assertEqual(first["expires_at"], first["fetched_at"])
                self.assertFalse(second["cache_hit"])
                self.assertEqual(len(resolver.calls), 2)

    def test_timeout_and_resolver_errors_use_distinct_short_cooldown(self):
        for error, status in [(dns.exception.Timeout(), "timeout"),
                              (dns.resolver.NoNameservers(), "resolver_error"),
                              (OSError("network unavailable"), "resolver_error")]:
            resolver = FakeResolver(error=error, identity=status + str(type(error)))
            with self.subTest(status=status, error=type(error)):
                result = get_reverse_dns_info(
                    IP, resolver=resolver, cache=self.cache, failure_ttl=5
                )
                self.assertEqual(result["status"], status)
                self.assertEqual(result["expires_at"], self.now + 5)
                self.assertTrue(get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)["cache_hit"])
                self.now += 5
                self.assertFalse(get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)["cache_hit"])
        resolver = FakeResolver(error=dns.exception.Timeout(), identity="uncached-failure")
        for _ in range(2):
            self.assertFalse(get_reverse_dns_info(
                IP, resolver=resolver, cache=self.cache, failure_ttl=0
            )["cache_hit"])
        self.assertEqual(len(resolver.calls), 2)

    def test_programmer_errors_propagate_and_are_not_cached(self):
        resolver = FakeResolver(error=TypeError("bad implementation"))
        for _ in range(2):
            with self.assertRaisesRegex(TypeError, "bad implementation"):
                get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
        self.assertEqual(len(resolver.calls), 2)

    def test_resolver_views_cannot_pollute_each_others_cache(self):
        first = FakeResolver(answer_for(names=["public.example."]), identity="public")
        second = FakeResolver(answer_for(names=["private.example."]), identity="private")
        self.assertEqual(get_reverse_dns_info(IP, resolver=first, cache=self.cache)["reverse_dns"], "public.example")
        self.assertEqual(get_reverse_dns_info(IP, resolver=second, cache=self.cache)["reverse_dns"], "private.example")
        self.assertTrue(get_reverse_dns_info(IP, resolver=first, cache=self.cache)["cache_hit"])
        self.assertEqual(len(second.calls), 1)

    def test_custom_resolver_default_identity_is_instance_scoped(self):
        first = FakeResolver(answer_for(names=["one.example."]), identity=None)
        second = FakeResolver(answer_for(names=["two.example."]), identity=None)
        get_reverse_dns_info(IP, resolver=first, cache=self.cache)
        self.assertTrue(get_reverse_dns_info(IP, resolver=first, cache=self.cache)["cache_hit"])
        result = get_reverse_dns_info(IP, resolver=second, cache=self.cache)
        self.assertFalse(result["cache_hit"])
        self.assertEqual(result["reverse_dns"], "two.example")

    def test_real_resolver_cache_nxdomain_keeps_original_expiration(self):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["192.0.2.53"]
        resolver.cache = dns.resolver.LRUCache()
        response = response_for(nxdomain=True)
        qname = response.question[0].name
        answer = dns.resolver.Answer(qname, dns.rdatatype.ANY, dns.rdataclass.IN, response)
        answer.expiration = self.now + 4
        resolver.cache.put((qname, dns.rdatatype.ANY, dns.rdataclass.IN), answer)
        with patch("dns.query.udp", side_effect=AssertionError("network must not be used")):
            result = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
        self.assertEqual(result["status"], "nxdomain")
        self.assertEqual(result["expires_at"], 1004)

    def test_missing_soa_is_not_kept_in_dnspython_memory_cache(self):
        for nxdomain in (False, True):
            with self.subTest(nxdomain=nxdomain):
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = ["192.0.2.53"]
                resolver.cache = dns.resolver.LRUCache()
                response = response_for(nxdomain=nxdomain, soa_ttl=None)
                with patch("dns.query.udp", return_value=response) as query:
                    first = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
                    second = get_reverse_dns_info(IP, resolver=resolver, cache=self.cache)
                self.assertEqual(query.call_count, 2)
                self.assertEqual(first["expires_at"], first["fetched_at"])
                self.assertFalse(second["cache_hit"])

    def test_real_resolver_timings_do_not_mutate_callers_configuration(self):
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ["192.0.2.53"]
        resolver.timeout = 9
        resolver.lifetime = 10
        response = response_for(names=["host.example."])
        observed = []
        def fake_query(request, where, **kwargs):
            observed.append(kwargs["timeout"])
            return response
        with patch("dns.query.udp", side_effect=fake_query):
            result = get_reverse_dns_info(IP, resolver=resolver, timeout=0.2, lifetime=0.4)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(observed, [0.2])
        self.assertEqual(resolver.timeout, 9)
        self.assertEqual(resolver.lifetime, 10)

    def test_real_nameserver_identity_includes_ports(self):
        from dshield_parser.utils._enrichment_dns import _resolver_identity
        first = dns.resolver.Resolver(configure=False)
        first.nameservers = ["192.0.2.53"]
        second = dns.resolver.Resolver(configure=False)
        second.nameservers = ["192.0.2.53"]
        self.assertEqual(_resolver_identity(first), _resolver_identity(second))
        second.port = 5353
        self.assertNotEqual(_resolver_identity(first), _resolver_identity(second))

    def test_invalid_ip_timing_and_concurrency_are_rejected(self):
        resolver = FakeResolver(answer_for(names=["host.example."]))
        for kwargs in ({"timeout": 0}, {"lifetime": -1}, {"failure_ttl": -1},
                       {"timeout": float("inf")}, {"lifetime": float("nan")}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                get_reverse_dns_info(IP, resolver=resolver, **kwargs)
        for ip in ("invalid", "fe80::1%eth0"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                get_reverse_dns_info(ip, resolver=resolver)
        for workers in (0, -1):
            with self.assertRaises(ValueError):
                list(iter_reverse_dns([IP], resolver=resolver, max_workers=workers))
        for workers in (True, 1.5):
            with self.assertRaises(TypeError):
                list(iter_reverse_dns([IP], resolver=resolver, max_workers=workers))
        self.assertEqual(resolver.calls, [])

    def test_batch_dedupes_and_reuses_disk_cache_on_resume(self):
        addresses = [IP, IP, "2001:db8::1", "2001:0db8:0:0:0:0:0:1", "192.0.2.2"]
        resolver = FakeResolver(answer_for(names=["host.example."]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dns.sqlite"
            with EnrichmentCache(path, clock=lambda: self.now) as cache:
                results = iter_reverse_dns(addresses, resolver=resolver, cache=cache, max_workers=1)
                first = next(results)
                results.close()
                self.assertEqual(first["ip"], IP)
                self.assertEqual(len(resolver.calls), 1)
            resumed_resolver = FakeResolver(answer_for(names=["host.example."]))
            with EnrichmentCache(path, clock=lambda: self.now) as cache:
                resumed = list(iter_reverse_dns(addresses, resolver=resumed_resolver, cache=cache, max_workers=2))
            self.assertEqual(len(resumed), 3)
            self.assertEqual(len(resumed_resolver.calls), 2)
            self.assertTrue(next(item for item in resumed if item["ip"] == IP)["cache_hit"])

    def test_batch_does_not_consume_or_queue_all_inputs(self):
        release = threading.Event()
        started = threading.Event()
        lock = threading.Lock()
        consumed = []
        running = []
        answer = answer_for(names=["host.example."])
        class BlockingResolver:
            def resolve_address(self, ip, **kwargs):
                with lock:
                    running.append(ip)
                    if len(running) == 2:
                        started.set()
                if not release.wait(2):
                    raise AssertionError("test failed to release workers")
                return answer
        def inputs():
            for number in range(1, 100):
                consumed.append(number)
                yield f"192.0.2.{number}"
        results = iter_reverse_dns(inputs(), resolver=BlockingResolver(), max_workers=2)
        with ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(next, results)
            try:
                self.assertTrue(started.wait(2))
                self.assertEqual(len(consumed), 2)
                self.assertEqual(len(running), 2)
            finally:
                release.set()
            self.assertEqual(first.result(timeout=2)["status"], "ok")
        results.close()
        self.assertEqual(len(consumed), 2)


if __name__ == "__main__":
    unittest.main()
