"""Offline contract tests for HTTP enrichment and atomic feed downloads."""
import copy
from datetime import datetime, timezone
from email.utils import format_datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import requests
from dshield_parser.utils import _enrichment_http as enrichment

CONTACT = "maintainer@example.org"
IP = "8.8.8.8"
BOOTSTRAP = {"0.0.0.0/0": "https://rdap.example.net/registry/"}


class MemoryCache:
    def __init__(self):
        self.records = {}

    def get(self, namespace, key):
        entry = self.records.get((namespace, key))
        if entry and entry[0] > enrichment.time.time():
            return copy.deepcopy(entry[1])
        return None

    def put(self, namespace, key, value, *, ttl=None, expires_at=None):
        expiry = expires_at if expires_at is not None else enrichment.time.time() + ttl
        self.records[(namespace, key)] = (expiry, copy.deepcopy(value))


class Response:
    def __init__(self, status=200, body=b"", headers=None, chunks=None):
        self.status_code = status
        self.body = body.encode() if isinstance(body, str) else body
        self.headers = headers or {}
        self.chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size):
        if self.chunks is not None:
            for chunk in self.chunks:
                if isinstance(chunk, Exception):
                    raise chunk
                yield chunk
        else:
            for start in range(0, len(self.body), chunk_size):
                yield self.body[start:start + chunk_size]

    def close(self):
        self.closed = True


class Session:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError(f"Unexpected HTTP request: {url}")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True


def rdap_payload(**updates):
    payload = {
        "objectClassName": "ip network", "handle": "NET-8-8-8",
        "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
        "ipVersion": "v4", "name": "EXAMPLE-NET", "country": "US",
        "entities": [{"handle": "ABUSE", "roles": ["abuse"],
                      "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.net"]]]}],
    }
    payload.update(updates)
    return payload


def json_response(payload, **kwargs):
    return Response(body=json.dumps(payload), **kwargs)


class HTTPEnrichmentTests(unittest.TestCase):
    def setUp(self):
        enrichment._COOLDOWNS.clear()
        enrichment._BOOTSTRAPS.clear()
        enrichment._FEED_DOWNLOADS.clear()
        self.sleeper = patch.object(enrichment.time, "sleep")
        self.sleep = self.sleeper.start()
        self.addCleanup(self.sleeper.stop)

    def test_retry_after_numeric_and_new_ip_share_origin_cooldown(self):
        response = Response(429, "arbitrary error", {"Retry-After": "300"})
        session = Session(response)
        cache = MemoryCache()
        with self.assertRaises(enrichment.EnrichmentRateLimitError) as error:
            enrichment.isc_ipinfo(IP, CONTACT, session=session, cache=cache)
        self.assertAlmostEqual(error.exception.retry_after, 300, delta=1)
        self.assertGreater(error.exception.retry_at, enrichment.time.time())
        with self.assertRaises(enrichment.EnrichmentRateLimitError):
            enrichment.isc_ipinfo("1.1.1.1", CONTACT, session=session)
        self.assertEqual(len(session.calls), 1)
        self.assertTrue(response.closed)
        self.sleep.assert_not_called()
        enrichment._COOLDOWNS.clear()
        with self.assertRaises(enrichment.EnrichmentRateLimitError):
            enrichment.isc_ipinfo("9.9.9.9", CONTACT, session=session, cache=cache)
        self.assertEqual(len(session.calls), 1)

    def test_retry_after_http_date_takes_precedence_over_html(self):
        with patch.object(enrichment.time, "time", return_value=1_700_000_000):
            date = format_datetime(datetime.fromtimestamp(1_700_000_120, timezone.utc), usegmt=True)
            session = Session(Response(429, "Try again after 900 seconds", {"Retry-After": date}))
            with self.assertRaises(enrichment.EnrichmentRateLimitError) as error:
                enrichment.isc_ipinfo(IP, CONTACT, session=session)
            self.assertEqual(error.exception.retry_after, 120)
            self.assertEqual(error.exception.retry_at, 1_700_000_120)

    def test_retry_after_html_and_unknown_body_fallback(self):
        for body, headers, expected in [
            ("<html><body>Too Many Requests. Try again after 600 seconds. bots cranky</body></html>", {}, 600),
            ("unexpected provider message", {}, 300),
            ("unexpected provider message", {"Retry-After": "not a date"}, 300),
        ]:
            with self.subTest(body=body):
                enrichment._COOLDOWNS.clear()
                with self.assertRaises(enrichment.EnrichmentRateLimitError) as error:
                    enrichment.isc_ipinfo(IP, CONTACT, session=Session(Response(429, body, headers)))
                self.assertAlmostEqual(error.exception.retry_after, expected, delta=1)
        self.sleep.assert_not_called()

    def test_503_retry_after_defers_without_short_retry(self):
        session = Session(Response(503, "busy", {"Retry-After": "30"}))
        with self.assertRaises(enrichment.EnrichmentRateLimitError):
            enrichment.isc_ipinfo(IP, CONTACT, session=session)
        self.assertEqual(len(session.calls), 1)
        self.sleep.assert_not_called()

    def test_permanent_failure_is_terminal(self):
        session = Session(Response(403, "forbidden"))
        with self.assertRaises(enrichment.EnrichmentHTTPError) as error:
            enrichment.isc_ipinfo(IP, CONTACT, session=session)
        self.assertEqual(error.exception.status_code, 403)
        self.assertEqual(len(session.calls), 1)
        self.sleep.assert_not_called()

    def test_transient_retries_have_finite_attempt_count(self):
        session = Session(Response(500), requests.Timeout("timed out"), Response(502))
        with self.assertRaises(enrichment.EnrichmentHTTPError):
            enrichment.isc_ipinfo(IP, CONTACT, session=session, max_attempts=3)
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(self.sleep.call_count, 2)
        self.assertTrue(all(call.args[0] <= 4 for call in self.sleep.call_args_list))

    def test_connection_failure_raises_expected_error(self):
        session = Session(requests.ConnectionError("offline"), requests.Timeout("late"))
        with self.assertRaises(enrichment.EnrichmentError) as error:
            enrichment.isc_ipinfo(IP, CONTACT, session=session, max_attempts=2)
        self.assertIsInstance(error.exception.__cause__, requests.Timeout)
        self.assertEqual(len(session.calls), 2)

    def test_explicit_timeout_contact_and_missing_optional_isc_fields(self):
        response = Response(body="<ip><number>8.8.8.8</number><as>15169</as></ip>")
        session = Session(response)
        result = enrichment.isc_ipinfo(IP, CONTACT, session=session, timeout=(1, 2))
        self.assertEqual(result[IP]["number"], IP)
        self.assertEqual(result[IP]["as"], "15169")
        self.assertIsNone(result[IP]["asabusecontact"])
        self.assertIsNone(result[IP]["weblog_avguseragents"])
        self.assertIsNone(result[IP]["lastseen"])
        self.assertEqual(session.calls[0][1]["timeout"], (1, 2))
        self.assertIn(CONTACT, session.calls[0][1]["headers"]["User-Agent"])
        self.assertFalse(session.calls[0][1]["allow_redirects"])
        self.assertTrue(response.closed)
        self.assertFalse(session.closed)

    def test_isc_weblogs_and_exact_ip_cache(self):
        session = Session(Response(body="""<ip><number>8.8.8.8</number><weblogs>
            <count>3</count><avguser_agents>2</avguser_agents><lastseen>2026-01-01</lastseen>
            </weblogs></ip>"""))
        cache = MemoryCache()
        first = enrichment.isc_ipinfo(IP, CONTACT, session=session, cache=cache)
        second = enrichment.isc_ipinfo(IP, CONTACT, session=session, cache=cache)
        self.assertEqual(first[IP]["number"], second[IP]["number"])
        self.assertFalse(first[IP]["cache_hit"])
        self.assertTrue(second[IP]["cache_hit"])
        self.assertEqual(first[IP]["fetched_at"], second[IP]["fetched_at"])
        self.assertEqual(first[IP]["weblog_avguseragents"], "2")
        self.assertEqual(first[IP]["lastseen"], "2026-01-01")
        self.assertEqual(len(session.calls), 1)

    def test_invalid_xml_and_html_success_are_not_cached(self):
        for body in ("", "broken", "<html><body>error</body></html>", "<ip/>",
                     "<ip><number>1.1.1.1</number></ip>", "<ip><number>wrong</number></ip>"):
            with self.subTest(body=body):
                cache = MemoryCache()
                with self.assertRaises(enrichment.EnrichmentError):
                    enrichment.isc_ipinfo(IP, CONTACT, session=Session(Response(body=body)), cache=cache)
                self.assertFalse(cache.records)

    def test_session_created_by_helper_is_closed(self):
        session = Session(Response(body="<ip><number>8.8.8.8</number></ip>"))
        with patch.object(enrichment.requests, "Session", return_value=session):
            enrichment.isc_ipinfo(IP, CONTACT)
        self.assertTrue(session.closed)

    def test_unbounded_timeout_attempts_and_invalid_contact_rejected(self):
        for options in ({"timeout": None}, {"timeout": 0}, {"timeout": (1, None)},
                        {"max_attempts": 0}, {"max_attempts": 11}, {"max_attempts": True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                enrichment.isc_ipinfo(IP, CONTACT, session=Session(), **options)
        with self.assertRaises(ValueError):
            enrichment.isc_ipinfo(IP, "bad\r\nheader", session=Session())

    def test_redirect_downgrade_and_loops_are_rejected(self):
        for destination in ("http://rdap.example.net/ip/8.8.8.8", "https://user:password@rdap.example.net/ip/8.8.8.8",
                            "https://127.0.0.1/ip/8.8.8.8", "https://isc.sans.edu/api/ip/8.8.8.8"):
            with self.subTest(destination=destination):
                session = Session(Response(302, headers={"Location": destination}))
                with self.assertRaises(enrichment.EnrichmentError):
                    enrichment.isc_ipinfo(IP, CONTACT, session=session)
                self.assertEqual(len(session.calls), 1)

    def test_isc_empty_fields_are_none_and_number_is_canonical(self):
        session = Session(Response(body="<ip><number> 8.8.8.8 </number><asname> </asname><comment /></ip>"))
        result = enrichment.isc_ipinfo(IP, CONTACT, session=session)
        self.assertEqual(result[IP]["number"], IP)
        self.assertIsNone(result[IP]["comment"])
        self.assertIsNone(result[IP]["asname"])
        self.assertEqual(result[IP]["expires_at"] - result[IP]["fetched_at"], 86400)

    def test_http_ip_inputs_reject_integer_boolean_and_scoped_ipv6(self):
        for value in (True, 1234, "fe80::1%eth0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    enrichment.isc_ipinfo(value, CONTACT, session=Session())
                with self.assertRaises(ValueError):
                    enrichment.get_rdap_data(value, email=CONTACT, bootstrap=BOOTSTRAP, session=Session())

    def test_cross_origin_redirect_drops_session_and_explicit_credentials(self):
        session = requests.Session()
        session.auth = ("user", "password")
        session.headers["Authorization"] = "Bearer session-secret"
        session.headers["X-API-Key"] = "session-key"
        session.cookies.set("session", "secret")
        observed = []

        def send(prepared, **kwargs):
            observed.append(prepared)
            response = requests.Response()
            response.status_code = 302 if len(observed) == 1 else 200
            response._content = b"<ip><number>8.8.8.8</number></ip>"
            response._content_consumed = True
            response.url = prepared.url
            if response.status_code == 302:
                response.headers["Location"] = "https://other.example.net/ip/8.8.8.8"
            return response

        with patch.object(session, "send", side_effect=send):
            with enrichment.request_get(
                "https://first.example.net/ip/8.8.8.8", email=CONTACT, session=session,
                headers={"X-Other-Token": "explicit-secret"},
            ) as response:
                self.assertEqual(response.status_code, 200)
        self.assertIn("Authorization", observed[0].headers)
        self.assertIn("Cookie", observed[0].headers)
        for name in ("Authorization", "Cookie", "X-API-Key", "X-Other-Token"):
            self.assertNotIn(name, observed[1].headers)
        self.assertIn(CONTACT, observed[1].headers["User-Agent"])
        self.assertEqual(session.auth, ("user", "password"))
        self.assertEqual(session.headers["X-API-Key"], "session-key")
        session.close()

    def test_rdap_referrals_strip_credentials_after_initial_registry(self):
        session = requests.Session()
        session.auth = ("user", "password")
        observed = []

        def send(prepared, **kwargs):
            observed.append(prepared)
            payload = ({"links": [{"rel": "related", "href": "https://other.example.net/ip/8.8.8.8"}]}
                       if len(observed) == 1 else rdap_payload())
            response = requests.Response()
            response.status_code = 200
            response._content = json.dumps(payload).encode()
            response._content_consumed = True
            response.url = prepared.url
            return response

        with patch.object(session, "send", side_effect=send):
            enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session)
        self.assertIn("Authorization", observed[0].headers)
        self.assertNotIn("Authorization", observed[1].headers)
        session.close()

    def test_rdap_longest_prefix_route_and_registry_semantics(self):
        bootstrap = {"services": [
            [["0.0.0.0/0"], ["https://default.example.net/"]],
            [["8.0.0.0/8"], ["http://legacy.example.net/", "https://specific.example.net/rdap/"]],
        ]}
        payload = rdap_payload()
        session = Session(json_response(payload))
        result = enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=bootstrap, session=session)
        self.assertEqual(session.calls[0][0], "https://specific.example.net/rdap/ip/8.8.8.8")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["network"]["country"], "US")
        self.assertEqual(result["abuse_contacts"], ["abuse@example.net"])
        self.assertEqual(result["raw"], payload)
        self.assertNotIn("asn", result)

    def test_rdap_exact_ip_cache_does_not_reuse_registry_parent_network(self):
        session = Session(json_response(rdap_payload()), json_response(rdap_payload()))
        cache = MemoryCache()
        first = enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session, cache=cache)
        cached = enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session, cache=cache)
        other = enrichment.get_rdap_data("8.8.8.9", email=CONTACT, bootstrap=BOOTSTRAP, session=session, cache=cache)
        self.assertFalse(first["cache_hit"])
        self.assertTrue(cached["cache_hit"])
        self.assertFalse(other["cache_hit"])
        self.assertEqual(len(session.calls), 2)

    def test_rdap_iana_bootstrap_and_ipv6_route_are_cached(self):
        bootstrap = {"services": [[["2000::/3"], ["https://v6.example.net/"]]]}
        ipv6 = "2606:4700:4700::1111"
        payload = rdap_payload(startAddress="2606:4700::", endAddress="2606:4700:ffff:ffff:ffff:ffff:ffff:ffff", ipVersion="v6")
        session = Session(json_response(bootstrap), json_response(payload))
        cache = MemoryCache()
        for unused in range(2):
            result = enrichment.get_rdap_data(ipv6, email=CONTACT, session=session, cache=cache)
        self.assertEqual(session.calls[0][0], "https://data.iana.org/rdap/ipv6.json")
        self.assertEqual(session.calls[1][0], f"https://v6.example.net/ip/{ipv6}")
        self.assertEqual(len(session.calls), 2)
        self.assertTrue(result["cache_hit"])

    def test_bootstrap_process_cache_avoids_repeated_iana_requests(self):
        bootstrap = {"services": [[["0.0.0.0/0"], ["https://rdap.example.net/"]]]}
        session = Session(json_response(bootstrap), json_response(rdap_payload()), json_response(rdap_payload()))
        enrichment.get_rdap_data(IP, email=CONTACT, session=session)
        enrichment.get_rdap_data("8.8.8.9", email=CONTACT, session=session)
        self.assertEqual(sum("data.iana.org" in url for url, unused in session.calls), 1)
        self.assertEqual(len(session.calls), 3)

    def test_rdap_referral_limit_is_finite(self):
        session = Session(*[
            json_response({"links": [{"rel": "related", "href": f"https://hop{index}.example.net/ip/8.8.8.8"}]})
            for index in range(6)
        ])
        with self.assertRaises(enrichment.EnrichmentError):
            enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session)
        self.assertEqual(len(session.calls), 6)

    def test_rdap_safe_redirect_and_exact_ip_referral_only(self):
        referral = {"links": [
            {"rel": "related", "type": "application/rdap+json", "href": "https://next.example.net/entity/ABUSE"},
            {"rel": "related", "type": "application/rdap+json", "href": "https://next.example.net/ip/8.8.8.8"},
        ]}
        session = Session(Response(302, headers={"Location": "https://redirect.example.net/ip/8.8.8.8"}),
                          json_response(referral), json_response(rdap_payload()))
        result = enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session)
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(result["source"], "https://next.example.net/ip/8.8.8.8")
        self.assertFalse(any("entity/" in url for url, unused in session.calls))

    def test_rdap_referral_loop_and_wrong_network_fail(self):
        session = Session(json_response({"links": [{"rel": "related", "href": "https://next.example.net/ip/8.8.8.8"}]}),
                          json_response({"links": [{"rel": "related", "href": "https://rdap.example.net/registry/ip/8.8.8.8"}]}))
        with self.assertRaises(enrichment.EnrichmentError):
            enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session)
        with self.assertRaises(enrichment.EnrichmentError):
            enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP,
                                     session=Session(json_response(rdap_payload(startAddress="1.1.1.0", endAddress="1.1.1.255"))))

    def test_rdap_not_found_and_non_global_are_explicit(self):
        session = Session(Response(404))
        result = enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=BOOTSTRAP, session=session)
        self.assertEqual(result["status"], "not_found")
        self.assertLessEqual(result["expires_at"] - result["fetched_at"], 300)
        result = enrichment.get_rdap_data("192.168.1.1", email=CONTACT, session=Session())
        self.assertEqual(result["status"], "not_global")

    def test_bootstrap_can_be_loaded_from_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            path.write_text(json.dumps(BOOTSTRAP), encoding="utf-8")
            result = enrichment.get_rdap_data(IP, email=CONTACT, bootstrap=path,
                                             session=Session(json_response(rdap_payload())))
            self.assertEqual(result["status"], "ok")

    def test_feed_atomic_download_and_independent_destination_cache(self):
        data = b"# provider-defined columns\n8.8.8.8\t1\t2\n"
        session = Session(Response(body=data), Response(body=data))
        cache = MemoryCache()
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.txt"
            second = Path(directory) / "second.txt"
            result = enrichment.download_isc_feed("daily_sources", first, email=CONTACT, session=session, cache=cache)
            reused = enrichment.download_isc_feed("daily_sources", first, email=CONTACT, session=session, cache=cache)
            distinct = enrichment.download_isc_feed("daily_sources", second, email=CONTACT, session=session, cache=cache)
            self.assertEqual(result["status"], "downloaded")
            self.assertEqual(reused["status"], "cached")
            self.assertEqual(distinct["status"], "downloaded")
            self.assertEqual(first.read_bytes(), data)
            self.assertEqual(second.read_bytes(), data)
            self.assertEqual(len(session.calls), 2)

    def test_feed_failure_preserves_last_good_file(self):
        for response in (
            Response(chunks=[b"# new data\n", requests.exceptions.ChunkedEncodingError("truncated")]),
            Response(body="<html><body>server unavailable</body></html>"),
            Response(body="error: unavailable"), Response(body='{"error": "unavailable"}'),
            Response(body=b""), Response(body=b"x" * 100),
            Response(body=b"short feed", headers={"Content-Length": "40"}),
        ):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory) / "feed.txt"
                destination.write_bytes(b"last good feed")
                with self.assertRaises(enrichment.EnrichmentError):
                    enrichment.download_isc_feed("daily_sources", destination, email=CONTACT,
                                                 session=Session(response), max_bytes=50)
                self.assertEqual(destination.read_bytes(), b"last good feed")
                self.assertEqual(list(Path(directory).iterdir()), [destination])

    def test_feed_reloads_if_cached_destination_was_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "feed.txt"
            session = Session(Response(body=b"original"), Response(body=b"fresh"))
            enrichment.download_isc_feed("threatintel", destination, email=CONTACT, session=session)
            destination.write_bytes(b"edited on disk")
            result = enrichment.download_isc_feed("threatintel", destination, email=CONTACT, session=session)
            self.assertEqual(result["status"], "downloaded")
            self.assertEqual(destination.read_bytes(), b"fresh")
            self.assertEqual(len(session.calls), 2)

    def test_feed_name_is_allowlisted(self):
        with self.assertRaises(ValueError):
            enrichment.download_isc_feed("https://other.example.net/feed", "unused.txt", email=CONTACT, session=Session())


if __name__ == "__main__":
    unittest.main()
