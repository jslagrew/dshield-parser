"""IP enrichment helpers.

Local databases are opt-in and never download themselves. DNS/RDAP/ISC helpers
accept an explicit persistent cache; see docs/IP-ENRICHMENT.md for result fields,
provider limits, and migration from 0.1.x.
"""

import json
import logging
import re
import time
import ipaddress
import xml.etree.ElementTree as ET
from functools import lru_cache
from urllib.parse import quote

import pandas as pd
import requests

from ._enrichment_cache import EnrichmentCache
from . import _enrichment_dns as _dns
from . import _enrichment_http as _http
from . import _enrichment_local as _local
from ._enrichment_http import EnrichmentError, EnrichmentRateLimitError


def get_geoip_asn(ip, database_path=None, *, reader=None):
    """Look up ASN/organization in a local GeoLite2 ASN MMDB.

    Install the ``geoip`` extra. Pass an open geoip2 reader for repeated lookups
    to avoid reopening the file. This function never downloads a database.
    """
    return _local.get_geoip_asn(ip, database_path, reader=reader)


def get_geoip_country(ip, database_path=None, *, reader=None):
    """Look up local IP geolocation and registered country as distinct fields."""
    return _local.get_geoip_country(ip, database_path, reader=reader)


def load_iptoasn_database(path):
    """Load/index a downloaded plain or gzip IPtoASN TSV once for reuse."""
    return _local.load_iptoasn_database(path)


def get_iptoasn_data(ip, database):
    """Look up an IP in an object returned by load_iptoasn_database."""
    return _local.get_iptoasn_data(ip, database)


def get_rdap_data(ip, *, email, session=None, cache=None, bootstrap=None,
                  timeout=(3.05, 10), max_attempts=3, cache_ttl=604800):
    """Query authoritative RDAP registration data, optionally caching exact IPs.

    Bootstrap discovery supports IPv4/IPv6. Returned registration fields remain
    separate from ASN attribution; contact entities are not recursively fetched.
    EnrichmentRateLimitError tells callers when deferred work can be retried.
    """
    return _http.get_rdap_data(
        ip, email=email, session=session, cache=cache, bootstrap=bootstrap,
        timeout=timeout, max_attempts=max_attempts, cache_ttl=cache_ttl,
    )


def get_reverse_dns_info(ip, *, resolver=None, cache=None, timeout=1.0,
                         lifetime=3.0, failure_ttl=60):
    """Return PTR names, status and expiration using bounded DNS resolution."""
    return _dns.get_reverse_dns_info(
        ip, resolver=resolver, cache=cache, timeout=timeout,
        lifetime=lifetime, failure_ttl=failure_ttl,
    )


def iter_reverse_dns(ips, *, max_workers=16, resolver=None, cache=None,
                     timeout=1.0, lifetime=3.0, failure_ttl=60):
    """Yield completed unique-IP PTR records with bounded in-flight work.

    Ordering is completion order. Include ``ip`` when joining results back to
    input data; never assume position matches the input iterable.
    """
    yield from _dns.iter_reverse_dns(
        ips, max_workers=max_workers, resolver=resolver, cache=cache,
        timeout=timeout, lifetime=lifetime, failure_ttl=failure_ttl,
    )


def download_isc_feed(feed, destination, *, email, session=None, cache=None,
                      timeout=(3.05, 10), max_attempts=3, **kwargs):
    """Atomically save a supported ISC static feed, retaining the last good file.

    Feed names are ``daily_sources`` and ``threatintel``. The download retains
    the original provider format; it is not a complete WHOIS/ASN database.
    See docs/IP-ENRICHMENT.md for refresh and size-limit options.
    """
    return _http.download_isc_feed(
        feed, destination, email=email, session=session, cache=cache,
        timeout=timeout, max_attempts=max_attempts, **kwargs,
    )


#Enter a valid IP Address (e.g. 1.1.1.1), ASN (e.g. AS1234), or TAG (e.g. NORD_VPN)
@lru_cache
def get_spur_data(log_source, input, session, api):
    try:
        ipaddress.ip_address(input)
        logging.debug(f"IP Address: {input}")
    except Exception as e:
        logging.debug(f"Not an IP Address: {input}")

    session.headers = {'Token': api}
    url = "https://api.spur.us/v2/context/" + input
    while True:
        try:
            response = session.get(url)
        except Exception as e:
            logging.error(f"Exception hit for SPUR query: '{e}'. Pausing for 15 seconds before trying again.")
            time.sleep(15)
            continue
        break
    json_data = json.loads(response.text)
    json_data["DShield Log Source"] = log_source
    json_data["DShield Log Identifier"] = input
    file = open("spur_data.json", 'a',encoding="utf-8")
    file.write(json.dumps(json_data) + "\n")
    file.close()
    return (json_data)

#URL, IP Address, Domain or file hash
@lru_cache
def get_vt_data(input, input_type, api):
    vt_data = {}
    headers = {'X-Apikey': api}
    if input_type == "url":
        url = "https://www.virustotal.com/api/v3/urls/" + input #url
    elif input_type == "domain":
        url = "https://www.virustotal.com/api/v3/domains/" + input #domain
    elif input_type == "hash":
        url = "https://www.virustotal.com/api/v3/files/" + input #hash
    elif input_type == "ip":
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + input #ip address
    else:
        logging.error("Invalid input type given for VirusTotal to process.")
    
    while True:
        try:
            response = requests.get(url, headers=headers)
        except Exception as e:
            logging.error(f"Exception hit for VirusTotal query: '{e}'. Pausing for 15 seconds before trying again.")
            time.sleep(15)
            continue
        break
    
    json_response = json.loads(response.text)
    logging.debug(response.text)
    if "error" in json_response:
        for key, value in json_response["error"].items():
            logging.error(f"VT Error for '{hash}': {value}")
    elif "data" in json_response:
        if "attributes" in json_response["data"]:
            if "last_analysis_stats" in json_response["data"]["attributes"]:
                for key, value in json_response["data"]["attributes"]["last_analysis_stats"].items():
                    vt_data[key] = value
                if "last_analysis_date" in json_response["data"]["attributes"]:
                    vt_data["last_analysis_date"] = json_response["data"]["attributes"]["last_analysis_date"]
                if "trid" in json_response["data"]["attributes"]:
                    vt_data["filetype"] = json_response["data"]["attributes"]["trid"][0]["file_type"]
                if "type_tag" in json_response["data"]["attributes"]:
                    vt_data["typetag"] = json_response["data"]["attributes"]["type_tag"]
                if "type_description" in json_response["data"]["attributes"]:
                    vt_data["description"] = json_response["data"]["attributes"]["type_description"]
                if "meaningful_name" in json_response["data"]["attributes"]:
                    vt_data["filename"] = json_response["data"]["attributes"]["meaningful_name"]
                if "popular_threat_classification" in json_response["data"]["attributes"]:
                    vt_data["classification"] = json_response["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
        
        filehandle = open("vt_data.json", "a", encoding="utf-8")
        filehandle.write(json.dumps(vt_data) +"\n")
        filehandle.close()
    return(vt_data)

@lru_cache
def get_uh_data(input):
    pass

def get_whois_data(input, email, **kwargs):
    """Return structured registration data using :func:`get_rdap_data`.

    This replaces the old no-op placeholder. It uses RDAP over HTTPS and needs
    contact information for the request User-Agent; it does not issue port-43
    WHOIS requests or recursively retrieve contact entities.
    """
    return get_rdap_data(input, email=email, **kwargs)

@lru_cache
def get_isc_data(input):
    pass

@lru_cache
def get_shodan_host(input, key):
    if not key:
        logging.info("Skipping Shodan host enrichment: no API key configured")
        return None
    import shodan

    api_shodan = shodan.Shodan(key)
    try:
        info = api_shodan.host(input)
        return info
    except Exception as e:
        logging.error(f"Issue looking up {input}: {e}")
    

@lru_cache
def get_shodan_domain(input, key):
    if not key:
        logging.info("Skipping Shodan domain enrichment: no API key configured")
        return {"data": []}
    import shodan

    api_shodan = shodan.Shodan(key)
    try:
        info = api_shodan.dns.domain_info(input)
        return info
    except Exception as e:
        logging.error(f"Issue looking up {input}: {e}")

#https://proxycheck.io/ 
@lru_cache
def get_proxycheck_data(input):
    pass

#https://ipinfo.io/
@lru_cache
def get_ipinfo_data(input):
    pass

#https://www.abuseipdb.com/
@lru_cache
def get_abuseipdb_data(input):
    pass    
    
#https://cybergordon.com/
@lru_cache
def get_cybergordon_data(input):
    pass

@lru_cache
def get_urlscan_data(input):
    pass

@lru_cache
def get_input(input):
    if "http" in input:
        logging.debug(f"URL: {input}")
    elif "." in input:
        try:
            ipaddress.ip_address(input)
            logging.debug(f"IP Address: {input}")
        except Exception as e:
            logging.debug(f"Not an IP Address: {input}")

@lru_cache
def extract_ip_address(input):
    pass

def isc_cloudapis(email):
    url = "https://isc.sans.edu/api/cloudips"
    headers = {
        'User-Agent': f'Request from {email}',
    }   

    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")
    
    xml =  text_response
    root = ET.fromstring(xml)
    ips = []
    netmasks = []
    providers = []
    comments = []
    for idx, cidr in enumerate(root.findall("cidr")):
        for idx2, ip in enumerate(cidr.findall("ip")):
            #print("IP: ", ip.text)
            ips.append(ip.text)
        for idx2, netmask in enumerate(cidr.findall("netmask")):
            #print("Netmask: ", netmask.text)
            netmasks.append(netmask.text)
        for idx2, provider in enumerate(cidr.findall("provider")):
            #print("Provider: ", provider.text)
            providers.append(provider.text)
        for idx2, comment in enumerate(cidr.findall("comment")):
            #print("Comment: ", comment.text)
            comments.append(comment.text)
    d = {'IP Address': ips, 'Netmask': netmasks, 'Provider': providers, 'Comment': comments}
    return pd.DataFrame(d)

def isc_cloudcidrs(email):
    url = "https://isc.sans.edu/api/cloudcidrs"
    headers = {
        'User-Agent': f'Request from {email}',
    }   
    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")
    
    xml =  text_response
    root = ET.fromstring(xml)
    ips = []
    providers = []
    comments = []
    for idx, cidr in enumerate(root.findall("cidr")):
        for idx2, ip in enumerate(cidr.findall("prefix")):
            #print("IP: ", ip.text)
            ips.append(ip.text)
        for idx2, provider in enumerate(cidr.findall("provider")):
            #print("Provider: ", provider.text)
            providers.append(provider.text)
        for idx2, comment in enumerate(cidr.findall("comment")):
            #print("Comment: ", comment.text)
            comments.append(comment.text)
    d = {'CIDR': ips, 'Provider': providers, 'Comment': comments}
    return pd.DataFrame(d)

def isc_intelfeed(email):
    url = "https://isc.sans.edu/api/intelfeed"
    headers = {
        'User-Agent': f'Request from {email}',
    }   

    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")
    
    xml =  text_response
    root = ET.fromstring(xml)


    #return pd.DataFrame(d)

def isc_ipinfo(ip, email, *, session=None, cache=None, timeout=(3.05, 10),
               max_attempts=3, cache_ttl=86400):
    """Return the legacy ``{ip: fields}`` ISC result with bounded requests.

    Missing optional fields are None. HTTP 429 raises EnrichmentRateLimitError
    with retry_at/retry_after instead of blocking the entire job for minutes.
    Pass an EnrichmentCache to reuse exact-IP results across separate runs.
    """
    return _http.isc_ipinfo(
        ip, email, session=session, cache=cache, timeout=timeout,
        max_attempts=max_attempts, cache_ttl=cache_ttl,
    )


#<threatcategory>
#<research>
#<ipv4>4.16.74.81</ipv4>
#<added>2020-07-18</added>
#<lastseen>2024-07-24</lastseen>
#<type>scorecard</type>
#</research>
def isc_research_threats(email, start_date=None, end_date=None):
    #url = f"https://isc.sans.edu/api/ip/{ip}"
    date_range = ""
    if start_date is not None and end_date is not None:
        date_range = f"{start_date}/{end_date}"
    url = f"https://isc.sans.edu/api/threatcategory/research/{date_range}"
    headers = {
        'User-Agent': f'Request from {email}',
    }   

    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")
        
    xml =  text_response
    logging.debug(f"XML Data: {xml}")
    root = ET.fromstring(xml)
    threat_intel = []
    for idx, research_info in enumerate(root.findall("research")):
        threat_intel.append(
            {
                "ipv4": research_info.findtext("ipv4"),
                "added": (research_info.findtext("added") or research_info.findtext("date")),
                "lastseen": research_info.findtext("lastseen"),
                "type": research_info.findtext("type")
            }
        )

    return pd.DataFrame(threat_intel, columns=["ipv4", "added", "lastseen", "type"])

def binary_edge_minions(email):
    # bad URL as of 7/6/2025
    # url = f"https://api.binaryedge.io/krang/v1/minions"
    url = f"https://api.binaryedge.io/v1/minions"

    headers = {
        'User-Agent': f'Request from {email}',
    }   

    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")
      
    scanners =  json.loads(text_response)['scanners']

    #return a list of binary edge minions (scanning agents)
    return scanners

def censys_networks(email):
    url = f"https://support.censys.io/hc/en-us/article_attachments/25644686434196"

    headers = {
        'User-Agent': f'Request from {email}',
    }   

    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")

    scanners =  text_response.split("\n")

    #return a list of binary edge minions (scanning agents)
    return scanners

def get_reverse_dns(ipaddress, **kwargs):
    """Return a PTR hostname or an empty string, preserving the legacy interface.

    Use get_reverse_dns_info for all PTR names, failure status and timestamps.
    Keyword arguments (including cache, resolver, timeout and lifetime) are
    forwarded to that function. Programming/configuration errors are raised.
    """
    result = get_reverse_dns_info(ipaddress, **kwargs)
    if result["status"] not in ("ok", "nxdomain", "no_ptr"):
        logging.warning("Reverse DNS for %s: %s", ipaddress, result["status"])
    return result["reverse_dns"]


def isc_webhoneypot_useragents(user_agent, day, email):
    encoded_agent = quote(str(user_agent), safe="")
    encoded_day = quote(str(day), safe="")
    url = f"https://isc.sans.edu/api/webhoneypotreportsbyua/{encoded_agent}/{encoded_day}?json"
    headers = {
        'User-Agent': f'Request from {email}',
    }   
    with _http.request_get(url, email=email, stream=True) as response:
        body = _http._read_body(response, 64 * 1024 * 1024)
    text_response = body.decode("utf-8-sig")
    
    return json.loads(text_response)
    
def extract_ips(data):
    ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', data)
    return_ips = []
    for each_ip in ips:
        try:
            ip = ipaddress.ip_address(each_ip)
            return_ips.append(each_ip)
        except:
            logging.error(f"Error trying to create IP address object from {each_ip}")
    return return_ips

def extract_subnets(data):
    networks = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})', data)
    return_networks = []
    for each_network in networks:
        try:
            network = ipaddress.ip_network(each_network)
            return_networks.append(each_network)
        except:
            logging.error(f"Error trying to create network object from {each_network}")
    return return_networks   
