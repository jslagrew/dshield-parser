import os

# set working path. This is where data will logging data will be stored
working_path = "."
os.chdir(working_path)

import logging, datetime

date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
basic_with_time_format = '%(asctime)s:%(levelname)s:%(name)s:%(filename)s:%(funcName)s:%(message)s'
logging_fhandler = logging.FileHandler(f"{date}_dshield-parser-clear_research_ips.log")
logging_fhandler.setFormatter(logging.Formatter(basic_with_time_format))
logging_fhandler.setLevel(logging.INFO)

import sys

stdout_handler = logging.StreamHandler(stream = sys.stdout)
stdout_handler.setFormatter(logging.Formatter(basic_with_time_format))
stdout_handler.setLevel(logging.INFO)

logging.root.addHandler(logging_fhandler)
logging.root.addHandler(stdout_handler)
logging.root.setLevel(logging.DEBUG)

import ipaddress
import time
import json
import requests
import dshield_parser.utils.sql
import dshield_parser.utils.enrichment
import pandas as pd
from contextlib import ExitStack
from pathlib import Path


def _prepare_source_ips(sources):
    """Canonicalize source addresses and return their deterministic union."""
    addresses = set()
    for name, source in sources.items():
        if not isinstance(source, pd.DataFrame):
            raise TypeError(f"{name} source data must be a pandas DataFrame")
        if "ipv4" not in source.columns:
            raise ValueError(f"{name} source data requires an ipv4 column")
        normalized = []
        for index, value in source["ipv4"].items():
            try:
                if not isinstance(value, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    raise ValueError("expected an IP address literal")
                address = ipaddress.ip_address(value)
                if getattr(address, "scope_id", None) is not None:
                    raise ValueError("scoped IPv6 addresses are not supported")
            except ValueError as exc:
                raise ValueError(f"Invalid source IP in {name} at row {index}: {value!r}") from exc
            normalized.append(str(address))
        source["ipv4"] = pd.Series(normalized, index=source.index, dtype="object")
        addresses.update(normalized)
    return sorted(addresses)


def _shodan_ipv4_addresses(payload):
    """Return valid IPv4 records from an optional Shodan domain response."""
    if payload is None:
        return []
    if not isinstance(payload, dict):
        logging.warning("Ignoring an unexpected Shodan domain response")
        return []
    records = payload.get("data") or []
    if not isinstance(records, (list, tuple)):
        logging.warning("Ignoring unexpected Shodan domain records")
        return []
    addresses = []
    for record in records:
        value = record.get("value") if isinstance(record, dict) else None
        if not isinstance(value, str):
            continue
        try:
            addresses.append(str(ipaddress.IPv4Address(value)))
        except ValueError:
            # Domain responses also contain ordinary CNAME and AAAA records.
            continue
    return list(dict.fromkeys(addresses))


def _optional_feed(source, fetch, default, *, skip_reason=None):
    """Keep failed optional sources unknown and record their availability."""
    row = {"source": source, "status": "ok", "checked_at": time.time(),
           "retry_at": None, "error": None}
    result = default
    if skip_reason is not None:
        row.update(status="skipped", error=skip_reason)
        logging.warning("Optional enrichment source %s skipped: %s", source, skip_reason)
    else:
        try:
            response = fetch()
            if response is None:
                row["status"] = "unavailable"
                logging.warning("Optional enrichment source %s returned no result", source)
            elif not isinstance(response, type(default)):
                raise TypeError("unexpected response type")
            else:
                result = response
        except dshield_parser.utils.enrichment.EnrichmentRateLimitError as exc:
            row.update(status="deferred", retry_at=exc.retry_at)
            logging.warning("Optional enrichment source %s deferred until %s", source, exc.retry_at)
        except Exception as exc:
            # Optional feeds must not discard the run's event data. Store the
            # error type, never provider exception text that could contain keys.
            row.update(status="error", error=type(exc).__name__)
            logging.warning("Optional enrichment source %s failed (%s)", source, type(exc).__name__)
    enrichment_sources.append(row)
    return result


def _get_feed_text(url):
    with requests.get(url, timeout=(3.05, 10)) as response:
        response.raise_for_status()
        return response.text


# Availability is separate from labels: a failed source is not evidence of a
# benign IP. checked_at records this check, not a cached result's fetch time.
enrichment_sources = []


# enter email address to be used in user agent strings for data enrichment
email = os.environ.get("DSHIELD_CONTACT_EMAIL", "")

# enter shodan API key for Shodan data enrichment
shodan_api = os.environ.get("SHODAN_API_KEY", "")

# enter filename for SQLite data
filename = "2024-09-07-120032_extracts_dates.sqlite"

# read web honeypot data and rename dataframe columns for future joining (merge)
web_data = dshield_parser.utils.sql.select(filename, "*", "web")
web_data = web_data.rename(columns={"sip": "ipv4"})
web_data = web_data.rename(columns={"dates": "date"})

# read cowrie honeypot data and rename dataframe columns for future joining (merge)
cowrie_data = dshield_parser.utils.sql.select(filename, "*", "cowrie")
cowrie_data = cowrie_data.rename(columns={"src_ip": "ipv4"})
cowrie_data = cowrie_data.rename(columns={"dates": "date"})

# read firewall honeypot data and rename dataframe columns for future joining (merge)
firewall_data = dshield_parser.utils.sql.select(filename, "*", "firewall")
firewall_data = firewall_data.rename(columns={"sip": "ipv4"})
firewall_data = firewall_data.rename(columns={"dates": "date"})

# get unique list of ip addresses in all of the logs
ips = _prepare_source_ips({
    "web": web_data, "cowrie": cowrie_data, "firewall": firewall_data,
})

# set up and start multi-threaded process to gather reverse DNS of all IP addresses
# Cache is shared across runs; each completed lookup is persisted by the helper.
cache_path = Path(os.environ.get(
    "DSHIELD_ENRICHMENT_CACHE",
    str(Path.home() / "dshield-parser-cache" / "enrichment.sqlite"),
)).expanduser()
with dshield_parser.utils.enrichment.EnrichmentCache(cache_path) as cache:
    dns_results = list(dshield_parser.utils.enrichment.iter_reverse_dns(
        ips, cache=cache, max_workers=16, timeout=1.0, lifetime=3.0,
    ))
lookups = pd.DataFrame([
    {"ipv4": item["ip"], "reverse_dns": item["reverse_dns"],
     "reverse_dns_status": item["status"],
     "reverse_dns_fetched_at": item["fetched_at"],
     "reverse_dns_expires_at": item["expires_at"]}
    for item in dns_results
], columns=["ipv4", "reverse_dns", "reverse_dns_status",
            "reverse_dns_fetched_at", "reverse_dns_expires_at"])


# join the reverse DNS lookup data with cowrie, web and firewall honeypot dataframes
web_data = web_data.merge(lookups, on=["ipv4"], how="left", validate="many_to_one")
cowrie_data = cowrie_data.merge(lookups, on=["ipv4"], how="left", validate="many_to_one")
firewall_data = firewall_data.merge(lookups, on=["ipv4"], how="left", validate="many_to_one")

# retrieve mass scanner data for enrichment
# https://github.com/stamparm/maltrail/blob/master/trails/static/mass_scanner.txt
mass_scanners = _optional_feed(
    "maltrail", lambda: _get_feed_text(
        "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt"
    ).splitlines(), [],
)
ip = []
comment = []
for each_item in mass_scanners:
    try:
        integer = int(each_item[:1])
        ip.append(each_item.split(" ")[0])
        if "#" in each_item:
            comment.append(each_item.split("#")[1].strip("\n").strip())
        else:
            comment.append("Other scanner")
    except:
        logging.info(f"Looks like it didn't start with an integer: {each_item}")

scanners = pd.DataFrame({"ipv4": ip, "mass_scanner": comment})

#add scanner data from https://github.com/stamparm/maltrail/blob/master/trails/static/mass_scanner.txt
scanner_lookup = scanners.groupby("ipv4", as_index=False).agg(
    mass_scanner=("mass_scanner", lambda values: " | ".join(sorted(set(values.dropna())))),
)
web_data = web_data.merge(scanner_lookup, on=["ipv4"], how="left", validate="many_to_one").sort_values("mass_scanner")
cowrie_data = cowrie_data.merge(scanner_lookup, on=["ipv4"], how="left", validate="many_to_one").sort_values("mass_scanner")
firewall_data = firewall_data.merge(scanner_lookup, on=["ipv4"], how="left", validate="many_to_one").sort_values("mass_scanner")

# add any IPs with a user agent containing "CensysInspect" as a Censys research IP
censys_ips = web_data[web_data['user-agent'].str.contains("CensysInspect", na=False)]['ipv4'].tolist()
research_data = pd.DataFrame()
censys_networks = _optional_feed("censys", lambda: dshield_parser.utils.enrichment.censys_networks(email), [])
for each_network in censys_networks:
    try:
        censys_ips += [str(ip) for ip in ipaddress.IPv4Network(each_network)]
    except:
        logging.error(f"Not a valid IPv4 network: {each_network}")

# add censys IPs to research_data dataframe
censys_ips = list(set(censys_ips))
research_ips = pd.DataFrame(censys_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Censys"
research_data = pd.concat([research_data, research_ips])

# gather binary edge minion IP addresses
binaryedge_networks = _optional_feed("binaryedge", lambda: dshield_parser.utils.enrichment.binary_edge_minions(email), [])
return_addresses = []
for each_address in binaryedge_networks:
    if ":" not in each_address:
        return_addresses.append(each_address)

# add binary edge IPs to research_data dataframe
research_ips = pd.DataFrame(return_addresses, columns=["ipv4"])
research_ips["Research Organization"] = "BinaryEdge"
research_data = pd.concat([research_data, research_ips])

# add alpha strike IPs to research_data dataframe
# https://ipinfo.io/AS208843
alphastrike_networks = ["45.83.64.0/22", "194.187.176.0/22"]
for each_network in alphastrike_networks:
    try:
        research_ips = [str(ip) for ip in ipaddress.IPv4Network(each_network)]
    except:
        logging.error(f"Not a valid IPv4 network: {each_network}")
    research_ips = pd.DataFrame(research_ips, columns=["ipv4"])
    research_ips["Research Organization"] = "Alpha Strike Labs"
    research_data = pd.concat([research_data, research_ips])

# add palo alto IPs to research_data dataframe
palo_ips = web_data[web_data['user-agent'].str.contains("Expanse, a Palo", na=False)]['ipv4'].tolist()
paloalto_networks = ["205.210.31.0/24", "198.235.24.0/24", "162.216.149.0/24", "162.216.150.0/24", "35.203.210.0/24"]
for each_network in paloalto_networks:
    try:
        palo_ips += [str(ip) for ip in ipaddress.IPv4Network(each_network)]
    except:
        logging.error(f"Not a valid IPv4 network: {each_network}")

palo_ips = list(set(palo_ips))
research_ips = pd.DataFrame(palo_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Palo Alto Expanse"
research_data = pd.concat([research_data, research_ips])

#https://internet-measurement.com/#ips
#internetmeasurement_networks = ["87.236.176.0/24", "193.163.125.0/24", "68.183.53.77/32", "104.248.203.191/32", "104.248.204.195/32",
#                                "142.93.191.98/32", "157.245.216.203/32", "165.22.39.64/32", "167.99.209.184/32", "188.166.26.88/32",
#                                "206.189.7.178/32", "209.97.152.248/32"]

# add internetmeasurement IPs to research_data dataframe - implied from user agent data in web requests
internetmeasurement_ips = web_data[web_data['user-agent'].str.contains("InternetMeasurement", na=False)]['ipv4'].tolist()
internetmeasurement_networks = _optional_feed(
    "internet_measurement",
    lambda: dshield_parser.utils.enrichment.extract_subnets(
        _get_feed_text("https://internet-measurement.com/#ips")
    ), [],
)
for each_network in internetmeasurement_networks:
    try:
        internetmeasurement_ips += [str(ip) for ip in ipaddress.IPv4Network(each_network)]
    except:
        logging.error(f"Not a valid IPv4 network: {each_network}")

research_ips = pd.DataFrame(internetmeasurement_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Internet Measurement"
research_data = pd.concat([research_data, research_ips])

# add ipip IPs to research_data dataframe - implied from user agent data in web requests
ipip_ips = web_data[web_data['user-agent'].str.contains("ipip", na=False)]['ipv4'].tolist()
ipip_networks = ["103.203.56.0/24", "103.203.57.0/24"]
for each_network in ipip_networks:
    try:
        ipip_ips += [str(ip) for ip in ipaddress.IPv4Network(each_network)]
    except:
        logging.error(f"Not a valid IPv4 network: {each_network}")

ipip_ips = list(set(ipip_ips))
research_ips = pd.DataFrame(ipip_ips, columns=["ipv4"])
research_ips["Research Organization"] = "IPIP Security"
research_data = pd.concat([research_data, research_ips])

# add LeakIX IPs to research_data dataframe - implied from user agent data in web requests
leakix_ips = web_data[web_data['user-agent'].str.contains("leakix", case=False, na=False)]['ipv4'].tolist()
leakix_domains = _optional_feed(
    "shodan:leakix.org", lambda: dshield_parser.utils.enrichment.get_shodan_domain("leakix.org", shodan_api), {},
    skip_reason=None if shodan_api else "missing_api_key",
)
leakix_ips.extend(_shodan_ipv4_addresses(leakix_domains))

research_ips = pd.DataFrame(leakix_ips, columns=["ipv4"])
research_ips["Research Organization"] = "LeakIX"
research_data = pd.concat([research_data, research_ips])

# add Onyphe IPs to research_data dataframe - implied from shodan domain data
onyphe_ips = []
onyphe_domains = _optional_feed(
    "shodan:onyphe.net", lambda: dshield_parser.utils.enrichment.get_shodan_domain("onyphe.net", shodan_api), {},
    skip_reason=None if shodan_api else "missing_api_key",
)
onyphe_ips.extend(_shodan_ipv4_addresses(onyphe_domains))

research_ips = pd.DataFrame(onyphe_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Onyphe"
research_data = pd.concat([research_data, research_ips])

# add recyber IPs to research_data dataframe - implied from shodan domain data
recyber_ips =[]
recyber_networks = _optional_feed(
    "shodan:recyber.net", lambda: dshield_parser.utils.enrichment.get_shodan_domain("recyber.net", shodan_api), {},
    skip_reason=None if shodan_api else "missing_api_key",
)
recyber_ips.extend(_shodan_ipv4_addresses(recyber_networks))

# add recyber IPs to research_data dataframe
recyber_networks = ["89.248.163.0/25", "89.248.165.0/24"]
for each_network in recyber_networks:
    try:
        recyber_ips += [str(ip) for ip in ipaddress.IPv4Network(each_network)]
    except:
        logging.error(f"Not a valid IPv4 network: {each_network}")

recyber_ips = list(set(recyber_ips))
research_ips = pd.DataFrame(recyber_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Recyber"
research_data = pd.concat([research_data, research_ips])


# add Shadowserver IPs inferred from web requests and Shodan domain data
shadowserver_ips = web_data[web_data['url'].str.contains("shadowserver", na=False)]['ipv4'].tolist()
shadowserver_domains = _optional_feed(
    "shodan:shadowserver.org", lambda: dshield_parser.utils.enrichment.get_shodan_domain("shadowserver.org", shodan_api), {},
    skip_reason=None if shodan_api else "missing_api_key",
)
shadowserver_ips.extend(_shodan_ipv4_addresses(shadowserver_domains))

research_ips = pd.DataFrame(shadowserver_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Shadowserver"
research_data = pd.concat([research_data, research_ips])

# marge research IP data with honeypot dataframes (web, cowrie, firewall)
research_lookup = research_data.groupby("ipv4", as_index=False).agg({
    "Research Organization": lambda values: " | ".join(sorted(set(values.dropna())))
})
web_data = web_data.merge(research_lookup, on=["ipv4"], how="left", validate="many_to_one").sort_values("Research Organization")
cowrie_data = cowrie_data.merge(research_lookup, on=["ipv4"], how="left", validate="many_to_one").sort_values("Research Organization")
firewall_data = firewall_data.merge(research_lookup, on=["ipv4"], how="left", validate="many_to_one").sort_values("Research Organization")

# gather researcher IPs from SANS Internet storm center based on date range
isc_researchers = _optional_feed(
    "isc_researchers", lambda: dshield_parser.utils.enrichment.isc_research_threats(email, start_date="2024-04-21", end_date="2024-05-21"),
    pd.DataFrame(columns=["ipv4", "added", "lastseen", "type"]),
)
isc_researchers = isc_researchers.rename(columns={"type": "isc_researcher"})
isc_researchers = isc_researchers.rename(columns={"added": "isc_added"})
isc_researchers = isc_researchers.rename(columns={"lastseen": "isc_lastseen"})
# An empty feed may have no columns; absent optional dates stay unknown.
isc_researchers = isc_researchers.reindex(
    columns=["ipv4", "isc_added", "isc_lastseen", "isc_researcher"]
).astype({"ipv4": "object", "isc_researcher": "object"})

# marge SANS ISC research IP data with honeypot dataframes (web, cowrie, firewall)
isc_lookup = isc_researchers.groupby("ipv4", as_index=False).agg(
    isc_added=("isc_added", "min"), isc_lastseen=("isc_lastseen", "max"),
    isc_researcher=("isc_researcher", lambda values: " | ".join(sorted(set(values.dropna())))),
)
web_data = web_data.merge(isc_lookup, on=["ipv4"], how="left", validate="many_to_one")
cowrie_data = cowrie_data.merge(isc_lookup, on=["ipv4"], how="left", validate="many_to_one")
firewall_data = firewall_data.merge(isc_lookup, on=["ipv4"], how="left", validate="many_to_one")

# perform ISC network data lookups, preferring a local cache file and doing a lookup when data not found in the local file
# Choose a local database by setting one of these paths. ISC remains an explicit
# fallback when neither path is configured. Never reinterpret country/AS-size.
asn_mmdb = os.environ.get("DSHIELD_ASN_MMDB")
iptoasn_file = os.environ.get("DSHIELD_IPTOASN_FILE")
if asn_mmdb and iptoasn_file:
    raise ValueError("Set only one of DSHIELD_ASN_MMDB and DSHIELD_IPTOASN_FILE")

ips = sorted(set(web_data["ipv4"]) | set(cowrie_data["ipv4"]) | set(firewall_data["ipv4"]))
ip_rows = []
fields = ["ipv4", "as", "asname", "ascountry", "assize", "network", "updated",
          "enrichment_source", "enrichment_status", "enrichment_fetched_at",
          "enrichment_retry_at", "asn_range_start", "asn_range_end", "source_country"]
with ExitStack() as stack:
    cache = stack.enter_context(dshield_parser.utils.enrichment.EnrichmentCache(cache_path))
    session = stack.enter_context(requests.Session())
    reader = None
    database = None
    if asn_mmdb:
        import geoip2.database
        reader = stack.enter_context(geoip2.database.Reader(asn_mmdb))
    elif iptoasn_file:
        database = dshield_parser.utils.enrichment.load_iptoasn_database(iptoasn_file)
    for each_ip in ips:
        row = dict.fromkeys(fields)
        row["ipv4"] = each_ip
        if not ipaddress.ip_address(each_ip).is_global:
            row["enrichment_status"] = "non_global"
            ip_rows.append(row)
            continue
        if reader is not None or database is not None:
            if reader is not None:
                record = dshield_parser.utils.enrichment.get_geoip_asn(each_ip, reader=reader)
            else:
                record = dshield_parser.utils.enrichment.get_iptoasn_data(each_ip, database)
            row.update({"as": record.get("asn"), "asname": record.get("asn_organization"),
                        "network": record.get("lookup_network"),
                        "enrichment_source": record["source"], "enrichment_status": record["status"],
                        "enrichment_fetched_at": record["fetched_at"],
                        "asn_range_start": record.get("range_start"),
                        "asn_range_end": record.get("range_end"),
                        "source_country": record.get("source_country")})
        else:
            row["enrichment_source"] = "isc"
            try:
                record = dshield_parser.utils.enrichment.isc_ipinfo(
                    each_ip, email, cache=cache, session=session,
                )[each_ip]
            except dshield_parser.utils.enrichment.EnrichmentRateLimitError as exc:
                row["enrichment_status"] = "deferred"
                row["enrichment_retry_at"] = exc.retry_at
            except dshield_parser.utils.enrichment.EnrichmentError as exc:
                logging.warning("ISC lookup failed for %s: %s", each_ip, exc)
                row["enrichment_status"] = "error"
            else:
                row.update({key: record.get(key) for key in
                            ("as", "asname", "ascountry", "assize", "network", "updated")})
                row["enrichment_status"] = "ok"
                # The provider's updated field is not a local lookup timestamp.
                row["enrichment_fetched_at"] = record.get("fetched_at")
        ip_rows.append(row)

# One result row per IP; duplicate enrichment must not multiply event counts.
ip_data = pd.DataFrame(ip_rows, columns=fields)
web_data = web_data.merge(ip_data, on="ipv4", how="left", validate="many_to_one")
cowrie_data = cowrie_data.merge(ip_data, on="ipv4", how="left", validate="many_to_one")
firewall_data = firewall_data.merge(ip_data, on="ipv4", how="left", validate="many_to_one")
logging.info("IP enrichment status counts: %s", ip_data["enrichment_status"].value_counts().to_dict())


# write data to new SQLite file
# research data also stored as separate tables
enrichment_sources = pd.DataFrame(
    enrichment_sources, columns=["source", "status", "checked_at", "retry_at", "error"]
)
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", web_data, "web")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", cowrie_data, "cowrie")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", firewall_data, "firewall")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", scanners, "mass_scanners")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", research_data, "public_researcher_data")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", isc_researchers, "isc_researchers")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", enrichment_sources, "enrichment_sources")
