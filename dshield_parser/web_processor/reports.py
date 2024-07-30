from dshield_parser.utils import json as dshield_json
import itertools

default_datespan = {'start_date': '1970-01-01', 'end_date': '3000-01-01'}

def get_top_10_ips(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("sip", json_data, datespan)

def get_summary_ips(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("sip", json_data, datespan, exclusions)

def get_top_10_headers(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("headers", json_data, datespan)

def get_summary_headers(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("headers", json_data, datespan, exclusions)

def get_top_10_method(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("method", json_data, datespan)

def get_summary_methods(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("method", json_data, datespan, exclusions)

def get_top_10_url(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("url", json_data, datespan)

def get_summary_urls(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("url", json_data, datespan, exclusions)

def get_all_urls(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_json_values("url", json_data, datespan, exclusions)

def get_top_10_data(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("data", json_data, datespan)

def get_summary_data(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("data", json_data, datespan, exclusions)

def get_top_10_useragent(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("useragent", json_data, datespan)

def get_summary_useragents(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("useragent", json_data, datespan, exclusions)

def get_top_10_version(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("version", json_data, datespan)

def get_summary_versions(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("version", json_data, datespan, exclusions)

def get_top_10_responseid(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("response_id", json_data, datespan)

def get_summary_responseids(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("response_id", json_data, datespan, exclusions)

def get_top_10_signatureid(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("signature_id", json_data, datespan)

def get_summary_signatureids(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("signature_id", json_data, datespan, exclusions)

def get_top_10_multiple(fields, json_data, datespan=default_datespan):
    return dshield_json.get_top_10(fields, json_data, datespan)

def get_summary_multiple(fields, json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values(fields, json_data, datespan, exclusions)

def get_summary_all(json_data, datespan=default_datespan, exclusions=None):
    keys = dshield_json.get_json_keys(json_data)
    return keys, dshield_json.get_summary_values(keys, json_data, datespan, exclusions)

def get_volume_over_time(json_data, datespan=None):
    if datespan is None:
        datespan = default_datespan    
    return dshield_json.get_summary_values("time", json_data, datespan)