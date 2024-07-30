import logging
import re
from dshield_parser.utils import json as dshield_json

default_datespan = {'start_date': '1970-01-01', 'end_date': '3000-01-01'}

def get_top_10_usernames(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("username", json_data, datespan)

def get_summary_usernames(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("username", json_data, datespan, exclusions)

def get_top_10_passwords(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("password", json_data, datespan)

def get_summary_src_passwords(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("password", json_data, datespan, exclusions)

def get_top_10_dst_ports(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("dst_port", json_data, datespan)

def get_summary_dst_ports(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("dst_port", json_data, datespan, exclusions)

#shasum also gets tty files created, not just files uploaded or downloaded to the honeypot
def get_top_10_shasum(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("shasum", json_data, datespan)

#shasum also gets tty files created, not just files uploaded or downloaded to the honeypot
def get_summary_shasum(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("shasum", json_data, datespan, exclusions)

def get_top_10_files_created(json_data, datespan=default_datespan):
    created_files = dshield_json.get_top_10("outfile", json_data, datespan)
    updated_created_files = {}
    for key, value in created_files.items():
        hash = re.findall(r".*/(.*)", key)[0]
        updated_created_files[hash] = value
    return updated_created_files

def get_summary_files_created(json_data, datespan=default_datespan, exclusions=None):
    created_files = dshield_json.get_summary_values("outfile", json_data, datespan, exclusions)
    updated_created_files = {}
    for key, value in created_files.items():
        hash = re.findall(r".*/(.*)", key)[0]
        updated_created_files[hash] = value
    return updated_created_files

def get_all_input(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_json_values("input", json_data, datespan, exclusions)

def get_top_10_input(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("input", json_data, datespan)

def get_summary_input(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("input", json_data, datespan, exclusions)

def get_top_10_src_ip(json_data, datespan=default_datespan):
    return dshield_json.get_top_10("src_ip", json_data, datespan)

def get_summary_src_ip(json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values("src_ip", json_data, datespan, exclusions)

def get_top_10_multiple(fields, json_data, datespan=default_datespan):
    return dshield_json.get_top_10(fields, json_data, datespan)

def get_summary_multiple(fields, json_data, datespan=default_datespan, exclusions=None):
    return dshield_json.get_summary_values(fields, json_data, datespan, exclusions)

def get_summary_all(json_data, datespan=default_datespan, exclusions=None):
    logging.info("Gathering JSON Keys")
    keys = dshield_json.get_json_keys(json_data)
    logging.info("Completed gathering JSON Keys")
    return keys, dshield_json.get_summary_values(keys, json_data, datespan, exclusions)

def get_volume_over_time(json_data, datespan=None):
    if datespan is None:
        datespan = default_datespan
    return dshield_json.get_summary_values("timestamp", json_data, datespan)