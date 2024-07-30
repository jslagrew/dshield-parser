import logging
from pathlib import Path
from dshield_parser.utils import json as dshield_json

default_timespan={"start_time": 0, "end_time": 32516881838}

def get_top_10_flags(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("flags", json_data, timespan)

def get_summary_flags(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("flags", json_data, timespan, exclusions)

def get_top_10_src_ips(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("sip", json_data, timespan)

def get_summary_src_ips(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("sip", json_data, timespan, exclusions)

def get_top_10_dst_ips(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("dip", json_data, timespan)

def get_summary_dst_ips(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("dip", json_data, timespan, exclusions)

def get_top_10_proto(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("proto", json_data, timespan)

def get_summary_proto(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("proto", json_data, timespan, exclusions)

def get_top_10_sport(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("sport", json_data, timespan)

def get_summary_sport(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("sport", json_data, timespan, exclusions)

def get_top_10_dport(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("dport", json_data, timespan)

def get_summary_dport(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("dport", json_data, timespan, exclusions)

def get_top_10_version(json_data, timespan=default_timespan):
    return dshield_json.get_top_10("version", json_data, timespan)

def get_summary_version(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("version", json_data, timespan, exclusions)

def get_summary_times(json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values("time", json_data, timespan, exclusions)

def get_summary_multiple(fields, json_data, timespan=default_timespan, exclusions=None):
    return dshield_json.get_summary_values(fields, json_data, timespan, exclusions)

def get_summary_all(json_data, timespan=default_timespan, exclusions=None):
    keys = dshield_json.get_json_keys(json_data)
    return keys, dshield_json.get_summary_values(keys, json_data, timespan, exclusions)

def get_timspan(json_data):
    start_time = ""
    end_time = ""
    logging.info(f"Getting summary times from: '{json_data}'")
    times = get_summary_times(Path(json_data))
    for key, value in times['time'].items():
        if start_time == "":
            start_time = key
            end_time = key
        elif key < start_time:
            start_time = key
        elif key > end_time:
            end_time = key
    logging.info(f"Found start time of: '{start_time}'")
    logging.info(f"Found end time of '{end_time}'")
    return start_time, end_time

def get_volume_over_time(json_data, timespan=None):
    if timespan is None:
        timespan = default_timespan
    return dshield_json.get_summary_values("time", json_data, timespan)