import logging

import json
import itertools
import os
import sys
import re
from datetime import datetime
from datetime import timezone
import dshield_parser
import dshield_parser.firewall_processor
import dshield_parser.firewall_processor.reports
import dshield_parser.utils.file_io as file_io

default_datespan={'start_date': '1970-01-01', 'end_date': '3000-01-01'}
default_timespan={"start_time": 0, "end_time": 32516881838}

def print_json_pretty(incoming_data):
    for json_data in incoming_data:
        if os.path.exists(json_data):
            for yielded_json in file_io.read_file_json_generator(json_data):
                if "logs" in yielded_json:
                    for each_item in yielded_json["logs"]:
                        json_data_formatted = json.dumps(yielded_json, indent = 2)
                        print(json_data_formatted)
                else:            
                    json_data_formatted = json.dumps(yielded_json, indent = 2)
                    print(json_data_formatted)
        else:
            json_data = json.loads(json_data)
            json_data_formatted = json.dumps(json_data, indent = 2)
            print(json_data_formatted)

def print_json_keys(json_data):
    print_list(json.loads(json_data.keys()))

def get_json_keys(incoming_data):
    logging.info("Starting JSON key gathering.")
    keys = []
    if not isinstance(incoming_data, list):
        incoming_data = [incoming_data]
    for json_data in incoming_data:
        if os.path.exists(json_data):
            for yielded_json in file_io.read_file_json_generator(json_data):
                if "logs" in yielded_json:
                    for each_item in yielded_json["logs"]:
                        for each_key in each_item.keys():
                            if each_key not in keys:
                                keys.append(each_key)                
                else:
                    for each_key in yielded_json.keys():
                        if each_key not in keys:
                            keys.append(each_key)

        else:
            for each_item in json_data:
                for each_key in each_item.keys():
                    if each_key not in keys:
                        keys.append(each_key)
    ("Completed JSON key gathering.")
    return keys

def print_dict(dictionary):
    for key, value in dictionary.items():
        print(value, "\t", key)

def print_list(list):
    for each_item in list:
        print(each_item)

def get_json_values(key, incoming_data, timespan=default_timespan, exclusions=None):
    if "start_time" in timespan and "end_time" in timespan:
        start_date = convert_to_date(timespan["start_time"])
        end_date = convert_to_date(timespan["end_time"])    
        start_time = timespan["start_time"]
        end_time = timespan["end_time"]
    elif "start_date" in timespan and "end_date" in timespan:
        start_time = convert_to_epoch(timespan["start_date"])
        end_time = convert_to_epoch(timespan["end_date"])
        start_date = timespan["start_date"]
        end_date = timespan["end_date"]
    if not isinstance(incoming_data, list):
        incoming_data = [incoming_data]
    if not isinstance(key, list):
        key = [key]  
    values = []
    for file in incoming_data:
        logging.info(f"Starting processing of '{file}'")
        if os.path.exists(file):
            if len(re.findall(r"(\d\d\d\d-\d\d-\d\d)", str(file))) > 0:
                date = re.findall(r"(\d\d\d\d-\d\d-\d\d)", str(file))[0]
                if in_date_range(date, start_date, end_date):
                    for yielded_json in file_io.read_file_json_generator(file):
                        exclude_log = False
                        if isinstance(exclusions, dict):
                            for exclusion_key, exclusion_value in exclusions.items():
                                if exclusion_key in yielded_json:
                                    if yielded_json[exclusion_key] == exclusion_value:
                                        exclude_log = True
                        if exclude_log == False:      
                            log_data = {}                  
                            for each_key in key:
                                if "logs" in yielded_json:
                                    for each_item in yielded_json["logs"]:
                                        if each_key in each_item:
                                            #values.append(each_item[each_key])  
                                            log_data[each_key] = each_item[each_key]
                                else:
                                    if each_key in yielded_json:
                                        #values.append(yielded_json[each_key])    
                                        log_data[each_key] = yielded_json[each_key]
                            if len(log_data) > 0:
                                values.append(log_data)
            else:
                for yielded_json in file_io.read_file_json_generator(file):
                    if "logs" in yielded_json:
                        for each_item in yielded_json["logs"]:
                            log_data = {}
                            for each_key in key:
                                if "time" in each_item:
                                    if each_item["time"] < end_time and each_item["time"] > start_time:
                                        exclude_log = False
                                        if isinstance(exclusions, dict):
                                            for exclusion_key, exclusion_value in exclusions.items():
                                                if exclusion_key in each_item:
                                                    if each_item[exclusion_key] == exclusion_value:
                                                        exclude_log = True
                                        if exclude_log == False:
                                            if each_key in each_item:
                                                log_data[each_key] = each_item[each_key]
                                                #values.append(each_item[each_key])     
                                    else:
                                        logging.debug(f"Filtered out data since {each_item['time']} is not between {timespan['start_time']} and {timespan['end_time']}")  
                            if len(log_data) > 0:
                                values.append(log_data)                                               
        else:
            for each_item in file:
                if key in each_item:
                    values.append(each_item[key])
    return values

def summarize_values(list):
    summary = {}
    for each_value in list:
        if each_value in summary:
            summary[each_value] += 1
        else:
            summary[each_value] = 1
    return summary
    
def print_json_values(json_data, key):
    print_list(get_json_values(json_data, key))

def print_summary_values(list):
    print_list(summarize_values(list))

def get_top_10(json_data, key, timespan=default_timespan):
    data = get_summary_values(json_data, key, timespan)
    #the key and json_data seemed to be swapped
    data = sorted(data[json_data].items(), key=lambda x: x[1], reverse=True)
    data = dict(data)
    return dict(itertools.islice(data.items(), 10))

def get_summary_values(key, incoming_data, timespan=default_timespan, exclusions=None):
    if "start_time" in timespan and "end_time" in timespan:
        start_date = convert_to_date(timespan["start_time"])
        end_date = convert_to_date(timespan["end_time"])    
        start_time = timespan["start_time"]
        end_time = timespan["end_time"]
    elif "start_date" in timespan and "end_date" in timespan:
        start_time = convert_to_epoch(timespan["start_date"])
        end_time = convert_to_epoch(timespan["end_date"])
        start_date = timespan["start_date"]
        end_date = timespan["end_date"]
    list_unpacking_needed = set()
    dict_unpacking_needed = set()
    logging.info(f"Starting summary value processing for '{key}' from '{incoming_data}'")
    if not isinstance(incoming_data, list):
        incoming_data = [incoming_data]
    if not isinstance(key, list):
        key = [key]        
    data = {}
    for each_key in key:
        data[each_key] = {}
    for file in incoming_data:
        logging.info(f"Starting processing of '{file}'")
        if os.path.exists(file):
            if len(re.findall(r"(\d\d\d\d-\d\d-\d\d)", str(os.path.basename(file)))) > 0:
                date = re.findall(r"(\d\d\d\d-\d\d-\d\d)", str(file))[0]
                if in_date_range(date, start_date, end_date):
                    for yielded_json in file_io.read_file_json_generator(file):
                        exclude_log = False
                        if isinstance(exclusions, dict):
                            for exclusion_key, exclusion_value in exclusions.items():
                                if exclusion_key in yielded_json:
                                    if yielded_json[exclusion_key] == exclusion_value:
                                        exclude_log = True
                        if exclude_log == False:
                            for each_key in key:
                                if each_key in yielded_json:
                                    if isinstance(yielded_json[each_key], list):
                                        #need to do list things
                                        list_unpacking_needed.add(each_key)
                                        logging.debug(f"List data needs to be unpacked for key '{each_key}': '{yielded_json}'")
                                    elif isinstance(yielded_json[each_key], dict):
                                        #need to do dict things
                                        dict_unpacking_needed.add(each_key)
                                        logging.debug(f"List data needs to be unpacked for key '{each_key}': '{yielded_json}'")
                                        for jsonkey, jsonvalue in yielded_json[each_key].items():
                                            if isinstance(jsonvalue, dict) or isinstance(jsonvalue, list):
                                                logging.debug(f"Data needs to be unpacked for key '{jsonkey}': '{jsonvalue}'")
                                            else:
                                                if f"{each_key}_{jsonkey}" not in data:
                                                    data[f"{each_key}_{jsonkey}"]= {}
                                                if jsonvalue in data[f"{each_key}_{jsonkey}"]:
                                                    data[f"{each_key}_{jsonkey}"][jsonvalue] += 1
                                                else:
                                                    data[f"{each_key}_{jsonkey}"][jsonvalue] = 1                                        
                                    else:
                                        if yielded_json[each_key] in data[each_key]:
                                            data[each_key][yielded_json[each_key]] += 1
                                        else:
                                            data[each_key][yielded_json[each_key]] = 1
                else:
                    logging.debug(f"Filtered out data since {date} is not between {start_date} and {end_date}")        
            else:      
                for yielded_json in file_io.read_file_json_generator(file):
                    #process for firewall logs
                    if "logs" in yielded_json:
                        for each_item in yielded_json["logs"]:
                            if "time" in each_item:
                                if each_item["time"] < end_time and each_item["time"] > start_time:
                                    exclude_log = False
                                    if isinstance(exclusions, dict):
                                        for exclusion_key, exclusion_value in exclusions.items():
                                            if exclusion_key in each_item:
                                                if each_item[exclusion_key] == exclusion_value:
                                                    exclude_log = True
                                    if exclude_log == False:
                                        for each_key in key:                 
                                            if each_key in each_item:
                                                if each_item[each_key] in data[each_key]:
                                                    data[each_key][each_item[each_key]] += 1
                                                else:
                                                    data[each_key][each_item[each_key]] = 1
                                else:
                                    logging.debug(f"Filtered out data since {each_item['time']} is not between {timespan['start_time']} and {timespan['end_time']}")
        else:
            for each_line in file:
                for each_entry in each_line:
                    if key in each_entry:
                        if each_entry[key] in data:
                            data[each_entry[key]] += 1
                        else:
                            data[each_entry[key]] = 1    

    #data = sorted(data.items(), key=lambda x: x[1], reverse=True)
    #data = dict(data)
    logging.info("Finished data summarization.")
    logging.info(f"Dictionaries that need unpacking: {dict_unpacking_needed}")
    logging.info(f"Lists that need unpacking: {list_unpacking_needed}")
    return data

def sort_dict_desc(data):
    data = sorted(data.items(), key=lambda x: x[1], reverse=True)
    data = dict(data)
    return data

def get_daily_count(incoming_data):
    data = {}
    for json_data in incoming_data:
        if os.path.exists(json_data):
            for yielded_json in file_io.read_file_json_generator(json_data):
                if "logs" in yielded_json:
                    for each_item in yielded_json["logs"]:
                        if "time" in each_item:
                            date = convert_to_day(each_item["time"])
                            if date in data:
                                data[date] += 1
                            else:
                                data[date] = 1 
                else:
                    if "timestamp" in yielded_json:
                        date = convert_to_day(yielded_json["timestamp"])
                        if date in data:
                            data[date] += 1
                        else:
                            data[date] = 1 
                    if "time" in yielded_json:
                        date = convert_to_day(yielded_json["time"])
                        if date in data:
                            data[date] += 1
                        else:
                            data[date] = 1 
        else:
            for each_line in json_data:
                for each_entry in each_line:
                    if "timestamp" in each_entry:
                        date = convert_to_day(each_entry["timestamp"])
                        if date in data:
                            data[date] += 1
                        else:
                            data[date] = 1 
                    if "time" in each_entry:
                        date = convert_to_day(each_entry["time"])
                        if date in data:
                            data[date] += 1
                        else:
                            data[date] = 1               
    return data

# used to convert summary "time" or "timestamp" dictionaries so values are "datetime"
def convert_to_day(dictionary):
    for key, value in dictionary.items():
        if key == "time" or key == "timestamp":
            new_dates[key] = {}
            for time, count in value.items():
                day = time_to_day(time)
                if day in new_dates[key]:
                    new_dates[key][day] += count
                else:
                    new_dates[key][day] = count                                
        else:
            raise ValueError(f"Unexpected key: '{key}'")
    return new_dates

def time_to_day(time):
    if isinstance(time, int):
        day = datetime.fromtimestamp(time).astimezone(timezone.utc)
        day = day.strftime('%Y-%m-%d')                       
    elif time[-1:] == "Z":
        day = datetime.fromisoformat(time[:-1]).astimezone(timezone.utc)
        day = day.strftime('%Y-%m-%d')        
    else:
        day = datetime.fromisoformat(time).astimezone(timezone.utc)
        day = day.strftime('%Y-%m-%d')
    return day

def get_overlapping_timeframes(honeypot_dict):
    consolidated_start_time = ""
    consolidated_end_time = ""
    consolidated_start_date = ""
    consolidated_end_date = ""

    for key, value in honeypot_dict.items():
        logging.info(f"Reviewing {key} honeypot firewall times")
        for each_file in value["firewall"]:
            logging.info(f"Reviewing file '{each_file}'")
            start_time, end_time = dshield_parser.firewall_processor.reports.get_timspan(each_file)
            if consolidated_start_time == "":
                logging.info(f"{key} caused timing update: Setting start time to {start_time} and end time to {end_time}")
                consolidated_start_time = start_time
                consolidated_end_time = end_time
            elif start_time > consolidated_start_time:
                logging.info(f"{key} caused timing update: Updating start time from {consolidated_start_time} to {start_time}")
                consolidated_start_time = start_time
            elif end_time < consolidated_end_time:
                logging.info(f"{key} caused timing update: Updating end time from {consolidated_end_time} to {end_time}")
                consolidated_end_time = end_time                
    consolidated_start_date = dshield_parser.utils.json.convert_to_day(consolidated_start_time)
    consolidated_end_date = dshield_parser.utils.json.convert_to_day(consolidated_end_time)
    return consolidated_start_time, consolidated_end_time, consolidated_start_date, consolidated_end_date

def in_date_range(date, start_date, end_date):
    if datetime(int(date[0:4]), int(date[5:7]), int(date[8:10])) >= datetime(int(start_date[0:4]), 
            int(start_date[5:7]), int(start_date[8:10])) and datetime(int(date[0:4]), 
            int(date[5:7]), int(date[8:10])) <= datetime(int(end_date[0:4]), int(end_date[5:7]), int(end_date[8:10])):
        return True
    return False

# used to convert summary "time" or "timestamp" dictionaries so values are "datetime"
new_dates = {}
def convert_to_datetime(dictionary):
    logging.info(f"Starting to convert datetime")
    for key, value in dictionary.items():
        if key == "time" or key == "timestamp":
            new_dates[key] = {}
            for time, count in value.items():
                if isinstance(time, int):
                    day = datetime.fromtimestamp(time).astimezone(timezone.utc)
                    new_dates[key][day] = count
                elif time[-1:] == "Z":
                    day = datetime.fromisoformat(time[:-1]).astimezone(timezone.utc)
                    new_dates[key][day] = count
                else:
                    day = datetime.fromisoformat(time).astimezone(timezone.utc)
                    new_dates[key][day] = count
        else:
            raise ValueError(f"Unexpected key: '{key}'")
    return new_dates

def convert_to_epoch(date):
    return datetime.strptime(date, "%Y-%m-%d")

def convert_to_date(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')

# will be used when executing the script
if __name__ == "__main__":
    filepath = sys.argv[1]
    if os.path.exists(filepath):
        # print_list(get_json_keys(sys.argv[1]))
        
        # output dshield web honeypot data
        # print_dict(get_summary_values(sys.argv[1], "url"))
        print_dict(get_top_10(sys.argv[1], "url"))   

        # output dshield cowrie data
        # print_dict(get_summary_values(sys.argv[1], "command"))
        print_dict(get_top_10(sys.argv[1], "command"))   

        # output dshield firewall data
        # print_dict(get_summary_values(sys.argv[1], "dport"))
        print_dict(get_top_10(sys.argv[1], "dport"))        
    else:
        print("Argument supplied is not a file that exists.")