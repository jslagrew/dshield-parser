import os

# set working path. This will be the location that logs are stored
working_path = "."
os.chdir(working_path)

import logging, sys
import datetime

date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")

basic_with_time_format = '%(asctime)s:%(levelname)s:%(name)s:%(filename)s:%(funcName)s:%(message)s'
logging_fhandler = logging.FileHandler(f"{date}_dshield-parser-extractions.log")
logging_fhandler.setFormatter(logging.Formatter(basic_with_time_format))
logging_fhandler.setLevel(logging.INFO)

stdout_handler = logging.StreamHandler(stream = sys.stdout)
stdout_handler.setFormatter(logging.Formatter(basic_with_time_format))
stdout_handler.setLevel(logging.INFO)

logging.root.addHandler(logging_fhandler)
logging.root.addHandler(stdout_handler)
logging.root.setLevel(logging.DEBUG)

import pandas as pd

import dshield_parser.cowrie_processor
import dshield_parser.cowrie_processor.reports
import dshield_parser.firewall_processor
import dshield_parser.firewall_processor.reports
import dshield_parser.utils
import dshield_parser.utils.file_io
import dshield_parser.web_processor
import dshield_parser.web_processor.reports
import dshield_parser.utils.sql
import dshield_parser.utils.json
import dshield_parser.utils.graphs

# set location of honeypot data
honeypot_log_path = "\\\\fileserver\\honeypotdata"
honeypots, honeypot_dirs = dshield_parser.utils.file_io.get_honeypot_directories(honeypot_log_path)

logging.debug(f"Honeypots: {honeypots}")
logging.debug(f"Honeypot directories: {honeypot_dirs}")

honeypot_files = {}
for each_directory in honeypot_dirs:
    cowrie_files, web_honeypot_files, firewall_files = dshield_parser.utils.file_io.get_file_lists(each_directory)
    honeypot_files[each_directory] = {"cowrie": cowrie_files, "web": web_honeypot_files, "firewall": firewall_files}

date_format = "%Y-%m-%d"

#narrow testing timeframe
start_date = "2024-04-21"
end_date = "2024-05-21"
start_time = datetime.datetime.timestamp(datetime.datetime.strptime(start_date, date_format))
end_time = datetime.datetime.timestamp(datetime.datetime.strptime(end_date, date_format))
timespan = {"start_time": start_time, "end_time": end_time}
datespan = {"start_date": start_date, "end_date": end_date}

os.mkdir(date + "_honeypot_comparisons")
os.chdir(date + "_honeypot_comparisons")

directories_to_analyze = ['AWS', 'Azure', 'Digital Ocean', 'GCP', 'Residential']

cowrie_data = pd.DataFrame()
web_data = pd.DataFrame()
firewall_data = pd.DataFrame()

for key, value in honeypot_files.items():
    honeypotname = key.stem #get last directory from directory path
    if honeypotname in directories_to_analyze:

        # extract cowrie honeypot data, excluding data from 80.243.171.172 and only including the following keys: "timestamp", "src_ip", "input", "outfile", "username", "password"
        logging.info(f"Starting cowrie summarization of all honeypot fields: '{key}'")
        cowrie_data_temp = dshield_parser.utils.json.get_json_values(["timestamp", "src_ip", "input", "outfile", "username", "password"], value["cowrie"], timespan, exclusions={'sip': '80.243.171.172'})
        df = pd.DataFrame(cowrie_data_temp)
        dates = [dshield_parser.utils.json.time_to_day(timestamp) for timestamp in df["timestamp"]]
        df["dates"] = dates
        df = df.drop('timestamp', axis=1)
        df = df.groupby(df.columns.tolist(),as_index=False, dropna=False).size()
        dshield_parser.utils.sql.insert_df(f"{date}_{honeypotname}_cowrie.sqlite", df, "cowrie")
        df = df.rename(columns={"size": honeypotname})
        if len(cowrie_data) == 0:
            cowrie_data = df
        else:
            cowrie_data = cowrie_data.merge(df, on=["dates", "src_ip", "input", "outfile", "username", "password"], how="outer")     

        # extract web honeypot data, excluding data from 80.243.171.172 and only including the following keys: "time", "sip", "url", "headers"
        logging.info(f"Starting web summarization of all honeypot fields: '{key}'")
        url_header_data = dshield_parser.utils.json.get_json_values(["time", "sip", "url", "headers"], value["web"], timespan, exclusions={'sip': '80.243.171.172'})

        df = pd.DataFrame(url_header_data)
        df["user-agent"] = df["headers"].str['user-agent'] #.fillna("")
        df = df.drop("headers", axis=1)
        dates = [dshield_parser.utils.json.time_to_day(timestamp) for timestamp in df["time"]]
        df["dates"] = dates
        df = df.drop('time', axis=1)        
        df = df.groupby(df.columns.tolist(),as_index=False, dropna=False).size()
        dshield_parser.utils.sql.insert_df(f"{date}_{honeypotname}_url_header_web.sqlite", df, "web")
        df = df.rename(columns={"size": honeypotname})
        if len(web_data) == 0:
            web_data = df
        else:
            web_data = web_data.merge(df, on=["dates", "sip", "url", "user-agent"], how="outer")

        # extract cowrie honeypot data, excluding data from 80.243.171.172 and only including the following keys: "time", "sip", "dport", "proto"
        logging.info(f"Starting firewall summarization of all honeypot fields: '{key}'")
        firewall_data_temp = dshield_parser.utils.json.get_json_values(["time", "sip", "dport", "proto"], value["firewall"], timespan, exclusions={'sip': '80.243.171.172'})

        df = pd.DataFrame(firewall_data_temp)
        dates = [dshield_parser.utils.json.time_to_day(timestamp) for timestamp in df["time"]]
        df["dates"] = dates
        df = df.drop('time', axis=1)          
        df = df.groupby(df.columns.tolist(),as_index=False, dropna=False).size()
        dshield_parser.utils.sql.insert_df(f"{date}_{honeypotname}_firewall.sqlite", df, "firewall")
        df = df.rename(columns={"size": honeypotname})
        if len(firewall_data) == 0:
            firewall_data = df
        else:
            firewall_data = firewall_data.merge(df, on=["dates", "sip", "dport", "proto"], how="outer")   

# fill data that does not have a value with a zero (0)
for directory in directories_to_analyze:
    cowrie_data[directory] = cowrie_data[directory].fillna(0)
    web_data[directory] = web_data[directory].fillna(0)
    firewall_data[directory] = firewall_data[directory].fillna(0)

# save honeypot data extracts and summaries to a file)
dshield_parser.utils.sql.insert_df(f"{date}_extracts.sqlite", cowrie_data, "cowrie")
dshield_parser.utils.sql.insert_df(f"{date}_extracts.sqlite", web_data, "web")
dshield_parser.utils.sql.insert_df(f"{date}_extracts.sqlite", firewall_data, "firewall")

# add a colunm with the total counts from all honeypots
cowrie_data["total"] = cowrie_data["AWS"] + cowrie_data["Azure"] + cowrie_data["Digital Ocean"] + cowrie_data["GCP"] + cowrie_data["Residential"]
web_data["total"] = web_data["AWS"] + web_data["Azure"] + web_data["Digital Ocean"] + web_data["GCP"] + web_data["Residential"]
firewall_data["total"] = firewall_data["AWS"] + firewall_data["Azure"] + firewall_data["Digital Ocean"] + firewall_data["GCP"] + firewall_data["Residential"]

# save honeypot data extracts and summaries to a new file (this is used in the following scripts - enrich_summary_hashes, clear_research_ips)
dshield_parser.utils.sql.insert_df(f"{date}_extracts_dates.sqlite", cowrie_data, "cowrie")
dshield_parser.utils.sql.insert_df(f"{date}_extracts_dates.sqlite", web_data, "web")
dshield_parser.utils.sql.insert_df(f"{date}_extracts_dates.sqlite", firewall_data, "firewall")
