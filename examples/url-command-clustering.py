import logging, sys
import datetime

date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")

basic_with_time_format = '%(asctime)s:%(levelname)s:%(name)s:%(filename)s:%(funcName)s:%(message)s'
logging_fhandler = logging.FileHandler(f"{date}_dshield-parser-clustering.log")
logging_fhandler.setFormatter(logging.Formatter(basic_with_time_format))
logging_fhandler.setLevel(logging.INFO)

stdout_handler = logging.StreamHandler(stream = sys.stdout)
stdout_handler.setFormatter(logging.Formatter(basic_with_time_format))
stdout_handler.setLevel(logging.DEBUG)

logging.root.addHandler(logging_fhandler)
logging.root.addHandler(stdout_handler)
logging.root.setLevel(logging.DEBUG)
import os
import re
import math
import dshield_parser.utils.sql
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import dshield_parser.utils.ml

def strip_protocol(string):
    if "://" in string:
        string = string.split("/")[3:]
        string = ['/'.join(string)][0]
    return string

def df_add_totals(df):
    df["total"] = 0
    for each_column in df.columns:
        if each_column != "index" and each_column != "total":
            df["total"] += df[each_column]
            df[f"{each_column}_perc"] = (df[each_column] / df[each_column].sum()) * 100
    df["percentage"] = (df["total"] / df["total"].sum()) * 100
    df.sort_values(by=['percentage'], ascending=False)
    df.head
    return df

def has_hidden(string):
    string = string.strip("/")
    string = strip_protocol(string)
    split_string = string.split("/")
    if len(split_string) > 0:
        for each_item in split_string:
            if len(each_item) > 0:
                if each_item[0] == ".":
                    return 1
    return 0    

def find_pattern_instance_num(string, pattern):
    return len(re.findall(rf'.*({pattern}).*', string))

def split_string(string, splitchars):
    string = string.strip("/")
    string = strip_protocol(string)
    return_string = []
    if isinstance(string, str):
        string = [string]
    for each_char in splitchars:
        for each_string in string:
            return_string += each_string.split(each_char)
        string = return_string
        return_string = []
    return string
        

def find_part_length(string, splitchars, segment):
    string = string.strip("/")
    string = strip_protocol(string)
    try:
        return len(split_string(string, splitchars)[segment])
    except:
        return 0
    
def get_number_of_parts(string, splitchars):
    string = string.strip("/")
    string = strip_protocol(string)
    try:
        return len(split_string(string, splitchars))
    except:
        return 0
    
def get_part_char1(string, splitchars, segment):
    string = string.strip("/")
    string = strip_protocol(string)
    try:
        return ord(split_string(string, splitchars)[segment][0])
    except:
        return 0

def get_file_stats(path):
    path = path.strip("/")
    string = strip_protocol(string)
    file_length = 0
    file_extension_length = 0
    file_extension_sum = 0
    filename = path.split("/")[-1]
    if len(filename) > 0:
        file_extension = filename.split(".")[-1]
        if len(file_extension) > 0:
            for each_char in file_extension:
                file_extension_sum += ord(each_char)
        return file_length, file_extension_length, int(round(math.sqrt(file_extension_sum),0))
    else:
        return file_length, file_extension_length, int(round(math.sqrt(file_extension_sum),0))
    
def get_file_length(path):
    path = path.strip("/")
    filename = path.split("/")[-1]
    return len(filename)

def get_file_sum(path):
    file_sum = 0
    path = path.strip("/")
    path = path.split("/")
    if "." in path[-1]:
        for each_char in path[-1]:
            file_sum += ord(each_char)
    return file_sum

def get_file_extension_length(path):
    filename = path.split("/")[-1]
    if len(filename) > 0:
        file_extension = filename.split(".")[-1]
        if len(file_extension) == len(filename):
            return 0
        return len(file_extension)
    else:
        return 0

def get_file_extension_sum(path):    
    file_extension_sum = 0
    filename = path.split("/")[-1]
    if len(filename) > 0:
        file_extension = filename.split(".")[-1]
        if len(file_extension) == len(filename):
            return 0        
        elif len(file_extension) > 0:
            for each_char in file_extension:
                file_extension_sum += ord(each_char)
        return file_extension_sum
    else:
        return file_extension_sum

def get_directory_sum(path, path_num=1):    
    path = path.strip("/")
    path = strip_protocol(path)
    directory_sum = 0
    if path.startswith("http://") or path.startswith("https://"):
        logging.debug(f"Full URL path detected: {path}")
        directories = path.split("/")[3:]
    else:
        directories = path.split("/")[0:]
    if len(directories) >= path_num:
        if len(directories) == path_num and "." in directories[path_num - 1]:
            logging.debug("This looks like a filename with an extension, so it will not be added to directory sums.")
            return directory_sum
        else:
            for each_char in directories[path_num - 1]:
                directory_sum += ord(each_char)
            return directory_sum
    else:
        return directory_sum

# enter working path
working_path = "."
os.chdir(working_path)
filename = "2024-09-07-141406_honeypot_enrichment_mappings.sqlite"

column_label = "input"
commands = dshield_parser.utils.sql.select(filename, "*", "cowrie")
commands = commands[[column_label, "AWS", "Azure", "Digital Ocean", "GCP", "Residential"]]
commands = commands.dropna()

commands = commands.groupby([column_label], axis=0, as_index=False).sum()
unique_commands = commands[(commands == 0).any(axis=1)]
unique_commands = unique_commands.loc[:, :column_label]

appends = [find_pattern_instance_num(index, " && ") for index in unique_commands[column_label]]
args1 = [find_pattern_instance_num(index, " +[A-Za-z] ") for index in unique_commands[column_label]]
args2 = [find_pattern_instance_num(index, " -[A-Za-z] ") for index in unique_commands[column_label]]
outputs = [find_pattern_instance_num(index, " > ") for index in unique_commands[column_label]]
conditionals = [find_pattern_instance_num(index, " if ") for index in unique_commands[column_label]]
command_parts = [find_part_length(index, [";", "|", "\n", " "], 0) for index in unique_commands[column_label]]
length = [len(index) for index in unique_commands[column_label]]
partn_length = [find_part_length(index, [";", "|", "\n"], -1) for index in unique_commands[column_label]]
partn_minus_1_length = [find_part_length(index, [";", "|", "\n", " "], -2) for index in unique_commands[column_label]]
partn_minus_2_length = [find_part_length(index, [";", "|", "\n", " "], -3) for index in unique_commands[column_label]]

unique_commands["appends"] = appends
unique_commands["args1"] = args1
unique_commands["args2"] = args2
unique_commands["outputs"] = outputs
unique_commands["conditionals"] = conditionals
unique_commands["command_parts"] = command_parts
unique_commands["length"] = length
unique_commands["partn_length"] = partn_length
unique_commands["partn_minus_1_length"] = partn_minus_1_length
unique_commands["partn_minus_2_length"] = partn_minus_2_length

datalimit = len(unique_commands)
unique_commands_data = unique_commands.loc[:, unique_commands.columns != column_label].to_numpy() 

minsamples_values = range(3, 11, 1)
eps_values = []
current_value = .5
limit = 6.5
while current_value <= limit:
    eps_values.append(current_value)
    current_value = round(current_value + .25, 2)

process_info = []
command_clusters = commands
for each_minsample in minsamples_values:
    for each_eps in eps_values:
        logging.info(f"Starting to process data with EPS: {each_eps} and Minsample: {each_minsample}.")  
        command_output, command_reduced_df = dshield_parser.utils.ml.analyze_chunk(unique_commands, unique_commands_data, column_label, 0, datalimit, each_minsample, each_eps)

        filehandle = open(f"{date}_{each_minsample}-MINSAMPLE_{each_eps}-EPS_command_clustering.txt", "w", encoding="utf-8")
        filehandle.write(command_output)
        filehandle.close()
        command_clusters = pd.merge(command_clusters, command_reduced_df[[column_label, "cluster"]], on=column_label)
        cluster_num = command_reduced_df["cluster"].nunique()
        command_clusters = command_clusters.rename(columns={'cluster': f'cluster-EPS({each_eps})-MINS({each_minsample})'})
        process_info.append([each_eps, each_minsample, cluster_num])

dshield_parser.utils.sql.insert_df(f"{date}_clusters.sqlite", command_clusters, f"commands")
process_info = pd.DataFrame(process_info, columns=["EPS Value", "Minsample Value", "Number of Clusters"])
dshield_parser.utils.sql.insert_df(f"{date}_cluster_comparisons.sqlite", process_info, "command_cluster_data")


column_label = "url"
urls = dshield_parser.utils.sql.select(filename, "*", "web")
urls = urls[[column_label, "AWS", "Azure", "Digital Ocean", "GCP", "Residential"]]
urls = urls.dropna()
urls = urls.groupby([column_label], axis=0, as_index=False).sum()
unique_urls = urls[(urls == 0).any(axis=1)]
unique_urls = unique_urls.loc[:, :column_label]


datalimit = len(unique_urls)

length = [len(index) for index in unique_urls[column_label]]
#url_parts = [get_number_of_parts(index, ["/", ".", "-"]) for index in unique_urls[column_label]]
#part1_length = [find_part_length(index, ["/", ".", "-"], 0) for index in unique_urls[column_label]]
#part2_length = [find_part_length(index, ["/", ".", "-"], 1) for index in unique_urls[column_label]]
#part3_length = [find_part_length(index, ["/", ".", "-"], 2) for index in unique_urls[column_label]]
url_parts = [get_number_of_parts(index, ["/"]) for index in unique_urls[column_label]]
part1_length = [find_part_length(index, ["/"], 0) for index in unique_urls[column_label]]
part2_length = [find_part_length(index, ["/"], 1) for index in unique_urls[column_label]]
part3_length = [find_part_length(index, ["/"], 2) for index in unique_urls[column_label]]
partn_length = [find_part_length(index, ["/"], -1) for index in unique_urls[column_label]]
partn_minus1_length = [find_part_length(index, ["/"], -2) for index in unique_urls[column_label]]
partn_minus2_length = [find_part_length(index, ["/"], -3) for index in unique_urls[column_label]]
partn_minus3_length = [find_part_length(index, ["/"], -4) for index in unique_urls[column_label]]
#partn_length = [find_part_length(index, ["/", ".", "-"], -1) for index in unique_urls[column_label]]
#partn_minus_1_length = [find_part_length(index, ["/", ".", "-"], -2) for index in unique_urls[column_label]]
#partn_minus_2_length = [find_part_length(index, ["/", ".", "-"], -3) for index in unique_urls[column_label]]
file_length = [get_file_length(index) for index in unique_urls[column_label]]
file_extension_length = [get_file_extension_length(index) for index in unique_urls[column_label]]
file_extension_sum = [get_file_extension_sum(index) for index in unique_urls[column_label]]
directory_1_sum = [get_directory_sum(index, 1) for index in unique_urls[column_label]]
directory_2_sum = [get_directory_sum(index, 2) for index in unique_urls[column_label]]
directory_3_sum = [get_directory_sum(index, 3) for index in unique_urls[column_label]]
directory_4_sum = [get_directory_sum(index, 4) for index in unique_urls[column_label]]
file_sum = [get_file_sum(index) for index in unique_urls[column_label]]
part2_char1 = [get_part_char1(index, ["/"] , 1) for index in unique_urls[column_label]]
part1_char1 = [get_part_char1(index, ["/"] , 0) for index in unique_urls[column_label]]
has_hidden_data = [has_hidden(index) for index in unique_urls[column_label]]

#unique_urls["url_parts"] = url_parts
#unique_urls["length"] = length
#unique_urls["part1_length"] = part1_length
#unique_urls["part2_length"] = part2_length
#unique_urls["part3_length"] = part3_length
#unique_urls["partn_length"] = partn_length
#unique_urls["partn_minus1_length"] = partn_minus1_length
#unique_urls["partn_minus2_length"] = partn_minus2_length
#unique_urls["partn_minus3_length"] = partn_minus3_length
unique_urls["file_length"] = file_length
unique_urls["file_extension_length"] = file_extension_length
unique_urls["has_hidden"] = has_hidden_data
unique_urls["file_extension_sum"] = file_extension_sum
#unique_urls["directory_1_sum"] = directory_1_sum
#unique_urls["directory_2_sum"] = directory_2_sum
#unique_urls["directory_3_sum"] = directory_3_sum
#unique_urls["directory_4_sum"] = directory_4_sum
unique_urls["file_sum"] = file_sum
#unique_urls["part2_char1"] = part2_char1
#unique_urls["part1_char1"] = part1_char1

unique_urls_data = unique_urls.loc[:, unique_urls.columns != column_label].to_numpy() 

process_info = []
url_clusters = urls
for each_minsample in minsamples_values:
    for each_eps in eps_values:
        logging.info(f"Starting to process data with EPS: {each_eps} and Minsample: {each_minsample}.")
        url_output, url_reduced_df =  dshield_parser.utils.ml.analyze_chunk(unique_urls, unique_urls_data, column_label, 0, datalimit, each_minsample, each_eps)

        filehandle = open(f"{date}_{each_minsample}-MINSAMPLE_{each_eps}-EPS_url_clustering.txt", "w", encoding="utf-8")
        filehandle.write(url_output)
        filehandle.close()
        cluster_num = url_reduced_df["cluster"].nunique()
        url_clusters = pd.merge(url_clusters, url_reduced_df[[column_label, "cluster"]], on=column_label)
        url_clusters = url_clusters.rename(columns={'cluster': f'cluster-EPS({each_eps})-MINS({each_minsample})'})
        process_info.append([each_eps, each_minsample, cluster_num])

dshield_parser.utils.sql.insert_df(f"{date}_clusters.sqlite", url_clusters, f"urls")
process_info = pd.DataFrame(process_info, columns=["EPS Value", "Minsample Value", "Number of Clusters"])
dshield_parser.utils.sql.insert_df(f"{date}_cluster_comparisons.sqlite", process_info, "url_cluster_data")
