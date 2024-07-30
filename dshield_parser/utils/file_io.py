import logging
import json
import dshield_parser.utils as utils
import dshield_parser.utils.json as dshield_json
from pathlib import Path
import sys
import os

def read_file_string(filename):
    filehandle = open(filename, encoding="utf-8")
    string = filehandle.read()
    return string

def read_file_json(filename):
    try:
        filehandle = open(filename, encoding="utf-8")
        json_data = json.load(filehandle)
    except:
        json_data = read_file_json_stream(filename)
    return json_data

def read_file_json_stream(filename):
    data = []
    with open(filename) as file:
        for line in file:
            if line[:1] =="{":
                data.append(json.loads(line))
    return(data)

def read_file_json_generator(filename):
    file = open(filename, "r", encoding="utf-8")
    for line in file:
        if line[:1] =="{":
            try:
                yield json.loads(line)
            except Exception as e:
                logging.error(f"Exception hit for file '{filename}': {e}")
                logging.error(f"Text of line with error (limted to first 40 characters): '{line[0:40]}'")
    file.close()

def get_honeypot_list(path):
    honeypots = []
    dir_contents =  os.listdir(path)
    for each_item in dir_contents:
        if os.path.isdir(path + "\\" + each_item):
            honeypots.append(each_item)
    return honeypots

def get_file_lists(path):
    cowrie_files = []
    web_honeypot_files = []
    firewall_files = []
    if os.path.exists(f"{path}\\logs\\dshield_firewall_.log"):
        firewall_files.append(f"{path}\\logs\\dshield_firewall_.log")
    try:
        folder_list = Path(path)
        #file_list = sorted(Path(path).iterdir(), key=os.path.getmtime)
    except:
        print(f"{path}: File Listing Error Occurred")
    for each_item in folder_list.glob('**/*'):
        if "cowrie.json" in str(each_item):
            cowrie_files.append(each_item)
        elif "webhoneypot-" in str(each_item):
            web_honeypot_files.append(each_item)
    cowrie_files = sorted(cowrie_files, key=os.path.getmtime)
    web_honeypot_files = sorted(web_honeypot_files, key=os.path.getmtime)
    firewall_files = sorted(firewall_files, key=os.path.getmtime)
    return cowrie_files, web_honeypot_files, firewall_files

def get_overlapping_file_lists(path):
    cowrie_files, web_honeypot_files, firewall_files = get_file_lists(path)

def get_honeypot_directories(path):
    honeypots = []
    honeypot_dirs = []
    try:
        file_list = sorted(Path(path).iterdir(), key=os.path.getmtime)
    except:
        print("File Listing Error Occurred")
    for each_item in file_list:
        if os.path.isdir(each_item):
            honeypots.append(os.path.basename(each_item))
            honeypot_dirs.append(each_item)
    return honeypots, honeypot_dirs

def save_dict_to_file(dict, filename):
    logging.info(f"Saving data from dict to file '{filename}'")
    filehandle = open(filename, "a", encoding="utf-8")
    for key, value in dict.items():
        filehandle.write(f"{value}\t{key}\n")
    filehandle.close()

def save_list_to_file(list, filename):
    logging.info(f"Saving data from list to file '{filename}'")
    filehandle = open(filename, "a", encoding="utf-8")
    for each_item in dict:
        filehandle.write(f"{each_item}\n")
    filehandle.close()

# will be used when executing the script
if __name__ == "__main__":
    filepath = sys.argv[1]
    if os.path.exists(filepath):
        dshield_json.print_json_pretty(sys.argv[1])
    else:
        print("Argument supplied is not a file that exists.")