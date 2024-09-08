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
from concurrent.futures import ThreadPoolExecutor


# enter email address to be used in user agent strings for data enrichment
email = "enter email address here"

# enter shodan API key for Shodan data enrichment
shodan_api = "enter Shodan API key here"

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
ips = list(set(web_data["ipv4"].tolist() + cowrie_data["ipv4"].tolist() + firewall_data["ipv4"].tolist()))
           
# set up and start multi-threaded process to gather reverse DNS of all IP addresses
runner = ThreadPoolExecutor()
ips = list(set(firewall_data["ipv4"].tolist()))
ips_reverse_dns = [runner.submit(dshield_parser.utils.enrichment.get_reverse_dns, ipv4) for ipv4 in ips]

# check on process of reverse DNS lookups
done = False
while not done:
    number_not_complete = 0
    for each_lookup in ips_reverse_dns:
        if each_lookup.done() == False:
            number_not_complete += 1
            logging.debug(f"State: {each_lookup._state} left")
    if number_not_complete == 0:
        done = True
        logging.info(f"Processing completed. {number_not_complete} left")
    else:
        logging.info(f"Processing not yet completed. {number_not_complete} left")
    time.sleep(10)

# create dataframe of ip addresses and their reverse DNS lookups
reverse_dns = [rdns._result for rdns in ips_reverse_dns]
lookups = pd.DataFrame({'ipv4': ips, 'reverse_dns': reverse_dns})

# join the reverse DNS lookup data with cowrie, web and firewall honeypot dataframes
web_data = web_data.merge(lookups, on=["ipv4"], how="left")
cowrie_data = cowrie_data.merge(lookups, on=["ipv4"], how="left")
firewall_data = firewall_data.merge(lookups, on=["ipv4"], how="left")

# retrieve mass scanner data for enrichment
# https://github.com/stamparm/maltrail/blob/master/trails/static/mass_scanner.txt
mass_scanners = requests.get("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt").text.split("\n")
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
web_data = web_data.merge(scanners, on=["ipv4"], how="left").sort_values("mass_scanner")
cowrie_data = cowrie_data.merge(scanners, on=["ipv4"], how="left").sort_values("mass_scanner")
firewall_data = firewall_data.merge(scanners, on=["ipv4"], how="left").sort_values("mass_scanner")

# add any IPs with a user agent containing "CensysInspect" as a Censys research IP
censys_ips = web_data[web_data['user-agent'].str.contains("CensysInspect", na=False)]['ipv4'].tolist()
research_data = pd.DataFrame()
censys_networks = dshield_parser.utils.enrichment.censys_networks(email)
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
binaryedge_networks = dshield_parser.utils.enrichment.binary_edge_minions(email)
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
internetmeasurement_networks = dshield_parser.utils.enrichment.extract_subnets(requests.get("https://internet-measurement.com/#ips").text)
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
leakix_ips = web_data[web_data['user-agent'].str.contains("leakix", na=False)]['ipv4'].tolist()
leakix_domains = dshield_parser.utils.enrichment.get_shodan_domain("leakix.org", shodan_api)
for each_item in leakix_domains["data"]:
    ip = each_item["value"]
    try:
        ipaddress.IPv4Address(ip)
        leakix_ips.append(ip)
    except Exception as e:
        logging.error(f"Issus with {ip}: {e}")

research_ips = pd.DataFrame(leakix_ips, columns=["ipv4"])
research_ips["Research Organization"] = "LeakIX"
research_data = pd.concat([research_data, research_ips]) 

# add Onyphe IPs to research_data dataframe - implied from shodan domain data
onyphe_ips = []
onyphe_domains = dshield_parser.utils.enrichment.get_shodan_domain("onyphe.net", shodan_api)
for each_item in onyphe_domains["data"]:
    ip = each_item["value"]
    try:
        ipaddress.IPv4Address(ip)
        onyphe_ips.append(ip)
    except Exception as e:
        logging.error(f"Issus with {ip}: {e}")

research_ips = pd.DataFrame(onyphe_ips, columns=["ipv4"])
research_ips["Research Organization"] = "LeakIX"
research_data = pd.concat([research_data, research_ips]) 

# add recyber IPs to research_data dataframe - implied from shodan domain data
recyber_ips =[]
recyber_networks = dshield_parser.utils.enrichment.get_shodan_domain("recyber.net", shodan_api)
for each_item in recyber_networks["data"]:
    ip = each_item["value"]
    try:
        ipaddress.IPv4Address(ip)
        recyber_ips.append(ip)
    except Exception as e:
        logging.error(f"Issus with {ip}: {e}")

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


# add LeakIX IPs to research_data dataframe - implied from data in web requests and Shodan domain data
shadowserver_ips = web_data[web_data['url'].str.contains("shadowserver", na=False)]['ipv4'].tolist()
shadowserver_domains = dshield_parser.utils.enrichment.get_shodan_domain("shadowserver.org", shodan_api)
for each_item in shadowserver_domains["data"]:
    ip = each_item["value"]
    try:
        ipaddress.IPv4Address(ip)
        shadowserver_ips.append(ip)
    except Exception as e:
        logging.error(f"Issus with {ip}: {e}")

research_ips = pd.DataFrame(shadowserver_ips, columns=["ipv4"])
research_ips["Research Organization"] = "Shadowserver"
research_data = pd.concat([research_data, research_ips]) 

# marge research IP data with honeypot dataframes (web, cowrie, firewall)
web_data = web_data.merge(research_data, on=["ipv4"], how="left").sort_values("Research Organization")
cowrie_data = cowrie_data.merge(research_data, on=["ipv4"], how="left").sort_values("Research Organization")
firewall_data = firewall_data.merge(research_data, on=["ipv4"], how="left").sort_values("Research Organization")

# gather researcher IPs from SANS Internet storm center based on date range
isc_researchers = dshield_parser.utils.enrichment.isc_research_threats(email, start_date="2024-04-21", end_date="2024-05-21")
isc_researchers = isc_researchers.rename(columns={"type": "isc_researcher"})     
isc_researchers = isc_researchers.rename(columns={"added": "isc_added"})        
isc_researchers = isc_researchers.rename(columns={"lastseen": "isc_lastseen"})           

# marge SANS ISC research IP data with honeypot dataframes (web, cowrie, firewall)
web_data = web_data.merge(isc_researchers, on=["ipv4"], how="left")
cowrie_data = cowrie_data.merge(isc_researchers, on=["ipv4"], how="left")
firewall_data = firewall_data.merge(isc_researchers, on=["ipv4"], how="left")

# perform ISC network data lookups, preferring a local cache file and doing a lookup when data not found in the local file
ip_data = []
ip_data_file = "ip_lookups.txt"
if os.path.isfile(ip_data_file):
    filehandle = open(ip_data_file, "r")
    for each_line in open(ip_data_file):
        tempdata = json.loads(each_line)
        ip_data.append(tempdata)
ip_df = pd.DataFrame()
ips = set(web_data['ipv4'].values.tolist() + cowrie_data['ipv4'].values.tolist() + firewall_data['ipv4'].values.tolist())
for each_ip in ips:
    match = False
    for each_data in ip_data:
        if "network" in each_data:
            if each_data["network"] != None:
                if ipaddress.ip_address(each_ip) in ipaddress.ip_network(each_data['network']):
                    logging.debug(f"Found {each_ip} in the local list. No need to look it up via API")
                    temp_data = each_data.copy() #issue with data overwrite without using .copy()
                    temp_data["ipv4"] = each_ip
                    ip_data.append(temp_data)
                    match = True
                    break
            elif each_data["ipv4"] == each_ip:
                logging.debug(f"Found {each_ip} in the local list. No need to look it up via API")
                match = True
                break

    if not match:
        try:
            tempdata = dshield_parser.utils.enrichment.isc_ipinfo(each_ip, email)
        except Exception as e:
            logging.error(f"ISC ipinfo lookup failed for {each_ip} {e}")
        tempdata = {"ipv4": tempdata[each_ip]["number"], 
                        "as": tempdata[each_ip]["as"],
                        "asname": tempdata[each_ip]["asname"],
                        "ascountry": tempdata[each_ip]["ascountry"],
                        "assize": tempdata[each_ip]["assize"],
                        "network": tempdata[each_ip]["network"],
                        "updated": tempdata[each_ip]["updated"]
                        }
        ip_data.append(tempdata)
        filehandle = open("ip_lookups.txt", "a", encoding="utf-8")
        filehandle.write(json.dumps(tempdata) + "\n")
        filehandle.close()
        time.sleep(5)

# merge SANS ISC WHOIS data with honeypot dataframes (web, cowrie, firewall)
ip_data = pd.DataFrame(ip_data)
web_data = web_data.merge(ip_data, on=["ipv4"], how="left")
cowrie_data = cowrie_data.merge(ip_data, on=["ipv4"], how="left")
firewall_data = firewall_data.merge(ip_data, on=["ipv4"], how="left")

# write data to new SQLite file
# research data also stored as separate tables
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", web_data, "web")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", cowrie_data, "cowrie")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", firewall_data, "firewall")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", scanners, "mass_scanners")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", research_data, "public_researcher_data")
dshield_parser.utils.sql.insert_df(f"{date}_honeypot_enrichment_mappings.sqlite", isc_researchers, "isc_researchers")
