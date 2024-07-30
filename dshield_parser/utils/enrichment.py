import logging, datetime
import sys
import re
import json
import requests #needs to be installed
import shodan #needs to be installed
import dshield_parser.utils as utils
import dshield_parser.utils.json as dshield_json
import pandas as pd
import sys
import os
import time
import ipaddress
import requests
import xml.etree.ElementTree as ET
from pathlib import Path
from functools import lru_cache
import datetime
import socket

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
        except:
            print("Exception hit for SPUR query")
            #time.sleep(10)
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
    
    response = requests.get(url, headers=headers)
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

@lru_cache
def get_whois_data(input):
    pass

@lru_cache
def get_isc_data(input):
    pass

@lru_cache
def get_shodan_host(input, key):
    api_shodan = shodan.Shodan(key)
    try:
        info = api_shodan.host(input)
        return info
    except Exception as e:
        logging.error(f"Issue looking up {input}: {e}")
    

@lru_cache
def get_shodan_domain(input, key):
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
    response = requests.get(url, headers=headers)
    xml =  response.text
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
    response = requests.get(url, headers=headers)
    xml =  response.text
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
        f'User-Agent': 'Request from {email}',
    }   
    response = requests.get(url, headers=headers)
    xml =  response.text
    root = ET.fromstring(xml)


    #return pd.DataFrame(d)

@lru_cache
def isc_ipinfo(ip, email):

    url = f"https://isc.sans.edu/api/ip/{ip}"
    headers = {
        'User-Agent': f'Request from {email}',
    }   
    response = requests.get(url, headers=headers)    
    while response.status_code != 200:
        delay = 5
        if response.status_code == 429:
            logging.error(f"Request limit reached: {response.text}")
            try:
                delay_received = int(re.findall(r'.*Try again after (.*) seconds', response.text)[0])
                delay = int(delay_received)
                logging.error(f"Delaying for an additional {delay} seconds")
            except:
                logging.error(f"Some issue occured with the delay we recevied: {delay_received}")
        time.sleep(delay)
        response = requests.get(url, headers=headers) 
    if response.status_code == 200:
        xml =  response.text
        logging.debug(f"XML Data: {xml}")
        root = ET.fromstring(xml)
        ipdata = {}
        ipdata[ip] = {}
        ipdata[ip]["number"] = root.findall("number")[0].text
        ipdata[ip]["count"] = root.findall("count")[0].text
        ipdata[ip]["attacks"] = root.findall("attacks")[0].text
        ipdata[ip]["maxdate"] = root.findall("maxdate")[0].text
        ipdata[ip]["mindate"] = root.findall("mindate")[0].text
        ipdata[ip]["updated"] = root.findall("updated")[0].text
        ipdata[ip]["comment"] = root.findall("comment")[0].text
        ipdata[ip]["maxrisk"] = root.findall("maxrisk")[0].text
        ipdata[ip]["asabusecontact"] = root.findall("asabusecontact")[0].text
        ipdata[ip]["as"] = root.findall("as")[0].text
        ipdata[ip]["asname"] = root.findall("asname")[0].text
        ipdata[ip]["ascountry"] = root.findall("ascountry")[0].text
        ipdata[ip]["assize"] = root.findall("assize")[0].text
        ipdata[ip]["network"] = root.findall("network")[0].text
        for idx2, webloginfo in enumerate(root.findall("weblogs")):
            ipdata[ip]["weblog_count"] = webloginfo.findall("count")[0].text
            ipdata[ip]["weblog_avgauthors"] = webloginfo.findall("avgauthors")[0].text
            ipdata[ip]["weblog_avgurls"] = webloginfo.findall("avgurls")[0].text
            ipdata[ip]["weblog_avguseragents"] = webloginfo.findall("avguser_agents")[0].text
            ipdata[ip]["weblog_firstseen"] = webloginfo.findall("firstseen")[0].text
            ipdata[ip]["lastseen"] = webloginfo.findall("lastseen")[0].text
        return ipdata

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
    response = requests.get(url, headers=headers)    
    xml =  response.text
    logging.debug(f"XML Data: {xml}")
    root = ET.fromstring(xml)
    threat_intel = []
    for idx, research_info in enumerate(root.findall("research")):
        threat_intel.append(
            {
                "ipv4": research_info.findall("ipv4")[0].text,
                "added": research_info.findall("added")[0].text,
                "lastseen": research_info.findall("lastseen")[0].text,
                "type": research_info.findall("type")[0].text
            }
        )

    return pd.DataFrame(threat_intel)

def binary_edge_minions(email):
    url = f"https://api.binaryedge.io/krang/v1/minions"

    headers = {
        'User-Agent': f'Request from {email}',
    }   
    response = requests.get(url, headers=headers)    
    scanners =  json.loads(response.text)['scanners']

    #return a list of binary edge minions (scanning agents)
    return scanners

def censys_networks(email):
    url = f"https://support.censys.io/hc/en-us/article_attachments/25644686434196"

    headers = {
        'User-Agent': f'Request from {email}',
    }   
    response = requests.get(url, headers=headers)    
    scanners =  response.text.split("\n")

    #return a list of binary edge minions (scanning agents)
    return scanners

@lru_cache
def get_reverse_dns(ipaddress):
    response = ""
    try:
        response = socket.gethostbyaddr(f"{ipaddress}")
    except Exception as e:
        logging.error(f"Lookup failed for {ipaddress}: {e}")
    if len(response) == 0:
        return response
    else:
        return response[0]
    

def isc_webhoneypot_useragents(user_agent, day, email):
    url = f"https://isc.sans.edu/api/webhoneypotreportsbyua/{user_agent}/{day}?json"
    headers = {
        'User-Agent': f'Request from {email}',
    }   
    response = requests.get(url, headers=headers)  
    return json.loads(response.text)    
    
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


#cloudips = isc_cloudapis()
#insert_df(f"{date}_iscdata.sqlite", cloudips, "cloudips")

#cloudcidr = isc_cloudcidrs()
#insert_df(f"{date}_iscdata.sqlite", cloudcidr, "cloudcidrs")

#ipdata = isc_ipinfo("70.91.145.10")
#insert_dict(f"{date}_iscdata.sqlite", ipdata, "70.91.145.10")  

#research_data = isc_research_threats()
#insert_df(f"{date}_iscdata.sqlite", research_data, "research_ip")  