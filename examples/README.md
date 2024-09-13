# Scripts used to process honeypot data for SANS ISE master's degree paper. 

1) dshield_honeypot_comparisons_dbs_exclusions - Extract relevant data from honeypot logs based on selected JSON keys, time periods and IP address exclusions. Data extracted is stored in a SQLite file.

output file = 2024-09-07-120032_extracts_dates.sqlite

2) enrich_summary_hashes.py - Reads a SQLlite file and adds VirusTotal enrichment to file hashes uploaded or downloaded to the honeypot(s) ("outfile" field in Cowrie data is the file hash). Adds a "hashes" table to the SQLite file used. 

input file = 2024-09-07-120032_extracts_dates.sqlite  
output file = 2024-09-07-120032_extracts_dates.sqlite

3) clear_research_ips - Enrich data based on IP addresses to help identify research IP addresses. Enrichment data is sourced from the SANS Internet Storm Center, Shodan, vendor IP addresses, WHOIS data and reverse DNS lookups.

input file = 2024-09-07-120032_extracts_dates.sqlite  
output file = 2024-09-07-141406_honeypot_enrichment_mappings.sqlite

4) url-command-clustering - Build clusters from honeypot URLs and commands to group similar commands and find differences between honeypots. This uses changing EPS and minsample values to create new clusters. The clusters and values used to create the clusters are stored in a SQLite database file. Text files are also generated for an easier review of the data. Some feature examples in the script are commented out, but were used to test different features.

input file = 2024-09-07-141406_honeypot_enrichment_mappings.sqlite  
output file = 2024-09-08-080914_cluster_comparisons.sqlite


![Diagram of data processing](https://github.com/jslagrew/dshield-parser/blob/main/examples/data_processing_diagram.PNG)
