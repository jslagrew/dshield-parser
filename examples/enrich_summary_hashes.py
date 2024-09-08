import dshield_parser.utils.enrichment
import dshield_parser.utils.sql

# SQLite file to read data from
filename = "2024-09-07-120032_extracts_dates.sqlite"

# VirusTotal API
vt_api = "enter your api key here"

# Read cowrie data and extract file hashes
# Remove columns that are not needed ("src_ip", "username", "password", "input", "dates")
# This will maintain the columns that contain the counts of the hahes seen per honeypot
hash_data = dshield_parser.utils.sql.select(filename, "*", "cowrie")
hash_data = hash_data.drop(["src_ip", "username", "password", "input", "dates"], axis=1)
hash_data = hash_data.dropna()
hash_data["outfile"] = hash_data["outfile"].str.replace("var/lib/cowrie/downloads/","")
hash_data = hash_data.groupby('outfile', as_index=False).sum()

# Enrich hash data from VirusTotal
filetypes = []
typetags = []
descriptions = []
filenames = []
classifications = []
for each_hash in hash_data["outfile"]:
    vt_data = dshield_parser.utils.enrichment.get_vt_data(each_hash, "hash", vt_api)
    if "filetype" in vt_data:
        filetypes.append(vt_data["filetype"])
    else:
        filetypes.append("")

    if "typetag" in vt_data:
        typetags.append(vt_data["typetag"])
    else:
        typetags.append("")
    
    if "description" in vt_data:
        descriptions.append(vt_data["description"])
    else:
        descriptions.append("")
    
    if "filename" in vt_data:
        filenames.append(vt_data["filename"])
    else:
        filenames.append("")
    
    if "classification" in vt_data:
        classifications.append(vt_data["classification"])
    else:
        classifications.append("")

# add virustotal data to dataframe
hash_data["filetype"] = filetypes
hash_data["typetag"] = typetags
hash_data["description"] = descriptions
hash_data["filename"] = filenames
hash_data["classification"] = classifications

# save dataframe to the same file in a new "hashes" table
dshield_parser.utils.sql.insert_df(filename, hash_data, "hashes")