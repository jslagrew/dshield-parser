import utils
import os
import sys

import utils.file_io

if __name__ == "__main__":
    if os.path.isfile(sys.argv[0]):
        filesize = os.stat(sys.argv[0])
        filesize_gb = filesize.st_size / (1024 * 1024)

        #Check if file is greater than 1 GB in size
        if filesize_gb >  1:
            print(f"File is greater than 1 GB ({round(filesize_gb, 2)} GB). Switching to stream mode")
    else:
        "ERROR: filename was expected as an argument."

json_data = utils.file_io.read_file_json_stream("cowrie.json.2024-02-14")
#utils.json.print_json_pretty_stream(json_data)
utils.json.print_json_keys_stream(json_data)