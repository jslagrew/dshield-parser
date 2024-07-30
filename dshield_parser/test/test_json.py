import unittest
import dshield_parser.utils
import dshield_parser.cowrie_processor.reports
import dshield_parser.firewall_processor.reports
import dshield_parser.web_processor.reports
import pandas as pd
#import dshield_parser


class TestCowrieTop10Usernames(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        top_10 = {'root': 9, 'admin': 4, 'Alphanetworks': 1, 'cpanel': 1, 'default': 1, 'Epuser': 1, 'ftp_nmc': 1, 'GET / HTTP/1.1': 1, 'PCUSER': 1, 'User-Agent: curl/7.64.1': 1}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_top_10_usernames(logfile), 
                        top_10, msg="Top 10 username value mismatch")
        
class TestCowrieTop10Usernames2(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/gcp/cowrie.json.2024-06-01"
        top_10 = {'root': 118, 'admin': 39, 'support': 19, 'user': 17, 'telecomadmin': 17, 'ubnt': 11, 'unknown': 8, 'test': 8, 'default': 8, 'operator': 6}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_top_10_usernames(logfile), 
                        top_10, msg="Top 10 username value mismatch")
        
class TestCowrieSummaryUsernames(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        summary_data = {}
        summary_data['username'] = {'root': 9, 'admin': 4, 'Alphanetworks': 1, 'cpanel': 1, 'default': 1, 'Epuser': 1, 'ftp_nmc': 1, 'GET / HTTP/1.1': 1, 'PCUSER': 1, 'User-Agent: curl/7.64.1': 1}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_summary_usernames(logfile), 
                        summary_data, msg="Summary username value mismatch")

class TestCowrieTop10Passwords(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        top_10 = {'password': 3, 'admin': 2, '123123': 2, '1111': 2, '0fc0f17d6087680e': 1, 'vizxv': 1, 'juantech': 1, 'Host: 44.204.196.240:23': 1, 'Accept: */*': 1, 'root': 1}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_top_10_passwords(logfile), 
                        top_10, msg="Top 10 password value mismatch")
        
class TestCowrieSummaryPasswords(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        summary_data = {}
        summary_data['password'] = {'0fc0f17d6087680e': 1,
                                    '696969': 1,
                                    'Accept: */*': 1,
                                    'default': 1,
                                    'Host: 44.204.196.240:23': 1,
                                    'juantech': 1,
                                    'root': 1,
                                    'SYS': 1,
                                    'tuxalize': 1,
                                    'userEp': 1,
                                    'vizxv': 1,
                                    'wrgn22_dlwbr_dir615': 1,
                                    '1111': 2,
                                    '123123': 2,
                                    'admin': 2,
                                    'password': 3}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_summary_src_passwords(logfile), 
                        summary_data, msg="Summary password value mismatch")

class TestCowrieTop10Ports(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        top_10 = {2222: 7, 2223: 128}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_top_10_dst_ports(logfile), 
                        top_10, msg="Top 10 ports value mismatch")

class TestCowrieSummaryDstPorts(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        summary_data = {}
        summary_data['dst_port'] = {2222: 7, 2223: 128}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_summary_dst_ports(logfile), 
                        summary_data, msg="Summary cowrie destination port value mismatch")

class TestCowrieSummaryDstPorts2(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/gcp/cowrie.json.2024-06-01"
        summary_data = {}
        summary_data['dst_port'] = {2222: 474, 2223: 583, 443: 10, 587: 2, 80: 8}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_summary_dst_ports(logfile), 
                        summary_data, msg="Summary cowrie destination port value mismatch")

class TestCowrieSummaryExclusionDstPorts2(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/gcp/cowrie.json.2024-06-01"
        summary_data = {}
        summary_data['dst_port'] = {2222: 474, 2223: 583, 443: 10, 80: 8}
        self.assertDictEqual(dshield_parser.cowrie_processor.reports.get_summary_dst_ports(logfile, exclusions={'dst_port': 587}), 
                        summary_data, msg="Summary cowrie destination port value mismatch")

class TestCowrieKeyRetrieval(unittest.TestCase):
    def test_correct(self):        
        #cat aws/cowrie.json.2024-02-24| jq keys | sort | uniq| sort -n 
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        sorted_keys = dshield_parser.utils.json.get_json_keys(logfile)
        sorted_keys.sort()
        self.assertEqual(sorted_keys, 
                         [  "arch",
                            "compCS",
                            "dst_ip",
                            "dst_port",
                            "duplicate",
                            "duration",
                            "encCS",
                            "eventid",
                            "hassh",
                            "hasshAlgorithms",
                            "input",
                            "kexAlgs",
                            "keyAlgs",
                            "langCS",
                            "macCS",
                            "message",
                            "password",
                            "protocol",
                            "sensor",
                            "session",
                            "shasum",
                            "size",
                            "src_ip",
                            "src_port",
                            "timestamp",
                            "ttylog",
                            "username",
                            "version"], msg="JSON key value retrieval mismatch")
        
class TestWebhoneypotKeyRetrieval(unittest.TestCase):
    def test_correct(self):        
        #cat aws/webhoneypot-2024-02-24.json| jq keys | sort | uniq 
        logfile = "dshield_parser/test/honeypotdata/aws/webhoneypot-2024-02-24.json"
        sorted_keys = dshield_parser.utils.json.get_json_keys(logfile)
        sorted_keys.sort()        
        self.assertEqual(sorted_keys, 
                         ["data",
                        "dip",
                        "headers",
                        "method",
                        "response_id",
                        "signature_id",
                        "sip",
                        "time",
                        "url",
                        "useragent",
                        "version"], msg="JSON key value retrieval mismatch")        
        
class TestWebHoneypotTop10URLs(unittest.TestCase):
    def test_correct(self):
        #cat gcp/webhoneypot-2024-06-01.json| jq .url | sort | uniq -c| sort -n
        logfile = "dshield_parser/test/honeypotdata/gcp/webhoneypot-2024-06-01.json"
        top_10 = {"/.env.backup": 257, 
                  "/.docker/.env": 265,
                  "/.c9/metadata/environment/.env": 269,
                  "/_static/.env": 273,
                  "/.env": 274,
                  "/.aws/credentials": 277,
                  "/.env_sample": 281,
                  "/.env_1": 285,
                  "/.env.www": 289,
                  "/": 312}                
        self.assertDictEqual(dshield_parser.web_processor.reports.get_top_10_url(logfile), 
                        top_10, msg="Top 10 URLs value mismatch")        
        
class TestWebSummaryURLs(unittest.TestCase):
    def test_correct(self):
        #cat aws/webhoneypot-2024-02-24.json | jq .url | sort | uniq -c | sort -n
        logfile = "dshield_parser/test/honeypotdata/aws/webhoneypot-2024-02-24.json "
        summary_data = {}
        summary_data['url'] = {"/manager/text/list": 1, 
                               "/public/index.php": 1, 
                               "/ReportServer": 1, 
                               "/favicon.ico": 2, 
                               "/goform/set_LimitClient_cfg": 2,
                               "/index.php": 9, 
                               "/.env": 11,
                               "/": 18}
        self.assertDictEqual(dshield_parser.web_processor.reports.get_summary_urls(logfile), 
                        summary_data, msg="Summary URLs value mismatch")
        
class TestWebSummaryURLsExclusion(unittest.TestCase):
    def test_correct(self):
        #cat aws/webhoneypot-2024-02-24.json | jq .url | sort | uniq -c | sort -n
        logfile = "dshield_parser/test/honeypotdata/aws/webhoneypot-2024-02-24.json "
        summary_data = {}
        summary_data['url'] = {"/manager/text/list": 1, 
                               "/public/index.php": 1, 
                               "/ReportServer": 1, 
                               "/favicon.ico": 2, 
                               "/index.php": 9, 
                               "/.env": 11,
                               "/": 18}
        self.assertDictEqual(dshield_parser.web_processor.reports.get_summary_urls(logfile, exclusions={'url': '/goform/set_LimitClient_cfg'}), 
                        summary_data, msg="Summary URLs value mismatch")

        
class TestWebGetJSONValuesIPExclusion(unittest.TestCase):
    def test_correct(self):
        #cat aws/webhoneypot-2024-02-24.json | jq 'select (.url)' | jq .url | wc -l
        #total of 45 entries

        #exclude sip of 207.90.244.3
        #cat aws/webhoneypot-2024-02-24.json | jq 'select (.url)' | jq 'select (.sip!="207.90.244.3")' | jq .url | wc -l
        #total of 42 entries

        logfile = "dshield_parser/test/honeypotdata/aws/webhoneypot-2024-02-24.json "
        self.assertEqual(len(dshield_parser.web_processor.reports.get_all_urls(logfile)), 
                        45, msg="Summary URLs value mismatch")
        
        self.assertEqual(len(dshield_parser.web_processor.reports.get_all_urls(logfile, exclusions={'sip': '207.90.244.3'})), 
                        42, msg="Summary URLs value mismatch")
        
class TestCowrieJSONValuesIPExclusion(unittest.TestCase):
    def test_correct(self):
        #cat aws/cowrie.json.2024-02-24 | jq 'select (.input)' | jq .input | wc -l
        #total of 61 entries

        #exclude sip of 213.6.13.197
        #cat aws/cowrie.json.2024-02-24 | jq 'select (.input)' | jq 'select (.src_ip!="213.6.13.197")' |jq .input | wc -l
        #total of 48 entries

        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"
        self.assertEqual(len(dshield_parser.cowrie_processor.reports.get_all_input(logfile)), 
                        61, msg="Cowrie Input value mismatch")
        
        self.assertEqual(len(dshield_parser.cowrie_processor.reports.get_all_input(logfile, exclusions={'src_ip': '213.6.13.197'})), 
                        48, msg="Cowrie input value mismatch with set exclusion")        

class TestFirewallKeyRetrieval(unittest.TestCase):
    def test_correct(self):     
        logfile = "dshield_parser/test/honeypotdata/gcp/dshield_firewall_.log"
        sorted_keys = dshield_parser.utils.json.get_json_keys(logfile)
        sorted_keys.sort()                
        self.assertEqual(sorted_keys, 
                         ['dip', 'dport', 'flags', 'proto', 'sip', 'sport', 'time', 'version'], msg="JSON key value retrieval mismatch")        
        
class TestFirewallKeyLogRetrieval(unittest.TestCase):
    def test_correct(self):        
        logfile = "dshield_parser/test/honeypotdata/gcp/dshield_firewall_.log"
        log_data = dshield_parser.utils.json.get_json_values("time", logfile)
        log_data_entry_num = len(log_data)
        self.assertEqual(log_data_entry_num, 
                         17252, msg="JSON key value retrieval mismatch")        
        
class TestFirewallReportsRetrieval(unittest.TestCase):
    def test_correct(self):        
        logfile = "dshield_parser/test/honeypotdata/gcp/dshield_firewall_.log"
        self.assertEqual(dshield_parser.firewall_processor.reports.get_top_10_src_ips(logfile), 
                        {'104.156.155.6': 645,
                        '121.182.176.148': 78,
                        '148.135.35.230': 95,
                        '195.85.205.159': 98,
                        '207.180.235.220': 183,
                        '62.122.184.51': 122,
                        '79.110.62.166': 71,
                        '79.110.62.73': 1324,
                        '79.110.62.92': 73,
                        '79.124.62.74': 125}, msg="Top 10 source IP value mismatch")      
        self.assertEqual(dshield_parser.utils.json.get_top_10("sip", logfile), 
                        {'104.156.155.6': 645,
                        '121.182.176.148': 78,
                        '148.135.35.230': 95,
                        '195.85.205.159': 98,
                        '207.180.235.220': 183,
                        '62.122.184.51': 122,
                        '79.110.62.166': 71,
                        '79.110.62.73': 1324,
                        '79.110.62.92': 73,
                        '79.124.62.74': 125}, msg="Top 10 source IP value mismatch")  

class TestFirewallSummarySrcIPs(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/gcp/dshield_firewall_.log"
        self.assertEqual(len(dshield_parser.firewall_processor.reports.get_summary_src_ips(logfile)['sip']), 
                        4542, msg="Summary source IPs value mismatch. Wrong number of expected values returned.")
        
        self.assertEqual(dshield_parser.firewall_processor.reports.get_summary_src_ips(logfile)['sip']['152.89.198.75'], 
                        17, msg="Summary source IPs value mismatch. Wrong number of occurences returned for IP address.")        

class TestFirewallSummarySrcIPsExclusion(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/gcp/dshield_firewall_.log"
        self.assertEqual(len(dshield_parser.firewall_processor.reports.get_summary_src_ips(logfile, exclusions={'sip': '152.89.198.75'})['sip']), 
                        4541, msg="Summary source IPs value mismatch. Wrong number of expected values returned.")
        
        data_with_exclusion = dshield_parser.firewall_processor.reports.get_summary_src_ips(logfile, exclusions={'sip': '152.89.198.75'})['sip']
        self.assertRaises(KeyError, data_with_exclusion.__getitem__, '152.89.198.75')
        
        self.assertEqual(data_with_exclusion['147.185.133.120'], 3)

        #self.assertEqual(len(dshield_parser.firewall_processor.reports.get_summary_src_ips(logfile, exclusions={'sip': {'152.89.198.75', '162.216.150.118'}})['sip']), 
        #                4540, msg="Summary source IPs value mismatch. Wrong number of expected values returned.")

class TestWebMultipleFields(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/webhoneypot-2024-02-24.json"

        url_header_data = dshield_parser.utils.json.get_json_values(["sip", "url", "headers"], logfile)

        # cat webhoneypot-2024-02-24.json | jq -r '. | [.sip, .url, .headers.["user-agent"]] | @csv' | sort | uniq -c

        # should have 22 entries
        # cat webhoneypot-2024-02-24.json | jq -r '. | [.sip, .url, .headers.["user-agent"]] | @csv' | sort | uniq -c | wc -l 

        df = pd.DataFrame(url_header_data)
        df["user-agent"] = df["headers"].str['user-agent']
        df = df.drop("headers", axis=1)
        df = df.groupby(df.columns.tolist(),as_index=False, dropna=False).size()

        #with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        #   print(df)
        self.assertEqual(len(df), 22)


class TestCowrieMultipleFields(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/cowrie.json.2024-02-24"

        cowrie_data = dshield_parser.utils.json.get_json_values(["src_ip", "dst_port", "input"], logfile)

        # cat cowrie.json.2024-02-24 | jq -r '. | [.src_ip, .dst_port, .message] | @csv' | sort | uniq -c

        # should have 180 entries
        # cat cowrie.json.2024-02-24 | jq -r '. | [.src_ip, .dst_port, .message] | @csv' | sort | uniq -c | wc -l 

        df = pd.DataFrame(cowrie_data)
        df = df.groupby(df.columns.tolist(),as_index=False, dropna=False).size()

        #with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        #    print(df)
        self.assertEqual(len(df), 180)

class TestFirewallMultipleFields(unittest.TestCase):
    def test_correct(self):
        logfile = "dshield_parser/test/honeypotdata/aws/local_copy.log"

        firewall_data = dshield_parser.utils.json.get_json_values(["sip", "dip", "dport"], logfile)

        # cat local_copy_2024-02-24.log | sed "s/},/}\\n/$m;P;D"  | sed "s/\[/\\n/$m;P;D" | sed "s/\]/\\n/$m;P;D" | awk '{$1=$1};1' | sed -ne '/^{"time/p' | jq -r '. | [.sip, .dip, .dport, .flags] | @csv' | sort | uniq -c

        # should have 4362 entries
        # cat local_copy_2024-02-24.log | sed "s/},/}\\n/$m;P;D"  | sed "s/\[/\\n/$m;P;D" | sed "s/\]/\\n/$m;P;D" | awk '{$1=$1};1' | sed -ne '/^{"time/p' | jq -r '. | [.sip, .dip, .dport, .flags] | @csv' | sort | uniq -c | wc -l 

        df = pd.DataFrame(firewall_data)
        df = df.groupby(df.columns.tolist(),as_index=False, dropna=False).size()

        #with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
        #    print(df)
        self.assertEqual(len(df), 4362)


if __name__ == "__main__":
    unittest.main()



