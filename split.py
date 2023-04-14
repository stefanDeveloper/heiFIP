import fnmatch
import os
import re

from heifip.splitter import PcapSplitter

output_dir = "/home/smachmeier/data/test-data"
input_dir = "/home/smachmeier/data/test-pcaps"
orientation = {
    "Cridex": "malware",
    "Htbot": "malware",
    "Geodo": "malware",
    "Miuref": "malware",
    "Neris": "malware",
    "Nsis-ay": "malware",
    "Shifu": "malware",
    "Tinba": "malware",
    "Virut": "malware",
    "Weibo": "malware",
    "Zeus": "malware",
    "BitTorrent": "benign",
    "Facetime": "benign",
    "FTP": "benign",
    "Gmail": "benign",
    "MySQL": "benign",
    "Outlook": "benign",
    "Skype": "benign",
    "SMB": "benign",
    "WorldOfWarcraft": "benign"
}

for root, dirnames, filenames in os.walk(input_dir):
    for filename in fnmatch.filter(filenames, "*.pcap"):
        match = os.path.join(root, filename)
        sub_dir = match.replace(input_dir, "")
        # sub_dir = re.sub("(-[0-9])?.pcap", "", sub_dir)
        # sub_dir = sub_dir.replace("/", "")
        # print(sub_dir.split('/')[1])
        # sub_dir = "malware"
        # sub_dir = orientation[sub_dir]
        if not os.path.exists(f"{output_dir}/{sub_dir}"):
            try:
                os.makedirs(f"{output_dir}/{sub_dir}")
            except:
                pass
        ps = PcapSplitter(match)
        # ps.split_by_count(10000, "/home/smachmeier/data/test-pcaps", pkts_bpf_filter="ip and (tcp or udp) and not (port 67 or port 68 or port 546 or port 547)")
        ps.split_by_session(f"{output_dir}/{sub_dir.split('/')[1]}", pkts_bpf_filter="ip and (tcp or udp) and not (port 67 or port 68 or port 546 or port 547)")

