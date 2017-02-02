#   Copyright 2017 Center for Data Intensive Science
#   Author Ray Powell <rpowell1@uchicago.edu>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


dbmap_qualys_mapping={
    "ip": "IP",
    "os": "OS",
    "qid": "QID",
    "title": "Title",
    "severity":"Severity",
    "port": "Port",
    "protocol": "Protocol",
    "fqdn": "FQDN",
    "ssl": "SSL",
    "cveid": "CVE ID",
    "vendorref": "Vendor Reference",
    "bugtrackid": "Bugtraq ID",
    "results": "Results",
    "pcivuln": "PCI Vuln",
    }
dbmap_qualys_csv_headers=[ "IP","DNS","NetBIOS","OS","IP Status","QID","Title","Type","Severity","Port","Protocol","FQDN","SSL","CVE ID","Vendor Reference","Bugtraq ID","CVSS Base","CVSS Temporal","CVSS3 Base","CVSS3 Temporal","Threat","Impact","Solution","Exploitability","Associated Malware","Results","PCI Vuln","Instance","OS CPE","Category"]
dbmap_qualys_csv_scanrun_headers=[ "Launch Date","Active Hosts","Total Hosts","Type","Status","Reference","Scanner Appliance","Duration","Scan Title","Asset Groups","IPs","Excluded IPs","Option Profile" ]

dbmap_nessus_mapping={
    "ip": "Host",
    "cveid": "CVE",
    "severity":"CVSS",
    "protocol": "Protocol",
    "port": "Port",
    "title": "Name",
    "results": "Plugin Output",
    }
dbmap_nessus_csv_headers=[ "Plugin ID","CVE","CVSS","Risk","Host","Protocol","Port","Name","Synopsis","Description","Solution","See Also","Plugin Output"]
