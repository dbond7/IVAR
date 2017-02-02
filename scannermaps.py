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
