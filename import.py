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


import os
import sys
import csv
from datetime import datetime
import time
import getopt
import re
from pprint import pprint

import dbapp
#scanner maps
from scannermaps import *

class CVSVulnImporter():
    """Import a CSV from Qualy/Nessus and then load into database for processing"""

    def __init__(self,filename=None,scanner_type="qualys", scan_scope="unkown"):

        #FIXME: I abuse self
        self.csv_filename=filename
        self.reference_vulnscan_mapper=None
        self.reference_vulnscan_headers=None
        self.min_severity_level=float(3)
        self.scanrun_id=None
        self.scantype_id=None
        self.scanrun_launch_date=None
        self.scanrun_title=None

        #user tuneable settings
        self.scanner_type=scanner_type
        self.scan_scope=scan_scope

        #The db connections
        self.dbconn_scan_type=dbapp.ScanType()
        self.dbconn_scan_run=dbapp.ScanRun()
        self.dbconn_scan_results=dbapp.ScanResult()
        self.dbconn_issue_status=dbapp.ScanIssues()

        #used later to parse the results after insertion
        self.db_insert_ids={}


    def setup_scanner_specifics(self, scanner_type=None):
        """Build out a key,value mapping of csv headers to db column names"""

        #Set the scanner type based on filename, can be overriden later
        if scanner_type:
            self.scanner_type=scanner_type.lower()
        else:
            if "nessus" in self.csv_filename.lower():
                self.scanner_type="nessus"
            elif "qualys" in self.csv_filename.lower():
                self.scanner_type="qualys"

        #Set the headers and mapings if needed
        if self.scanner_type.lower() == "qualys":
            self.reference_vulnscan_mapper=dbmap_qualys_mapping
            self.reference_vulnscan_headers=dbmap_qualys_csv_headers
            self.scanner_type="qualys"
        elif self.scanner_type.lower() == "nessus":
            self.reference_vulnscan_mapper=dbmap_nessus_mapping
            self.scanner_type="nessus"
        else:
           sys.stderr.write("ERROR: Unable to determine scanner type from file\n" )
           sys.stderr.write("ERROR: Check --help for flag to explicitly declare\n" )
           sys.exit(1)

        #GDC_Qualys_VMs_25JAN17
        filename_re=re.compile('([a-zA-Z]+)_([a-zA-Z]+)_([a-zA-Z0-9]+)_(\d+)([a-zA-Z]+)(\d+)\.csv', re.IGNORECASE)
        instance=filename_re.search(self.csv_filename).group(1)
        scanner=filename_re.search(self.csv_filename).group(2)
        scope=filename_re.search(self.csv_filename).group(3)
        day=filename_re.search(self.csv_filename).group(4)
        month=filename_re.search(self.csv_filename).group(5)
        year=filename_re.search(self.csv_filename).group(6)

        title=instance + " " + scanner + " " + scope

        #Set the launch date 
        ## Qualys stores this in the file itself and will be overwritten to that value
        ## OTherwise namign convention suckage
        self.scanrun_launch_date = datetime.strptime("%s %s %s"%(day,month,year), "%d %b %y")

        #Set the scope
        self.scan_scope=scope

        #Set the title
        self.scanrun_title=title


    def commit_scan_results_records(self):
        """ I am silly, the records dont get commited till all ready to go"""
        self.dbconn_scan_run.commit_records()

    def import_csv(self):
        """ This function pulls everything to gethor and is what should be called"""
        self.setup_scanner_specifics()
        if self.scanner_type.lower() == "qualys":
            vulnimporter.parse_qualys_csv()
        elif self.scanner_type.lower() == "nessus":
            vulnimporter.parse_nessus_csv()

    def insert_scan_run_record(self, row):
        """ Create the ScanRun db entry 
            takes a row of k,v mapped to db
            Returns dict of run id """
        # Stupid way to remove excess fields and find run type id
        ## Will create new entry if None found
        scan_type_column_names = self.dbconn_scan_type.get_column_names()
        scan_type_row = {k:v for k,v in row.items() if k in scan_type_column_names}
        self.scantype_id=self.dbconn_scan_type.get_or_create_id( row=scan_type_row )

        # Generate the run row
        scan_run_column_names = self.dbconn_scan_run.get_column_names()
        scan_run_row = {k:v for k,v in row.items() if k in scan_run_column_names}
        scan_run_row['scantype_id']=self.scantype_id
        scanrun_info = self.dbconn_scan_run.insert_row( row=scan_run_row )
        self.scanrun_id=scanrun_info['id']


    def insert_scan_results_record(self, row):
        """ Rake the row from parsed CSV, and convert to sql insert """
        sql_row=dict()

        #Convert the CSV format, to DB expected format
        for db_key,csv_key in self.reference_vulnscan_mapper.items():
            sql_row[db_key] = row[csv_key]

        #Add additional fields to reference other tables
        ## I am doing this wrong
        sql_row['scanrun_id']=self.scanrun_id
        #pprint(sql_row['scanrun_id'])

        #Inesert into database
        row_info=self.dbconn_scan_results.insert_row( row=sql_row )
    
        #Keep a running dict of the ids inserted of scan_results
        #if str(row_info['hash']) not in self.db_insert_ids.keys():
        #    self.db_insert_ids[str(row_info['hash'])]=list() 
        #self.db_insert_ids[str(row_info['hash'])].append(row_info['id'])
        self.db_insert_ids[str(row_info['hash'])]={
            'scanrun_id': self.scanrun_id,
            'scantype_id': self.scantype_id,
            'launch_date': self.scanrun_launch_date,
            }
            
    def parse_qualys_csv(self):
        """ Parses inpute 'filename', discarding anything not a Vuln and Severity > 3 """
        # Open File
        # Assumes specific field headers
        with open(self.csv_filename, 'rt') as csvfile:
            reader = csv.DictReader(csvfile, quotechar='"',  fieldnames=self.reference_vulnscan_headers)
  
            #stupid flow control 
            launch_header_found = None
            lauch_header_processed = None

            for title_row in reader:
                if set(self.reference_vulnscan_headers) == set(list( title_row.values() )):
                    #print( "DEBUG: Fnd Start of Results" )
                    break
                elif "Launch Date" in list( title_row.values() ) and not launch_header_found :
                    launch_header_found = True
                    continue
                elif launch_header_found and not lauch_header_processed:
                    #The  following key values are jankey becasue of csv.DictReader
                    # Open the csv in excel and confirm the fields manually if changes
                    # needed to accomidate a new file format :(A
                    #01/08/2017 at 04:01:30 (GMT-0600)
                    #FIXME: sys.version_info will let me detect python2 vs pyhton3, and then use differnt strptime
                    self.scanrun_launch_date=datetime.strptime( title_row['IP'], '%m/%d/%Y at %H:%M:%S (GMT%z)' )
                    self.scanrun_title=title_row['Severity']
                    scan_run_row={
                        "launch_date": self.scanrun_launch_date,
                        "scan_title": self.scanrun_title,
                        "scanner_type": self.scanner_type,
                        "scan_scope": self.scan_scope,
                        "filename": self.csv_filename,
                    }
                    #So we dont try reprocessing
                    lauch_header_processed=True
        
                    #Insert the scanrun record into the db
                    ## It used to return info, that is now directly set as a self.scanrun_id
                    self.insert_scan_run_record( row=scan_run_row )
                    #scanrun_info=self.insert_scan_run_record( row=scan_run_row )
                    #self.scanrun_id=scanrun_info['id']
                else:
                    continue
    
            #Grab real values
            for row in reader:
                if row['Type'] == 'Vuln':
                    if float(row['Severity']) >= self.min_severity_level:
                        self.insert_scan_results_record( row=row  )

            self.update_issue_status()

    def parse_nessus_csv(self):
        """ Parses inpute 'filename', discarding anything not a Vuln and Severity > 3 """

        #stupid flow control
        launch_header_found = None

        scan_run_row={
            "launch_date": self.scanrun_launch_date,
            "scan_title": self.scanrun_title,
            "scanner_type": self.scanner_type,
            "scan_scope": self.scan_scope,
            "filename": self.csv_filename,
        }
        #Insert the scanrun record into the db
        ## It used to return info, that is now directly set as a self.scanrun_id
        self.insert_scan_run_record( row=scan_run_row )


        # Open File
        # Assumes specific field headers
        with open(self.csv_filename, 'rt') as csvfile:
            #reader = csv.DictReader(csvfile, quotechar='"',  fieldnames=self.reference_vulnscan_headers)
            reader = csv.DictReader(csvfile, quotechar='"')

            #Grab real values
            for row in reader:
                #NVD Vulnerability Severity Ratings
                #NVD provides severity rankings of "Low," "Medium," and "High" in addition to the numeric CVSS scores
                #but these qualitative rankings are simply mapped from the numeric CVSS scores:
                #1. Vulnerabilities are labeled "Low" severity if they have a CVSS base score of 0.0-3.9.
                #2. Vulnerabilities will be labeled "Medium" severity if they have a base CVSS score of 4.0-6.9.
                #3. Vulnerabilities will be labeled "High" severity if they have a CVSS base score of 7.0-10.0.
                ##
                ## We map the CVSS to the 1-5 scale
                ## 
                if row['CVSS']:
                    if float(row['CVSS']) < 2.0:
                        row['CVSS'] = "1.0"
                    elif float(row['CVSS']) < 3.9:
                        row['CVSS'] = "2.0"
                    elif float(row['CVSS']) < 6.9:
                        row['CVSS'] = "3.0"
                    elif float(row['CVSS']) < 8.0:
                        row['CVSS'] = "4.0"
                    elif float(row['CVSS']) < 10.0:
                        row['CVSS'] = "5.0"
                    else:
                        row['CVSS'] = 666.0

                    if float(row['CVSS']) >= self.min_severity_level:
                        self.insert_scan_results_record( row=row  )

            self.update_issue_status()



    def update_issue_status(self):
        """ This goes through self.db_inert_ids and the vuln_status db and
            marks things NEW, REOPENED, CLOSED, ONGOING
        """
        self.dbconn_issue_status.update_status(self.db_insert_ids)

    def print_issue_report(self):
        """ Print out a report of issues in a csv like format 

            New:
            X,X,X,X,X,X,X

            Closed:
            Y,Y,Y,Y,Y,Y,Y

            Ongoing:
            Z,Z,Z,Z,Z,Z

        """
        #new_issues=self.dbconn_issue_status.get_issues(statuses=["new"], scantype_ids=[self.scantype_id])
        #These pull all results regardless of scan run
        ## New means new for that scan run, so import three types of scans
        ## and all three results will show up as new
        new_issues=self.dbconn_issue_status.get_issues(statuses=["new"])
        reopened_issues=self.dbconn_issue_status.get_issues(statuses=["reopened"])
        ongoing_issues=self.dbconn_issue_status.get_issues(statuses=["open"])

        #print headers
        print( '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"' % (
            'ip',
            'severity',
            'status',
            'protocol',
            'port',
            'title',
            'qid',
            'cveid',
            'bugtrackid',
            'pcivuln',
            'results',
            'hash',
            'scantype'
            )
        )
        if new_issues:
            new_scanresults=self.dbconn_scan_results.get_results_by_hash(new_issues.keys())
            #print( "New Issues" )
            for k,v in new_scanresults.items():
                self.print_csv_row( row=v, status="new" )

        if reopened_issues:
            reopened_scanresults=self.dbconn_scan_results.get_results_by_hash(reopened_issues.keys())
            #print( "Reopened Issues" )
            for k,v in reopened_scanresults.items():
                self.print_csv_row( row=v, status="reopened")

        if ongoing_issues:
            ongoing_scanresults=self.dbconn_scan_results.get_results_by_hash(ongoing_issues.keys())
            #print( "Ongoing Issues" )
            for k,v in ongoing_scanresults.items():
                v['hash']=k
                self.print_csv_row( row=v , status="ongoing")


    def print_csv_row(self, row, status):
        """ Take a dict, print a line """
        print( '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"' % (
            row['ip'],
            row['severity'],
            status,
            row['protocol'],
            row['port'],
            row['title'],
            row['qid'],
            row['cveid'],
            row['bugtrackid'],
            row['pcivuln'],
            row['results'].replace('"',"'"),
            row['_hash'],
            row['scanrun_id']
            )
        )

       
 
if __name__ == "__main__":

    debug=False
    filename=None
    run=False
    printcsv=False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["help","debug", "file=", "filename=","scanner=","print"])
    except getopt.GetoptError:
        sys.stderr.write("ERROR: Getopt\n")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("--debug","-d"):
            debug = True
        elif opt in ("--help","-h"):
            print( """ Program takes 1 required arg --file .  
                ## Can also take --scanner=[qualys|nessus] as an optional arg
                Currently it will import the files passed to it and error out 
                if it finds what it thinks is the same file
                """)
            sys.exit(0)
        elif opt in ("--file","--filename","-f"):
            filename = arg
            run=True
        elif opt in ("--print","-p"):
            printcsv=True


    #vulnimporter=CVSVulnImporter(filename='testcsvs/GDC_Qualys_Internal_18JAN17-short.csv',scanner_type="qualys")
    #vulnimporter=CVSVulnImporter(filename='testcsvs/GDC_Qualys_Internal_18JAN17.csv',scanner_type="qualys")
    
    vulnimporter=CVSVulnImporter(filename=filename)
    if run:
        vulnimporter.import_csv()
    if printcsv:
        vulnimporter.print_issue_report()


