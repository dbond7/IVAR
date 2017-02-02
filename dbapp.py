#http://pythoncentral.io/introductory-tutorial-python-sqlalchemy/
import os
import sys

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, VARCHAR, Time, SmallInteger, Enum, Boolean, Numeric, UniqueConstraint, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship,sessionmaker
from sqlalchemy import create_engine

import hashlib

from pprint import pprint

Base = declarative_base()
engine = create_engine('sqlite:///vuln_issue.db')
Base.metadata.bind = engine
DBSession = sessionmaker()
scantype_session = DBSession()
scanrun_session = DBSession()
scanresult_session = DBSession()
scanissues_session = DBSession()


class ScanType(Base):
    __tablename__ = 'scantypes'
    __table_args__ = (UniqueConstraint( 'scanner_type',
                                        'scan_scope',
                                        'scan_title',
                                        name='uniq_scantype'),)
    id = Column(Integer,primary_key=True,unique=True)
    #Qualy, Nessus, ETc
    scanner_type = Column(VARCHAR(64))
    #Internal, External, Etc
    scan_scope = Column(VARCHAR(64)) 
    #Taken from scanner, no real fmt guarentueed
    scan_title = Column(VARCHAR(256)) 


    def get_column_names(self):
        return self.__table__.columns.keys()

    def get_or_create_id(self, row):
        """ Will return ID for scan type, will create one if doesnt exist """
        #Check if their is an entry. Assuming there is only one, otherwise :(
        scan_type_query = scantype_session.query(ScanType).filter_by(**row).one_or_none()
        #If no result, then insert it
        if not scan_type_query:
            inserted_scantype=ScanType( **row )
            scantype_session.add( inserted_scantype )
            scantype_session.commit()
            return inserted_scantype.id
        #if there is a result then return the ID of the row
        else:
           return scan_type_query.id

    def insert_row(self, row):
        """ row is a dict of key/values wher
            key = Column Headers/Names
            value = Values
        """
        new_scantype=ScanType( **row )
        scantype_session.add( new_scantype )



class ScanRun(Base):
    __tablename__ = 'scanruns'
    __table_args__ = (UniqueConstraint('launch_date',
                                        'scantype_id',
                                        name='uniq_scanrun'),)
    id = Column(Integer,primary_key=True,unique=True)
    #Time scan started, not confused with when published/finsihed
    launch_date=Column(DateTime)
    #optional, because why not
    filename = Column(VARCHAR(256))
    #map foriegn key to scanruns table
    scantype_id = Column(Integer, ForeignKey('scantypes.id'))
    scantype = relationship(ScanType)

    def commit_records(self):
        scanrun_session.commit()
    
    def get_column_names(self):
        return self.__table__.columns.keys()

    def insert_row(self, row):
        """ row is a dict of key/values wher
            key = Column Headers/Names
            value = Values
        """ 
        new_run=ScanRun( **row )
        exists = scanrun_session.query(ScanRun.id).filter_by( **row ).scalar() is not None
        if not exists:
            scanrun_session.add( new_run )
            scanrun_session.commit()
        else:
            # FIXME: Scan Run already exists, duplicate, need to handle this
            #print( "ERROR: ScanRun already Exists...Exiting")
            sys.stderr.write("ERROR: ScanRun already Exists...Exiting\n" )
            sys.exit(1)
            pass

        return { 'id': new_run.id }
        

class ScanResult(Base):
    __tablename__ = 'scanresults'

    id = Column(Integer, primary_key=True)
    ip = Column(VARCHAR(16))
    #ip = Column(Integer)
    # from IPy import IP
    # ip_dotted = str(IP(ip_dec))
    #netbios=Column(VARCHAR(64))
    os = Column(VARCHAR(64))
    qid = Column(Integer)
    title = Column(VARCHAR(256))
    severity = Column(Float)
    port = Column(Integer)
    protocol = Column(VARCHAR(8))
    fqdn = Column(VARCHAR(256))
    ssl = Column(VARCHAR(10))
    cveid = Column(VARCHAR(64))
    vendorref = Column(VARCHAR(256))
    bugtrackid = Column(VARCHAR(256))
    #cvssbase
    #cvsstemporal
    #cvss3base
    #threat <- LONG
    #impact <-Long
    #exploitability
    #results
    #associatedmalware
    results = Column(VARCHAR(256))
    pcivuln = Column(VARCHAR(10))
    #instance
    #oscpe
    category = Column(VARCHAR(64))
    _hash = Column(VARCHAR(256))

    #map foriegn key to scanruns table
    scanrun_id = Column(Integer, ForeignKey('scanruns.id'))
    scanrun = relationship(ScanRun)
   
    def get_results_by_hash(self, vuln_hashes):
        """ Takes a list of vuln hashes and returns the results for them """ 

        found_results={}

        #This might get jankey, id prefer if there was away to select last query
        for vuln_hash in vuln_hashes:
            results=scanresult_session.query(ScanResult).filter(
                        ScanResult._hash ==  vuln_hash,
                    ).all()
            result = results[-1].__dict__
            del result['_sa_instance_state']
            del result['_hash']
            found_results[vuln_hash]=result

        return found_results


    def insert_row(self, row):
        """ row is a dict of key/values wher
            key = Column Headers/Names, value = Values
            Returns: Dict of new record's unique row id and generated hash function  
        """ 
        new_result=ScanResult( **row )
        new_result._hash = hashlib.sha512(str(new_result.ip+new_result.title+new_result.severity+new_result.port+new_result.protocol).encode('utf-8')).hexdigest()
        scanresult_session.add( new_result )
        scanresult_session.commit()
        return { 'id': new_result.id, 'hash': new_result._hash }


class ScanIssues(Base):
    """ List of open, closed, ongoing, repopened Issues from scan result """
    __tablename__ = 'scanissues'

    id = Column(Integer, primary_key=True)
    #first_detected=Column(DateTime)
    #last_detected=Column(DateTime)
    status = Column(VARCHAR(32))
    #map foriegn key to scanruns table
    vuln_hash = Column(VARCHAR(256), ForeignKey('scanresults.id'))
    scantype_id = Column(Integer, ForeignKey('scantypes.id'))
    scan_result = relationship(ScanResult)
    scantype = relationship(ScanType)


    def get_issues(self, statuses, scantype_ids=None):
        """ Get issues of a status type
             status=['open','closed', 'new']
             scantype_ids=[] of scantype ids 
                For somereason i did this as a list of ids instead of one id   

            Returns a dict of the issue table for those statuses, because i dont know orm joins yet
        """
        #Closing all remaining issues for scantype
        if scantype_ids:
            issues=scanissues_session.query(ScanIssues).filter(
                    ScanIssues.status.in_( statuses ),
                    ScanIssues.scantype_id.in_( scantype_ids )
                ).all()
        else:
            issues=scanissues_session.query(ScanIssues).filter(
                    ScanIssues.status.in_( statuses ),
                ).all()

        issues_dict=dict()
        for issue in issues:
            issues_dict[issue.vuln_hash]={
                'id': issue.id,
                'status': issue.status,
                'vuln_hash': issue.vuln_hash,
            }

        return issues_dict
                

    def insert_new_issues( self, issues, result_hashes):
        #For new Issues add new entries
        for issue  in issues:
            row = {
                #'first_detected': result_hashes[issue]['launch_date'],
                #'last_detected': result_hashes[issue]['launch_date'],
                'status': 'new',
                'scantype_id': result_hashes[issue]['scantype_id'],
                'vuln_hash': issue,
            }
            inserted_scanissue=ScanIssues( **row )
            scanissues_session.add( inserted_scanissue )
            scanissues_session.commit()


    def update_existing_issues( self, issues, status):
        #For new Issues add new entries
        scanissues_session.query(ScanIssues).filter(
                ScanIssues.vuln_hash.in_( issues )
            ).update(
                {
                    'status': status, 
                },
                synchronize_session=False,
            )
        scanissues_session.commit()


    def update_status(self, result_hashes):
        """  Take dict of format {hash, [result_ids]} of scan result hashes and find status of each """
        list_of_scanresult_hashes=[ k for k,v in result_hashes.items() ] 
        #FIXME:  this should be only 1 scantype per import, so not sure why im not just passing it
        list_of_scantype_ids=[ v['scantype_id'] for k,v in result_hashes.items() ] 
        open_ongoing_states=['reopened', 'open', 'new']

        #Want them to exist but be blank
        reopening_issues=[]
        ongoing_issues=[]
   
        #Closing all remaining issues for scantype
        if list_of_scantype_ids:
            all_open_issues_tuple=scanissues_session.query(ScanIssues.vuln_hash).filter(
                ScanIssues.status.in_( open_ongoing_states ),
                ScanIssues.scantype_id.in_( list_of_scantype_ids )
                ).all() 
            all_open_issues=[ t[0] for t in all_open_issues_tuple ]
            closing_issues=set(all_open_issues) - set(list_of_scanresult_hashes)
            if closing_issues:
                self.update_existing_issues( issues=closing_issues,status="closed" )

        if list_of_scantype_ids and list_of_scanresult_hashes:
            ongoing_issues_tuple=scanissues_session.query(ScanIssues.vuln_hash).filter(
                ScanIssues.vuln_hash.in_( list_of_scanresult_hashes ),
                ScanIssues.status.in_( open_ongoing_states ),
                ScanIssues.scantype_id.in_( list_of_scantype_ids )
                ).all() 
            ongoing_issues=[ t[0] for t in ongoing_issues_tuple ]
            if ongoing_issues:
                self.update_existing_issues( issues=ongoing_issues,status="open" )
       
        if list_of_scanresult_hashes and list_of_scantype_ids:
            reopening_issues_tuple=scanissues_session.query(ScanIssues.vuln_hash).filter(
                ScanIssues.vuln_hash.in_( list_of_scanresult_hashes ),
                ScanIssues.status == 'closed',
                ScanIssues.scantype_id.in_( list_of_scantype_ids )
                ).all() 
            reopening_issues=[ t[0] for t in reopening_issues_tuple ]
            if reopening_issues:
                self.update_existing_issues( issues=reopening_issues,status="reopened" )

        #List of New Issues
        new_issues=set(list_of_scanresult_hashes) - set(reopening_issues) - set(ongoing_issues)
        self.insert_new_issues( issues=new_issues, result_hashes=result_hashes)


if __name__ == "__main__":
    # Create an engine that stores data in the local directory's
    # sqlalchemy_example.db file.
    engine = create_engine('sqlite:///vuln_issue.db')
     
    # Create all tables in the engine. This is equivalent to "Create Table"
    # statements in raw SQL.
    Base.metadata.create_all(engine)
