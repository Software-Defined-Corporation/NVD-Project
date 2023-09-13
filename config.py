#config.py
#-*- coding:utf-8 -*-
from datetime import date
from datetime import timedelta
API_KEY = "ea89362d-1bb9-43ce-8ad1-b88b1245c287"
RESULTS_PER_PAGE = 20
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
VENDORS = ['microsoft', 'cisco', 'fortinet', 'paloaltonetworks', 'juniper', 'oracle', 'vmware', 'adobe',\
           'sonicwall', 'adtran', 'extremenetworks', 'dell', 'nutanix', 'emc', 'aerohive']
CVSSV3_SEVERITY = ['LOW','MEDIUM','HIGH','CRITICAL']
DEFAULT_BASE_SCORE = 7.9
LOG_FILE_NAME = 'Jocelynne.log'

#Example URL for NVD Rest API Endpoint 
#https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2021-08-04T13:00:00.000%2B01:00&lastModEndDate=2021-10-22T13:36:00.000%2B01:00

#Set modifiedStartDate as 90 days ago
MODIFIED_START_DATE = (date.today() - timedelta(days=90))
MODIFIED_END_DATE = date.today()
FORMATTED_MODIFIED_END_DATE = MODIFIED_END_DATE.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
FORMATTED_MODIFIED_START_DATE = (date.today() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] 
MINIMUM_BASE_SCORE = 7.9

SMTP_SERVER = 'outbound-us1.ppe-hosted.com'
SMTP_PORT = 587 
SMTP_LOGIN = 'lanaircve@lanairgroup.com' 
SMTP_SECRET = '7stetdxG5d$?g5hB'
SMTP_SENDER = 'lanaircve@lanairgroup.com'
SMTP_RECIPIENT = 'ramin@lanairgroup.com'
SMTP_SUBJECT = 'CVE Alert'
MAX_EMAILS_PER_INSTANCE = 50

#MySQL Parameters
MYSQL_HOST = 'localhost'
MYSQL_USER = 'wordpress'
MYSQL_SECRET = 'lucRea7on'
MYSQL_DB = 'cve_database'

#Archiving Parameters
NUMBER_OF_YEARS_TO_ARCHIVE = 5