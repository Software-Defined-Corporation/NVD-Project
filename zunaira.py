import requests
import pymysql
import json
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import config

# Set up logging
logging.basicConfig(filename=config.LOG_FILE_NAME, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

#Database schema:
#CVE_Items
#ID, ASSIGNER, problemtype_data, description_lang, description_value, url, name, refsource, tags, publishedDate, lastModifiedDate

#CVSSV3
#ID, version, vectorString, attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore

#Configurations
#ID, operator, vulnerable, cpe22Uri, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding
#Function to query NVD API

def convert_datetime_format(dt_string):
    nvd_format = "%Y-%m-%dT%H:%MZ"
    mysql_format = "%Y-%m-%d %H:%M:%S"
    dt_obj = datetime.strptime(dt_string, nvd_format)
    return dt_obj.strftime(mysql_format)

def send_digest_email():
    smtp_server = config.SMTP_SERVER 
    smtp_port = config.SMTP_PORT
    login = config.SMTP_LOGIN
    password = config.SMTP_SECRET 
    
    sender = config.SMTP_SENDER 
    recipient = config.SMTP_RECIPIENT 
    subject = config.SMTP_SUBJECT 
    message = 'A new CVE record has been posted to the database.'

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'html'))

    #Retrieve the CVE record from the database that has isNew = TRUE
    db = pymysql.connect(host=config.MYSQL_HOST, user=config.MYSQL_USER, password=config.MYSQL_SECRET, database=config.MYSQL_DB)
    if db is None:
        #print("Error connecting to database")
        logging.error("Error connecting to database")
        return
    else:
        #print("Database connection successful")
        logging.info("Database connection successful")

    cursor = db.cursor()

    #Retrieve the CVE record of the records in CVE_Items that has isNew = TRUE, including lastModifiedDate, publishedDate, baseScore, baseSeverity, cpe23Uri
    sql = """SELECT CVE_Items.ID, CVE_Items.description_value, CVE_Items.publishedDate, CVE_Items.lastModifiedDate, CVSSV3.baseScore, CVSSV3.baseSeverity
        FROM CVE_Items
        INNER JOIN CVSSV3 ON CVE_Items.ID = CVSSV3.ID
        WHERE CVE_Items.isNew = TRUE
        ORDER BY CVE_Items.lastModifiedDate DESC"""

    #print ("Executing query : ", sql)
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        length_of_results = len(results)
        if len(results)>config.MAX_EMAILS_PER_INSTANCE or length_of_results==0:
            #print ("Too many CVEs to send in one email")
            logging.error("Too many CVEs to send in one emmail")
            logging.error(length_of_results)
            #Send an email that too many CVEs were found
            html_message = """\
            <html>
            <head></head>
            <body>
                <p>Hi!<br>
                <br>
                Too many CVEs were found. Please check the database.<br>
                <br>
                Sincerely,<br>
                CVE Notifier<br>

                LANAIR Technology Group<br>
                Date: """ + str(datetime.now()) + """<br>
                </p>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_message, 'html'))
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(login, password)
            server.send_message(msg)
            server.quit()
            return
        
        for row in results:
            cve_id = row[0]
            description_value = row[1]
            publishedDate = row[2]
            lastModifiedDate = row[3]
            baseScore = row[4]
            baseSeverity = row[5]
            #print ("CVE ID: ", cve_id)
            # Send an email for each CVE record

            # Send an email that a CVE was updated
            # Send an email that a CVE was deleted
            # Send an email that a CVE was marked as obsolete
            # Send an email that a CVE was marked as reserved
            # Send an email that a CVE was marked as rejected
            # Send an email that a CVE was marked as duplicate
            # Send an email that a CVE was marked as withdrawn
            # Send an email that a CVE was marked as candidate
            # Send an email that a CVE was marked as entry
            # Send an email that a CVE was marked as rejected
            # Send an email that a CVE was marked as reserved
            # Send an email that a CVE was marked as obsolete 
            # Send an email that a new CVE was found
            html_message = """\
            <html>
            <head></head>
            <body>
                <p>Hi!<br>
                <br>
                A new CVE record has been posted to the database.<br>
                <br>
                CVE ID: """ + cve_id + """<br>
                Description: """ + description_value + """<br>
                Published Date: """ + str(publishedDate) + """<br>
                Last Modified Date: """ + str(lastModifiedDate) + """<br>
                Base Score: """ + str(baseScore) + """<br>
                Base Severity: """ + str(baseSeverity) + """<br>
                <br>
                Sincerely,<br>
                CVE Notifier<br>

                LANAIR Technology Group<br>
                Date: """ + str(datetime.now()) + """<br>
                </p>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_message, 'html'))
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(login, password)
            server.send_message(msg)
            server.quit()
            return



    except Exception as e:
        #print ("Error executing SQL query: ", e)
        logging.error("Error executing SQL query: ", e)
        return
    finally:
        db.close()
    #

    #print ("Executing SQL query: ", sql)
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(login, password)
        server.send_message(msg)
        server.quit()
        print('Email sent successfully.')
        logging.info('Email sent successfully.')

    except Exception as e:
        #print('Error sending email: ', e)
        logging.error('Error sending email: ')
        logging.error(e)


def query_nvd_api(vendor):
    # Query NVD API for CVEs
    baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    params = {'ResultsPerPage': config.RESULTS_PER_PAGE, 'apiKey' : config.API_KEY, 'cpeMatchString': f'cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*'}
    #print("Querying: ", baseUrl, params)
    logging.info("Querying: ", baseUrl, params)
    try:
        response = requests.get(baseUrl, params=params)
        response.raise_for_status()
        response_json = response.json()
        if response_json['totalResults'] == 0:
            #print("Empty response")
            logging.warning("Empty response")
            response_json = [];
        return response_json
    except requests.exceptions.RequestException as e:
        #print("Error querying API: ", e)
        logging.error("Error querying API: ", e)
        return None
    except json.JSONDecodeError as e:
        #print("Error decoding response: ", e)
        logging.error("Error decoding response: ", e)
        return None
    

# Function to insert data into database
def insert_data(json_data_list):
    #print("Inserting data into database...")
    logging.info("Inserting data into database...")
    db = pymysql.connect(host="localhost", user="wordpress", password="lucRea7on", database="cve_database")
    if db is None:
        #print("Error connecting to database")
        logging.error("Error connecting to database")
        return
    else: 
        #print("Database connection successful")
        logging.info("Database connection successful")

    cursor = db.cursor()
    #print ("DEMO MODE IS ON...refreshing database")
    #cursor.execute("DELETE FROM Configurations")
    #cursor.execute("DELETE FROM CVSSV3")
    #cursor.execute("DELETE FROM CVE_Items")
    try:
        for json_data in json_data_list:
            for item in json_data['result']['CVE_Items']:
                cve_data_meta = item['cve']['CVE_data_meta']
                cve_id = cve_data_meta.get('ID')
                assigner = cve_data_meta.get('ASSIGNER')
                problemtype_data = json.dumps(item['cve']['problemtype'].get('problemtype_data', []))
                description_data = item['cve']['description'].get('description_data', [{}])[0]
                description_lang = description_data.get('lang')
                description_value = description_data.get('value')

                reference_data_list = item['cve']['references'].get('reference_data', [])
                reference_data = json.dumps(reference_data_list)
                refsource = reference_data_list[0].get('refsource') if reference_data_list else None
                tags = json.dumps(item.get('tags', []))

                published_date = item.get('publishedDate')
                if published_date:
                    published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%MZ')
                    formatted_published_date = published_date.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    formatted_published_date = None

                last_modified_date = item.get('lastModifiedDate')
                if last_modified_date:
                    last_modified_date = datetime.strptime(last_modified_date, '%Y-%m-%dT%H:%MZ')
                    formatted_last_modified_date = last_modified_date.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    formatted_last_modified_date = None

                # Insert data into database

                try: 
                    cursor.execute("""\
                            INSERT INTO CVE_Items (ID, ASSIGNER, problemtype_data, description_lang, description_value, url, name, refsource, tags, publishedDate, lastModifiedDate, isNew)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                            """, (cve_id, assigner, problemtype_data, description_lang, description_value, reference_data, cve_id, refsource, tags, formatted_published_date, formatted_last_modified_date))
                    #print ("I would have sent an email here")
                    logging.info("I would have sent an email here")
                except pymysql.err.IntegrityError:
                    # Duplicate record, update it
                    cursor.execute("""\
                            UPDATE CVE_Items SET ASSIGNER = %s, problemtype_data = %s, description_lang = %s, description_value = %s, url = %s, name = %s, refsource = %s, tags = %s, publishedDate = %s, lastModifiedDate = %s, isNew = FALSE
                            WHERE ID = %s
                            """, (assigner, problemtype_data, description_lang, description_value, reference_data, cve_id, refsource, tags, formatted_published_date, formatted_last_modified_date, cve_id))


                # Insert into CVSSV3 table
                base_metric_v3 = item['impact'].get('baseMetricV3', {})
                cvss_v3 = base_metric_v3.get('cvssV3', {})
                version = cvss_v3.get('version')
                vector_string = cvss_v3.get('vectorString')
                attack_vector = cvss_v3.get('attackVector')
                attack_complexity = cvss_v3.get('attackComplexity')
                privileges_required = cvss_v3.get('privilegesRequired')
                user_interaction = cvss_v3.get('userInteraction')
                scope = cvss_v3.get('scope')
                confidentiality_impact = cvss_v3.get('confidentialityImpact')
                integrity_impact = cvss_v3.get('integrityImpact')
                availability_impact = cvss_v3.get('availabilityImpact')
                base_score = cvss_v3.get('baseScore')
                base_severity = cvss_v3.get('baseSeverity')
                exploitability_score = base_metric_v3.get('exploitabilityScore')
                impact_score = base_metric_v3.get('impactScore')
                
                try:
                    cursor.execute("""
                    INSERT INTO CVSSV3 (ID, version, vectorString, attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore, isNew)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                """, (cve_id, version, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, base_score, base_severity, exploitability_score, impact_score))
                except pymysql.err.IntegrityError:
                    # Duplicate record, update it
                    cursor.execute("""
                    UPDATE CVSSV3 SET version = %s, vectorString = %s, attackVector = %s, attackComplexity = %s, privilegesRequired = %s,
                    userInteraction = %s, scope = %s, confidentialityImpact = %s, integrityImpact = %s, availabilityImpact = %s,
                    baseScore = %s, baseSeverity = %s, exploitabilityScore = %s, impactScore = %s, isNew = FALSE
                    WHERE ID = %s
                """, (version, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, base_score, base_severity, exploitability_score, impact_score, cve_id))
                    

            # Insert into Configurations table
                nodes = item['configurations'].get('nodes', [])
                operator = None
                vulnerable = None
                cpe23_uri = None
                version_start_including = None
                version_start_excluding = None
                version_end_including = None
                version_end_excluding = None
                
            for node in nodes:
                operator = node.get('operator',[])
                cpe_match_list = node.get('cpe_match', [])
            for cpe_match in cpe_match_list:
                vulnerable = cpe_match.get('vulnerable')
                cpe23_uri = cpe_match.get('cpe23Uri')
                version_start_including = cpe_match.get('versionStartIncluding')
                version_start_excluding = cpe_match.get('versionStartExcluding')
                version_end_including = cpe_match.get('versionEndIncluding')
                version_end_excluding = cpe_match.get('versionEndExcluding')

                try:
                    cursor.execute("INSERT INTO Configurations (ID, operator, vulnerable, cpe23Uri, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, isNew) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE)",\
                                   (cve_id, operator, vulnerable, cpe23_uri, version_start_including, version_start_excluding, version_end_including, version_end_excluding))
                    cursor.execute("INSERT INTO Configurations (ID, operator, vulnerable, cpe23Uri, versionEndExcluding, isNew) VALUES (%s, %s, %s, %s, %s, TRUE)",\
                        (cve_id, operator, vulnerable, cpe23_uri, version_end_excluding))

                except pymysql.err.IntegrityError:
                # Duplicate record, update it
                    cursor.execute("UPDATE Configurations SET operator=%s, vulnerable=%s, cpe23Uri=%s, versionEndExcluding=%s, isNew=FALSE WHERE ID=%s",\
                            (operator, vulnerable, cpe23_uri, version_end_excluding, cve_id))



        db.commit()
        #print("Data loaded successfully to tables")
        logging.info("Data loaded successfully to tables")
    except Exception as e:
        db.rollback()
        #print("Error inserting data: ", e)
        logging.error("Error inserting data: ", e)
    finally:
        db.close()

    return True

# Declare merged JSON object:

merged_json = []
API_KEY = config.API_KEY 
resultsPerPage = config.RESULTS_PER_PAGE
#vendors = ['Microsoft', 'Cisco', 'Fortinet', 'palo', 'Juniper', 'Citrix', 'Oracle', 'IBM', 'VMware', 'Redhat', 'Adobe', 'Apple', 'Azure', 'AWS', 'Google', 'Mozilla', \
#           'Ubuntu', 'Debian', 'Suse', 'Amazon', 'Shopify', 'OpenSSL', 'OpenSSH', 'OpenVPN', 'Kubernetes', 'Docker', 'Nagios', 'Apache', 'IIS', 'Github','Sonicwall']
#vendors = ['Microsoft', 'Cisco']
#vendors = ['Microsoft', 'Cisco', 'Fortinet', 'paloalto', 'Juniper', 'Citrix', 'Oracle', 'VMware', 'Adobe', 'Apple', 'Azure', 'Mozilla',\
#           'Sonicwall', 'Adtran', 'Extreme', 'Dell', 'nutanix', 'EMC', 'Aerohive', 'Apple']
#vendors = ['Microsoft', 'Cisco', 'Fortinet', 'Palo Alto', 'Juniper', 'Oracle', 'VMware', 'Adobe',\
#           'Sonicwall', 'Adtran', 'Extreme', 'Dell', 'nutanix', 'EMC', 'Aerohive']
vendors = config.VENDORS

for vendor in vendors:
    baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    #params = {'ResultsPerPage': resultsPerPage, 'vendor': vendor, 'apiKey' : API_KEY}
    #baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    #params = {'ResultsPerPage': 2000, 'apiKey' : API_KEY, 'cpeMatchString': f'cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*', 'exactMatch': False, 'noRejected': True}
    #params = {'ResultsPerPage': 2000, 'apiKey' : API_KEY, 'vendor': vendor, 'exactMatch': False}
    #params = {'ResultsPerPage': resultsPerPage, 'apiKey' : API_KEY, 'vendor': vendor, 'exactMatch': False, 'keyword': vendor, 'cvssv3Severity': 'HIGH,CRITICAL'}
    params = {'ResultsPerPage': resultsPerPage, 'apiKey' : API_KEY, 'exactMatch': False, 'keyword': vendor, 'cvssv3Severity': 'LOW,MEDIUM,HIGH,CRITICAL',\
              'cpeMatchString': f'cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*', 'noRejected': True}
    #params = {'ResultsPerPage': config.RESULTS_PER_PAGE, 'apiKey' : config.API_KEY, 'exactMatch': False, 'keyword': vendor, 'cvssv3Severity': 'LOW,MEDIUM,HIGH,CRITICAL'}
    #params = {'ResultsPerPage': config.RESULTS_PER_PAGE, 'apiKey' : config.API_KEY, 'exactMatch': False, 'keyword': vendor, 'cvssv3Severity': 'LOW,MEDIUM,HIGH,CRITICAL'}
              
    #print ("Querying: ", baseUrl, params)

    #Parse and pretty print the URL that is being queried
    params_string = "&".join("%s=%s" % (k,v) for k,v in params.items())
    print (baseUrl + "?" + params_string)

    try:
        response = requests.get(baseUrl, params=params) 
        response.raise_for_status() 
        response_json = response.json() 
        if response_json['totalResults'] == 0: 
            print("Empty response") 
            continue 
        merged_json.append(response_json)
        # Nest the NVD API JSON response of current vendor into the merged_json list
        #merged_json.append(query_nvd_api(vendor))
    except requests.exceptions.RequestException as e:
        print("Error querying API: ", e)
        continue
    except json.JSONDecodeError as e:
        print("Error decoding response: ", e)
        continue
#Pretty print merged_json
#print(json.dumps(merged_json, indent=4, sort_keys=True))
insert_data(merged_json)
send_digest_email()