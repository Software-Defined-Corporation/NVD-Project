import requests
import pymysql
import json
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import config
from time import sleep

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

def query_nvd_api(vendor):
    # Query NVD API for CVEs
    baseUrl = config.BASE_URL 
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
vendors = config.VENDORS

for vendor in vendors:
    baseUrl = config.BASE_URL 
    params = {'ResultsPerPage': resultsPerPage, 'apiKey' : API_KEY, 'cvssv3Severity': 'LOW,MEDIUM,HIGH,CRITICAL',\
              'cpeMatchString': f'cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*', 'noRejected': True}

    #Parse and pretty print the URL that is being queried
    params_string = "&".join("%s=%s" % (k,v) for k,v in params.items())

    try:
        response = requests.get(baseUrl, params=params) 
        response.raise_for_status() 
        response_json = response.json() 
        if response_json['totalResults'] == 0: 
            print("Empty response from: ", vendor) 
            print (baseUrl + "?" + params_string)
            continue 
        else:
            #Fetch the first 1000 results 
            for i in range(0, 1000, resultsPerPage):
                params.update({'startIndex': i})
                response = requests.get(baseUrl, params=params)
                response.raise_for_status()
                response_json = response.json()
                # Nest the NVD API JSON responses of current vendor into the merged_json list
                merged_json.append(response_json)
                print ("Sleeping for 6 seconds before next fetch...")
                sleep(6)
    except requests.exceptions.RequestException as e:
        print("Error querying API: ", e)
        continue
    except json.JSONDecodeError as e:
        print("Error decoding response: ", e)
        continue
insert_data(merged_json)