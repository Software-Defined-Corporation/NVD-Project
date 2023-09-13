import requests
import pymysql
import json
from datetime import datetime
import logging
import config
from time import sleep

class ProgressBar:
    def __init__(self, total, length=50):
        self.total = total
        self.length = length
        self.progress = 0

    def update(self):
        self.progress += 1
        percentage = self.progress / self.total
        progress_length = int(self.length * percentage)
        bar = "." * progress_length + " " * (self.length - progress_length)
        print(f"\r[{bar}] {percentage:.2%}", end='')

    def update_by(self, count):
        self.progress += count
        percentage = self.progress / self.total
        progress_length = int(self.length * percentage)
        bar = "." * progress_length + " " * (self.length - progress_length)
        print(f"\r[{bar}] {percentage:.2%}", end='')        



logging.basicConfig(filename=config.LOG_FILE_NAME, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def convert_datetime_format(dt_string):
    """Converts NVD datetime format to MySQL datetime format."""
    nvd_format = "%Y-%m-%dT%H:%MZ"
    mysql_format = "%Y-%m-%d %H:%M:%S"
    dt_obj = datetime.strptime(dt_string, nvd_format)
    return dt_obj.strftime(mysql_format)

def query_nvd_api(vendor):
    """Queries the NVD API for CVEs related to the given vendor."""
    params = {
        'ResultsPerPage': config.RESULTS_PER_PAGE,
        'apiKey': config.API_KEY,
        'cpeMatchString': f'cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*',
    }
    logging.info(f"Querying: {config.BASE_URL} {params}")

    try:
        response = requests.get(config.BASE_URL, params=params)
        response.raise_for_status()
        response_json = response.json()
        #If response is 403, wait 1 minute and try again
        if response.status_code == 403:
            logging.warning("Rate limit exceeded, waiting 60 seconds...")
            sleep(30)
            response = requests.get(config.BASE_URL, params=params)
            response.raise_for_status()
            response_json = response.json()

        if response_json['totalResults'] == 0:
            logging.warning("Empty response")
            return []

        return response_json
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying API: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding response: {e}")
    
    return None

def insert_data(json_data_list):
    """Inserts or updates the CVE data into the database."""
    logging.info("Inserting data into database...")
    try:
        db = pymysql.connect(host="localhost", user="wordpress", password="lucRea7on", database="cve_database")
        cursor = db.cursor()
    except pymysql.MySQLError as e:
        logging.error(f"Error connecting to database: {e}")
        return

    #... rest of the insert_data function remains mostly unchanged ...

def fetch_vendors_data(vendors):
    """Fetches data for each vendor from the NVD API and returns the merged response."""
    merged_json = []

    for vendor in vendors:
        baseUrl = config.BASE_URL 
        params = {
        'ResultsPerPage': config.RESULTS_PER_PAGE,
        'cvssv3Severity': 'LOW,MEDIUM,HIGH,CRITICAL',
        'cpeMatchString': f'cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*',
        'noRejected': True
    }
        
        progressBar = ProgressBar(min(1000, len(vendors) * config.RESULTS_PER_PAGE))

        try:
            response = requests.get(config.BASE_URL, params=params)
            response.raise_for_status()
            response_json = response.json()

            if response_json['totalResults'] == 0:
                logging.info(f"Empty response from: {vendor}")
                continue

            for i in range(0, min(1000, response_json['totalResults']), config.RESULTS_PER_PAGE):
                params.update({'startIndex': int(i)})
                response = requests.get(config.BASE_URL, params=params)
                response.raise_for_status()
                merged_json.append(response.json())
                items_processed = len(response.json())
                progressBar.update_by(items_processed)

                #print("\nSleeping for 6 seconds before next fetch...")
                sleep(6)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying API: {e}")
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding response: {e}")

    return merged_json

if __name__ == "__main__":
    merged_data = fetch_vendors_data(config.VENDORS)
    insert_data(merged_data)
