#An emailer program that scans the mysql database for isNew = 1 and sends an email to the user
#with the newest CVE, CVE description, base score, severity and link to the CVE page

import pymysql
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import config
import logging

#Connect to the database
connection = pymysql.connect(host=config.MYSQL_HOST, user=config.MYSQL_USER, password=config.MYSQL_SECRET, db=config.MYSQL_DB, charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)

#Create a cursor object
cursor = connection.cursor()

#Select all the rows from the database where isNew = 1
sql = "SELECT * FROM CVE_Items INNER JOIN CVSSV3 ON CVE_Items.ID = CVSSV3.ID WHERE CVE_Items.isNew = 1"

#Execute the query
cursor.execute(sql)

#Fetch all the rows
rows = cursor.fetchall()

if cursor.rowcount == 0: 
    print("No new vulnerabilities found")
    exit()
else:
    print("New vulnerabilities found: " + str(cursor.rowcount))
    #print (rows[0])

# Function to get color based on the score
def get_color(score):
    if score <= 4.0:
        return "#2ecc71"  # Green for Low
    elif score <= 7.0:
        return "#f39c12"  # Orange for Medium
    else:
        return "#e74c3c"  # Red for High/Critical

#Loop through the rows and send an email for each vulnerability
for row in rows:
    #Create a message object
    msg = MIMEMultipart()

    #Create the message body
    #message = "The following vulnerability has been added to the database: \n\n" + "CVE: " + row["CVE"] + "\n" + "Description: " + row["description"] + "\n" + "Base Score: " + str(row["baseScore"]) + "\n" + "Severity: " + row["severity"] + "\n" + "Link: " + row["link"]

    #Print dictionary object row
    cve_id = row["ID"]
    cve_assigner = row["ASSIGNER"]
    cve_description = row["description_value"]
    reflink = row["url"]
    cve_name = row['name']
    published_date = row['publishedDate']
    last_modified_date = row['lastModifiedDate']
    baseScore = row['baseScore']
    html = ""

    #Create the html message body
    #try baseScore > 7.9
    score_color = get_color(baseScore)

if baseScore > 7.9:
        html = """\
        <html>
        <head>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 100%;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 8px;
                    text-align: left;
                }}
                tr:nth-child(even) {{
                    background-color: #f2f2f2;
                }}
                th {{
                    background-color: #333;
                    color: white;
                }}
                .highlight {{
                    background-color: {score_color};
                }}
            </style>
        </head>
        <body>
            <p>The following high-severity vulnerability has been added to the database:</p>
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>CVE Assigner</th>
                    <th>CVE Description</th>
                    <th>Reference Link</th>
                    <th>CVE Name</th>
                    <th>Published Date</th>
                    <th>Base Score</th>
                </tr>
                <tr>
                    <td>{cve_id}</td>
                    <td>{cve_assigner}</td>
                    <td>{cve_description}</td>
                    <td><a href="{reflink}">Link</a></td>
                    <td>{cve_name}</td>
                    <td>{published_date}</td>
                    <td class="highlight">{baseScore}</td>
                </tr>
            </table>
        </body>
        </html>
        """.format(cve_id=cve_id, cve_assigner=cve_assigner, cve_description=cve_description, reflink=reflink, cve_name=cve_name, published_date=published_date, score_color=score_color, baseScore=baseScore)
        #Set the subject of the email
        msg['Subject'] = "New Vulnerability Added to Database"
        msg.attach(MIMEText(html,'html'))
        logging.info("Sending email to " + config.SMTP_RECIPIENT)

        #Set the from address
        msg['From'] = config.SMTP_SENDER

        #Set the to address
        msg['To'] = config.SMTP_RECIPIENT 

        #Create a server object
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        #Start the server
        server.starttls()

        #Login to the server
        server.login(config.SMTP_LOGIN, config.SMTP_SECRET)

        #Send the email
        try:
            server.sendmail(config.SMTP_SENDER, config.SMTP_RECIPIENT, msg.as_string())
            logging.info("Email sent to " + config.SMTP_RECIPIENT)
        except Exception as e:
            logging.error(e)

        #Close the server
        server.quit()

        #Update the isNew field to 0
        sql = "UPDATE CVE_Items SET isNew = 0 WHERE ID = %s"
        cursor.execute(sql, (cve_id,))
        #Commit the changes
        connection.commit()

        #Close the connection
        connection.close()

else:
    print("No vulnerabilities with base score > 7.9 found. Will not send email. New vulnerability found with score " + str(baseScore))
    #Update the isNew field to 0
    sql = "UPDATE CVE_Items SET isNew = 0 WHERE ID = %s"
    cursor.execute(sql, (cve_id,))

    #Commit the changes
    connection.commit()

    #Close the connection
    connection.close()
    exit()

