const cron = require('node-cron');
require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const ejs = require('ejs');

const app = express();
const default_min_score = process.env.DEFAULT_MIN_SCORE; 

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Create connection
const db = mysql.createConnection({
    host: process.env.DB_HOST, 
    user: process.env.DB_USER, 
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// Function to initialize the database and tables
function initializeDatabase() {
    db.query('CREATE DATABASE IF NOT EXISTS cve_database', (err, results) => {
        if (err) throw err;
        console.log('Database created...');
        if (results.warningCount === 1) {
            console.log('Database already exists...');
        }
    });

    const tableQueries = [
        {
            query: 'CREATE TABLE IF NOT EXISTS CVE_Items (ID VARCHAR(255) PRIMARY KEY, description_value VARCHAR(255), description_lang VARCHAR(255), lastModifiedDate DATE, url VARCHAR(255), url_lang VARCHAR(255), url_data_format VARCHAR(255), url_data_version VARCHAR(255), ASSIGNER VARCHAR(255))',
            message: 'CVE_Items table'
        },
        {
            query: 'CREATE TABLE IF NOT EXISTS CVSSV3 (ID VARCHAR(255) PRIMARY KEY, baseScore FLOAT, baseSeverity VARCHAR(255))',
            message: 'CVSSV3 table'
        },
        {
            query: 'CREATE TABLE IF NOT EXISTS Configuration (ID VARCHAR(255) PRIMARY KEY, CVE_data_version VARCHAR(255), CVE_data_format VARCHAR(255), CVE_data_numberOfCVEs INT, CVE_data_timestamp DATE)',
            message: 'Configuration table'
        }
    ];

    for (let table of tableQueries) {
        db.query(table.query, (err, results) => {
            if (err) throw err;
            console.log(`${table.message} created...`);
            if (results.warningCount === 1) {
                console.log(`${table.message} already exists...`);
            }
        });
    }
}

//Function to archive the oldest CVEs from the database, anything older than 10 years
function archiveOldestCVEs(years) {
    // Delete CVEs older than 5 years from CVE_Items and CVSSV3 tables
    let sql = 'DELETE CVE_Items, CVSSV3 FROM CVE_Items INNER JOIN CVSSV3 ON CVE_Items.ID = CVSSV3.ID WHERE lastModifiedDate < DATE_SUB(NOW(), INTERVAL ? YEAR)';
    db.query(sql, [years], (err, results) => {
    //if length of results is 0, then there are no CVEs older than 5 years to archive
    if (results.length === 0) {
        console.log('No CVEs older than 5 years to archive...');
    }
    else {
        if (err) throw err;
        console.log('Oldest CVEs archived...');
    }
    });

    // Delete CVEs older than 5 years from Configuration table
}


// Connect
db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected...');
    initializeDatabase();
});

// Function to add a condition to the SQL query
const addCondition = (conditions, params, condition, param) => {
    conditions.push(condition);
    params.push(param);
}

// Home page
app.get('/', (req, res) => {
    let sql = 'SELECT * FROM CVE_Items INNER JOIN CVSSV3 ON CVE_Items.ID = CVSSV3.ID';
    const params = [];
    const conditions = [];

    const { showAll, search = '', vendors: vendorParam = '', startDate, endDate, baseSeverity } = req.query;

    let vendors = typeof vendorParam === 'string' ? vendorParam.split(',') : vendorParam;

    if (baseSeverity) {
        addCondition(conditions, params, 'CVSSV3.baseSeverity = ?', baseSeverity);
    }

    if (!showAll && !baseSeverity) {
        addCondition(conditions, params, 'CVSSV3.baseScore > ?', default_min_score);
    } else {
        addCondition(conditions, params, '(CVSSV3.baseScore >= ? OR CVSSV3.baseScore IS NULL)', 0);
    }

    if (search) {
        const searchTerms = search.split(' ');
        const searchConditions = searchTerms.map(term => {
            params.push(`%${term}%`, `%${term}%`);
            return 'description_value LIKE ? OR ASSIGNER LIKE ?';
        });
        conditions.push(`(${searchConditions.join(' OR ')})`);
    }

    if (vendors && vendors.length > 0) {
        const vendorConditions = vendors.map(vendor => {
            params.push(`%${vendor}%`);
            return 'description_value LIKE ?';
        });
        conditions.push(`(${vendorConditions.join(' OR ')})`);
    }

    if (startDate) {
        addCondition(conditions, params, 'lastModifiedDate >= ?', startDate);
    }

    if (endDate) {
        addCondition(conditions, params, 'lastModifiedDate <= ?', endDate);
    }

    if (conditions.length > 0) {
        sql += ' WHERE ' + conditions.join(' AND ');
    }

    sql += ' ORDER BY lastModifiedDate DESC';

    // For debugging purposes
    // console.log("SQL Query is: ", sql);
    // console.log("SQL Params are: ", params);

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error("Error querying the database", err);
            return res.status(500).send("Internal server error");
        }
        results.forEach(item => {
            item.urlData = JSON.parse(item.url || '[]');
        });
        res.render('index', {
            cve_data: results,
            search: search,
            startDate: startDate,
            endDate: endDate,
            vendors: vendors.join(','),
            showAll: showAll,
            baseSeverity: baseSeverity
        });
    });
});

app.listen('5000', () => {
    console.log('Server started on port 5000')
});

// Schedule tasks to run on the server every hour
cron.schedule('0 * * * *', function() {
    console.log('Running a task every hour');
    archiveOldestCVEs(process.env.NUMBER_OF_YEARS_TO_ARCHIVE);  // archive CVEs older than 5 years
});
