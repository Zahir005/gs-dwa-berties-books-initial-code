# Bertie’s Books
A tiny Express web app for a fictional book shop. It renders EJS templates, serves static assets, and demonstrates simple CRUD patterns (list books, add a book, basic search).

## Features
- Server-side rendering with EJS
- Routes split by domain (routes/)
- Static assets served from /public
- Demo pages: home, about, list of books, bargain books, register, search + results
- “Add Book” form posting to the server

## Stack
- Node.js
- Express.js
- EJS (Embedded JavaScript Templates)
- MySQL
- HTML/CSS
- Javascript

## Project Structure
```
berties-books/
├── public/
│   └── main.css
├── routes/
│   ├── books.js        
│   ├── main.js         
│   └── users.js        
├── views/
│   ├── about.ejs
│   ├── addbook.ejs
│   ├── bargainbooks.ejs
│   ├── index.ejs
│   ├── list.ejs
│   ├── register.ejs
│   ├── search.ejs
│   └── searchresult.ejs
├── create_db.sql
├── insert_test_data.sql
├── index.js            
├── package.json
└── README.md
```

## Getting Started
1. Clone the repo:
```bash
git clone https://github.com/Zahir005/06_berties_33787146.git
cd 06_berties_33787146
```

2. Install dependencies
```bash
npm install
```

3. Set up the database
- Launch MySQL
```bash
sudo mysql
```
- Run the following 
```bash
SOURCE create_db.sql;
SOURCE insert_test_data.sql;
```

4. Start the server
```bash
node index.js
```

5. Open in browser:
```bash
http://localhost:8000
```

## dotenv
To avoid hard-coding sensitive MySQL credentials (host, user, password, database) in index.js, this project uses the dotenv module to load them from an environment file.

1. Install dotenv
```bash
npm install dotenv
```

2. Create a .env file in the project root (same level as index.js):
```ini
DB_HOST=localhost
DB_USER=berties_books_app
DB_PASSWORD=qwertyuiop
DB_NAME=berties_books
```

3. Load environment variables in index.js
At the very top of `index.js`, before using any database config:
```js
require('dotenv').config();
```
Then update the database connection pool to use `process.env` variables instead of plain text:
```js
const db = mysql.createPool({
... (16 lines left)
Collapse
message.txt
3 KB
CREATE TABLE IF NOT EXISTS login_audits (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    login_time DATETIME NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    PRIMARY KEY (id)
);
zahir — 10:54
audit
To track both successful and failed login attempts, an audit logging feature was added. This records who tried to log in, when, whether it succeeded, and from which IP address.
How it’s implemented
Audit table in MySQL
A new table login_audits was created to store login events:
CREATE TABLE IF NOT EXISTS login_audits (
Expand
message.txt
3 KB
Zoi — 10:58
# Bertie’s Books
A tiny Express web app for a fictional book shop. It renders EJS templates, serves static assets, and demonstrates simple CRUD patterns (list books, add a book, basic search).

## Features
- Server-side rendering with EJS
- Routes split by domain (routes/)
Expand
message.txt
6 KB
﻿
# Bertie’s Books
A tiny Express web app for a fictional book shop. It renders EJS templates, serves static assets, and demonstrates simple CRUD patterns (list books, add a book, basic search).

## Features
- Server-side rendering with EJS
- Routes split by domain (routes/)
- Static assets served from /public
- Demo pages: home, about, list of books, bargain books, register, search + results
- “Add Book” form posting to the server

## Stack
- Node.js
- Express.js
- EJS (Embedded JavaScript Templates)
- MySQL
- HTML/CSS
- Javascript

## Project Structure
```
berties-books/
├── public/
│   └── main.css
├── routes/
│   ├── books.js        
│   ├── main.js         
│   └── users.js        
├── views/
│   ├── about.ejs
│   ├── addbook.ejs
│   ├── bargainbooks.ejs
│   ├── index.ejs
│   ├── list.ejs
│   ├── register.ejs
│   ├── search.ejs
│   └── searchresult.ejs
├── create_db.sql
├── insert_test_data.sql
├── index.js            
├── package.json
└── README.md
```

## Getting Started
1. Clone the repo:
```bash
git clone https://github.com/Zahir005/06_berties_33787146.git
cd 06_berties_33787146
```

2. Install dependencies
```bash
npm install
```

3. Set up the database
- Launch MySQL
```bash
sudo mysql
```
- Run the following 
```bash
SOURCE create_db.sql;
SOURCE insert_test_data.sql;
```

4. Start the server
```bash
node index.js
```

5. Open in browser:
```bash
http://localhost:8000
```

## dotenv
To avoid hard-coding sensitive MySQL credentials (host, user, password, database) in index.js, this project uses the dotenv module to load them from an environment file.

1. Install dotenv
```bash
npm install dotenv
```

2. Create a .env file in the project root (same level as index.js):
```ini
DB_HOST=localhost
DB_USER=berties_books_app
DB_PASSWORD=qwertyuiop
DB_NAME=berties_books
```

3. Load environment variables in index.js
At the very top of `index.js`, before using any database config:
```js
require('dotenv').config();
```
Then update the database connection pool to use `process.env` variables instead of plain text:
```js
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});
global.db = db;
```
Ignore the .env file in Git
To make sure credentials are not pushed to a public repository, `.env` is added to `.gitignore`:
```
.env
```
With this setup, the app still connects to the same MySQL database, but the credentials are stored outside the source code and are not exposed in version control.

## Audit
To track both successful and failed login attempts, an audit logging feature was added. This records who tried to log in, when, whether it succeeded, and from which IP address.

1. Audit table in MySQL
A new table login_audits was created to store login events:
```sql
CREATE TABLE IF NOT EXISTS login_audits (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    login_time DATETIME NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address VARCHAR(45),
    PRIMARY KEY (id)
);
```

2. Helper function to log each attempt
In routes/users.js, a helper function logAudit inserts a record for every login attempt (success or failure):
```js
function logAudit(username, success, req) {
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    const sqlquery = "INSERT INTO login_audits (username, login_time, success, ip_address) VALUES (?, NOW(), ?, ?)";
    const values = [username, success, ipAddress];

    db.query(sqlquery, values, (err) => {
        if (err) {
            console.error('Audit Logging Failed:', err);
        }
    });
}
```
3. Logging on successful and failed logins
- In the /users/loggedin POST route, logAudit is called whenever a user attempts to log in:
- If the username does not exist → logAudit(username, false, req)
- If the password is wrong → logAudit(username, false, req)
- If the login is successful → logAudit(username, true, req) <br>
This ensures every attempt (good or bad) is captured.

4. New route to view the audit history<br>
A new route /users/audit was added in routes/users.js:
```js
router.get('/audit', function(req, res, next) {
    let sqlquery = "SELECT username, login_time, success, ip_address FROM login_audits ORDER BY login_time DESC";

    db.query(sqlquery, (err, result) => {
        if (err) {
            return next(err);
        }
        res.render("audit.ejs", { auditRecords: result });
    });
});
```
This fetches the full audit log ordered by most recent login attempts.

5. Audit view template<br>
The `views/audit.ejs` template displays the login history in a table:
- Shows timestamp, username, success/failure, and IP address
- Successful logins are shown in green
- Failed logins are shown in red<br>
This gives a clear, visual audit trail of all login activity in the application.
message.txt
6 KB
