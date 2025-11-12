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

