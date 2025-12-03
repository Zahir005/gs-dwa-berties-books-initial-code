// Create a new router
const express = require("express");
const router = express.Router();


// bcrypt for hashing passwords
const bcrypt = require("bcrypt");
const { check, validationResult } = require('express-validator');
const saltRounds = 10;

const redirectLogin = (req, res, next) => {
    if (!req.session.userId ) {
      res.redirect('../users/login') // redirect to the login page
    } else { 
        next (); // move to the next middleware function
    } 
}

// Show registration form
router.get("/register", function (req, res) {
    res.render("register.ejs");
});

// === Show login form ===
router.get("/login", function (req, res) {
    res.render("login.ejs");
});



// List all users
router.get('/listusers', function(req, res, next) {
    let sqlquery = "SELECT * FROM users"; // Query database to get all the users

    db.query(sqlquery, (err, result) => {
        if (err) {
            next(err);
        }
        // Render the new listusers.ejs file and pass the data as 'availableUsers'
        res.render("listusers.ejs", { availableUsers: result }); 
    });
});

// Handle registration form
router.post('/registered', 
    [
        // Email must be valid
        check('email')
          .isEmail()
          .withMessage('Please enter a valid email address.'),
      
        // Username length
        check('username')
          .isLength({ min: 5, max: 20 })
          .withMessage('Username must be between 5 and 20 characters long.'),
      
        // Password must be at least 8 chars
        check('password')
          .isLength({ min: 8 })
          .withMessage('Password must be at least 8 characters long.'),
      
        // First name and last name should not be empty
        check('first')
          .notEmpty()
          .withMessage('First name is required.'),
        check('last')
          .notEmpty()
          .withMessage('Last name is required.')
      ],
      
                function (req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('register.ejs', { errors: errors.array() });
    }
    else{
    // Task 11 will use req.body.password + hashedPassword
    const username = req.sanitize(req.body.username);
    const first = req.sanitize(req.body.first);
    const last = req.sanitize(req.body.last);
    const email = req.sanitize(req.body.email);
    const plainPassword = req.body.password;

    // Hash the password
    bcrypt.hash(plainPassword, saltRounds, function (err, hashedPassword) {
        if (err) {
            return next(err);
        }

      
        // TASK 10 — STORE IN DATABASE
        // ============================
        // Insert into the "users" table
        let sqlquery = "INSERT INTO users (username, first_name, last_name, email, password_hash) VALUES (?,?,?,?,?)";
        let newrecord = [username, first, last, email, hashedPassword];

        db.query(sqlquery, newrecord, (err, result) => {
            if (err) {
                return next(err);
            }

          
            // TASK 11 — OUTPUT PASSWORD + HASHED PASSWORD
           
            let output = 'Hello ' + req.body.first + ' ' + req.body.last +
                ' you are now registered! We will send an email to you at ' + req.body.email + '<br>';

            output += 'Your password is: ' + req.body.password +
                ' and your hashed password is: ' + hashedPassword;

            res.send(output);
        });

    });
}});


//audit log
function logAudit(username, success, req) {
    const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    const sqlquery = "INSERT INTO login_audits (username, login_time, success, ip_address) VALUES (?, NOW(), ?, ?)";
    const values = [username, success, ipAddress];

    db.query(sqlquery, values, (err) => {
        if (err) {
            console.error('Audit Logging Failed:', err);
        }
    })
}


// === Task 16: /users/loggedin – check username + password ===
router.post("/loggedin", 
    [
        check('username')
            .notEmpty()
            .withMessage("Username is required."),
        check('password')
            .notEmpty()
            .withMessage("Password is required.")
    ],
    function (req, res, next) {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.render('login.ejs');
        }
        else {

            const username = req.sanitize(req.body.username);
            const password = req.body.password;

            // 1. Get the stored hashed password for this user
            const sqlquery = "SELECT password_hash FROM users WHERE username = ?";

            db.query(sqlquery, [username], (err, result) => {
                if (err) {
                    return next(err);
                    logAudit(username, false, req);
                }

                if (result.length === 0) {
                    // No such user
                    logAudit(username, false, req);
                    return res.send("Login failed: incorrect username or password.");
                }

                const user = result[0];
                const hashedPassword = user.password_hash;

                // 2. Compare the password from the form with the hashed password from DB
                bcrypt.compare(password, hashedPassword, function (err, match) {
                    if (err) {
                        return next(err);
                        logAudit(username, false, req);
                    }

                    if (match === true) {
                        // Successful login
                        req.session.userId = username;
                        logAudit(username, true, req);
                        res.send("Hello " + user.first_name + ", you have successfully logged in!");
                    } else {
                        // Wrong password
                        res.send("Login failed: incorrect username or password.");
                        logAudit(username, false, req);
                    }
                });
            });
        }
});

router.get('/audit', function(req, res, next) {
    let sqlqeury = "SELECT username, login_time, success, ip_address FROM login_audits ORDER BY login_time DESC";

    db.query(sqlqeury, (err, result) => {
        if (err) {
            return next(err);
        }
        res.render("audit.ejs", {auditRecords: result});
    })
});


// ===== Task 13: /users/list route – show all users (no passwords) =====

router.get("/list",redirectLogin, function (req, res, next) {

    // only select non-sensitive fields
    const sqlquery = "SELECT username, first_name, last_name, email FROM users";

    db.query(sqlquery, (err, result) => {
        if (err) {
            return next(err);
        }

        // render the listusers page and pass the user data
        res.render("listusers.ejs", { availableUsers: result });
    });
});


// Export the router
module.exports = router;
