const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');

const app = express();
const db = new sqlite3.Database('database.sqlite');

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Vulnerable Session Configuration (v1)
// - No HttpOnly, No Secure, No SameSite
// - Weak secret
// - Re-save and SaveUninitialized true
app.use(session({
    secret: 'super-secret-key-123',
    resave: true,
    saveUninitialized: true,
    cookie: { 
        httpOnly: false, // VULNERABILITY: Cookie can be read by JavaScript (XSS risk)
        secure: false,   // VULNERABILITY: Cookie sent over HTTP
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));

// Provide user to all templates
app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.title = "AuthX";
    res.locals.error = null;
    res.locals.success = null;
    next();
});

// vulnerable: lacks some info
function logAudit(userId, action, resource, resourceId, req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    db.run(`INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) 
            VALUES (?, ?, ?, ?, ?)`, [userId, action, resource, resourceId, ip]);
}

app.get('/', (req, res) => {
    res.render('index', { title: 'Welcome to AuthX' });
});

app.get('/register', (req, res) => {
    res.render('register', { title: 'Register Account' });
});

app.post('/register', (req, res) => {
    const { email, password } = req.body;
    
    // VULNERABILITY: No password complexity/length validation
    // VULNERABILITY: Plaintext storage
    db.run(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`, 
        [email, password, 'USER'], 
        (err) => {
            if (err) {
                return res.render('register', { error: 'Email already exists!' });
            }
            res.redirect('/login?success=Account Created Successfully!');
        }
    );
});

app.get('/login', (req, res) => {
    const error = req.query.error;
    const success = req.query.success;
    res.render('login', { title: 'Login', error, success });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.render('login', { error: 'Database error' });

        if (!user) {
            // VULNERABILITY: User Enumeration - "User not found" is too specific
            return res.render('login', { error: 'This user account does not exist.' });
        }

        // VULNERABILITY: Comparison in plaintext
        if (user.password === password) {
            req.session.user = { id: user.id, email: user.email, role: user.role };
            logAudit(user.id, 'LOGIN', 'auth', user.id.toString(), req);
            res.redirect('/tickets');
        } else {
            // VULNERABILITY: User Enumeration - "Incorrect password" confirms email exists
            res.render('login', { error: 'Incorrect password for this user.' });
        }
    });
});

app.get('/logout', (req, res) => {
    if (req.session.user) {
        logAudit(req.session.user.id, 'LOGOUT', 'auth', req.session.user.id.toString(), req);
    }
    req.session.destroy();
    res.redirect('/login');
});

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { title: 'Reset Request' });
});

app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (!user) return res.render('forgot-password', { error: 'No user with that email!' });

        // VULNERABILITY: Use very predictable tokens (Math.random) or user ID
        const token = Math.floor(Math.random() * 10000); 
        db.run(`INSERT INTO password_reset_tokens (user_id, token) VALUES (?, ?)`, [user.id, token], () => {
             res.render('forgot-password', { success: `To exploit it, use /reset-password?token=${token} for user ID ${user.id}` });
        });
    });
});

app.get('/reset-password', (req, res) => {
    const token = req.query.token;
    res.render('reset-password', { title: 'Update Password', token });
});

app.post('/reset-password', (req, res) => {
    const { token, password } = req.body;
    
    // VULNERABILITY: Reset token doesn't expire and isn't checked for usage properly
    db.get(`SELECT * FROM password_reset_tokens WHERE token = ?`, [token], (err, row) => {
        if (!row) return res.render('reset-password', { error: 'Invalid or expired token!', token });

        db.run(`UPDATE users SET password = ? WHERE id = ?`, [password, row.user_id], () => {
            logAudit(row.user_id, 'RESET_PASSWORD', 'auth', row.user_id.toString(), req);
            res.redirect('/login?success=Password updated!');
        });
    });
});

app.get('/tickets', (req, res) => {
    if (!req.session.user) return res.redirect('/login');

    // VULNERABILITY: IDOR (Insecure Direct Object Reference)
    // No proper check if the user is owner or admin in the query logic
    db.all(`SELECT * FROM tickets`, [], (err, rows) => {
        res.render('tickets', { title: 'Support Tickets', tickets: rows });
    });
});

app.get('/audit', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    // Simple role check (also vulnerable if user can change their role easily)
    if (req.session.user.role !== 'ADMIN') {
         return res.render('index', { error: 'Access Denied: Administrative access required.' });
    }

    db.all(`SELECT * FROM audit_logs ORDER BY timestamp DESC`, [], (err, rows) => {
        res.render('audit', { title: 'Audit Tracker', logs: rows });
    });
});

app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    db.get(`SELECT * FROM users WHERE id = ?`, [req.session.user.id], (err, user) => {
        res.render('profile', { title: 'My Identity', user });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`AuthX vulnerable server (v1) running on http://localhost:${PORT}`);
});
