const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const db = new sqlite3.Database('database.sqlite');

const SESSION_SECRET = process.env.SESSION_SECRET || 'authx-v2-demo-session-secret-change-me';
const SESSION_MAX_AGE = 1000 * 60 * 60 * 24;
const PASSWORD_MIN_LENGTH = 10;
const LOGIN_LOCK_THRESHOLD = 5;
const LOGIN_LOCK_WINDOW_MINUTES = 15;
const RESET_TOKEN_TTL_MINUTES = 15;
const GENERIC_AUTH_ERROR = 'Invalid credentials.';
const GENERIC_REGISTER_ERROR = 'Unable to create account. Check your input and try again.';
const GENERIC_RESET_REQUEST_MESSAGE = 'If the account exists, a password reset link has been generated.';
const GENERIC_RESET_ERROR = 'The reset token is invalid or has expired.';

app.set('trust proxy', 1);
app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', 'layout');

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: 'auto',
        maxAge: SESSION_MAX_AGE
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).render('login', {
            title: 'Login',
            error: 'Too many login attempts. Try again later.',
            success: null
        });
    }
});

const resetRequestLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).render('forgot-password', {
            title: 'Reset Request',
            error: 'Too many reset requests. Try again later.',
            success: null
        });
    }
});

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
    return typeof password === 'string'
        && password.length >= PASSWORD_MIN_LENGTH
        && /[a-z]/.test(password)
        && /[A-Z]/.test(password)
        && /[0-9]/.test(password)
        && /[^A-Za-z0-9]/.test(password);
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, storedHash) {
    if (!storedHash || typeof storedHash !== 'string') {
        return false;
    }

    const parts = storedHash.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') {
        return false;
    }

    const [, salt, hash] = parts;
    const expected = Buffer.from(hash, 'hex');
    const actual = crypto.scryptSync(password, salt, expected.length);

    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function hashResetToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function issueResetToken() {
    return crypto.randomBytes(32).toString('hex');
}

function logAudit(userId, action, resource, resourceId, req) {
    const forwardedFor = req.headers['x-forwarded-for'];
    const ip = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor || req.socket.remoteAddress || 'unknown';

    db.run(
        `INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)`,
        [userId, action, resource, resourceId, ip]
    );
}

function renderLogin(res, status, error, success = null) {
    return res.status(status).render('login', {
        title: 'Login',
        error,
        success
    });
}

function renderRegister(res, status, error) {
    return res.status(status).render('register', {
        title: 'Register Account',
        error
    });
}

function renderForgotPassword(res, status, error = null, success = null) {
    return res.status(status).render('forgot-password', {
        title: 'Reset Request',
        error,
        success
    });
}

function isAccountLocked(user) {
    if (!user.locked_until) {
        return false;
    }

    return new Date(user.locked_until).getTime() > Date.now();
}

function unlockExpiredAccount(userId) {
    db.run(
        `UPDATE users SET locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?`,
        [userId]
    );
}

function recordFailedLogin(user) {
    const nextAttempts = (user.failed_attempts || 0) + 1;
    const shouldLock = nextAttempts >= LOGIN_LOCK_THRESHOLD;
    const lockedUntil = shouldLock
        ? new Date(Date.now() + LOGIN_LOCK_WINDOW_MINUTES * 60 * 1000).toISOString()
        : null;

    db.run(
        `UPDATE users SET failed_attempts = ?, locked = ?, locked_until = ? WHERE id = ?`,
        [nextAttempts, shouldLock ? 1 : 0, lockedUntil, user.id]
    );
}

function resetLoginCounters(userId) {
    db.run(
        `UPDATE users SET failed_attempts = 0, locked = 0, locked_until = NULL WHERE id = ?`,
        [userId]
    );
}

function invalidateResetTokens(userId) {
    db.run(
        `UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`,
        [new Date().toISOString(), userId]
    );
}

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.title = 'AuthX';
    res.locals.error = null;
    res.locals.success = null;
    next();
});

app.get('/', (req, res) => {
    res.render('index', { title: 'Welcome to AuthX' });
});

app.get('/register', (req, res) => {
    res.render('register', { title: 'Register Account' });
});

app.post('/register', (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!isValidEmail(email) || !isStrongPassword(password)) {
        return renderRegister(res, 400, 'Use a valid email and a password with at least 10 characters, upper and lower case letters, a number, and a symbol.');
    }

    db.get(
        `SELECT id FROM users WHERE email = ?`,
        [email],
        (err, existingUser) => {
            if (err) {
                return renderRegister(res, 500, GENERIC_REGISTER_ERROR);
            }

            if (existingUser) {
                return renderRegister(res, 400, GENERIC_REGISTER_ERROR);
            }

            const passwordHash = hashPassword(password);
            db.run(
                `INSERT INTO users (email, password, password_hash, role, created_at, locked, failed_attempts, locked_until) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 0, 0, NULL)`,
                [email, '__deprecated__', passwordHash, 'USER'],
                insertErr => {
                    if (insertErr) {
                        return renderRegister(res, 500, GENERIC_REGISTER_ERROR);
                    }

                    res.redirect('/login?success=Account created successfully. Please sign in.');
                }
            );
        }
    );
});

app.get('/login', (req, res) => {
    const error = req.query.error;
    const success = req.query.success;
    res.render('login', { title: 'Login', error, success });
});

app.post('/login', loginLimiter, (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    db.get(
        `SELECT id, email, password_hash, role, failed_attempts, locked, locked_until FROM users WHERE email = ?`,
        [email],
        (err, user) => {
            if (err) {
                return renderLogin(res, 500, GENERIC_AUTH_ERROR);
            }

            if (!user) {
                crypto.scryptSync(password || 'dummy-password', 'authx-dummy-salt', 64);
                return renderLogin(res, 401, GENERIC_AUTH_ERROR);
            }

            if (isAccountLocked(user)) {
                return renderLogin(res, 401, GENERIC_AUTH_ERROR);
            }

            if (user.locked_until && new Date(user.locked_until).getTime() <= Date.now()) {
                unlockExpiredAccount(user.id);
            }

            const passwordMatches = verifyPassword(password, user.password_hash);

            if (!passwordMatches) {
                recordFailedLogin(user);
                logAudit(user.id, 'LOGIN_FAILED', 'auth', user.id.toString(), req);
                return renderLogin(res, 401, GENERIC_AUTH_ERROR);
            }

            resetLoginCounters(user.id);

            req.session.regenerate(sessionErr => {
                if (sessionErr) {
                    return renderLogin(res, 500, GENERIC_AUTH_ERROR);
                }

                req.session.user = { id: user.id, email: user.email, role: user.role };
                logAudit(user.id, 'LOGIN', 'auth', user.id.toString(), req);
                res.redirect('/tickets');
            });
        }
    );
});

app.get('/logout', (req, res) => {
    const currentUser = req.session.user;

    if (currentUser) {
        logAudit(currentUser.id, 'LOGOUT', 'auth', currentUser.id.toString(), req);
    }

    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login?success=You have been logged out.');
    });
});

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { title: 'Reset Request' });
});

app.post('/forgot-password', resetRequestLimiter, (req, res) => {
    const email = normalizeEmail(req.body.email);

    db.get(
        `SELECT id, email FROM users WHERE email = ?`,
        [email],
        (err, user) => {
            if (err) {
                return renderForgotPassword(res, 500, null, GENERIC_RESET_REQUEST_MESSAGE);
            }

            if (!user) {
                return renderForgotPassword(res, 200, null, GENERIC_RESET_REQUEST_MESSAGE);
            }

            const token = issueResetToken();
            const tokenHash = hashResetToken(token);
            const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MINUTES * 60 * 1000).toISOString();

            db.run(
                `INSERT INTO password_reset_tokens (user_id, token, token_hash, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, NULL, CURRENT_TIMESTAMP)`,
                [user.id, token, tokenHash, expiresAt],
                insertErr => {
                    if (insertErr) {
                        return renderForgotPassword(res, 500, null, GENERIC_RESET_REQUEST_MESSAGE);
                    }

                    if (process.env.NODE_ENV !== 'production') {
                        console.log(`[reset-token] ${email}: ${token}`);
                    }

                    return renderForgotPassword(res, 200, null, GENERIC_RESET_REQUEST_MESSAGE);
                }
            );
        }
    );
});

app.get('/reset-password', (req, res) => {
    const token = String(req.query.token || '');
    res.render('reset-password', { title: 'Update Password', token });
});

app.post('/reset-password', (req, res) => {
    const token = String(req.body.token || '');
    const password = String(req.body.password || '');

    if (!token) {
        return res.status(400).render('reset-password', { title: 'Update Password', error: GENERIC_RESET_ERROR, token: '' });
    }

    if (!isStrongPassword(password)) {
        return res.status(400).render('reset-password', {
            title: 'Update Password',
            error: 'Use a stronger password with at least 10 characters, upper and lower case letters, a number, and a symbol.',
            token
        });
    }

    db.get(
        `SELECT id, user_id, token, token_hash, expires_at, used_at FROM password_reset_tokens WHERE token = ?`,
        [token],
        (err, resetRow) => {
            if (err || !resetRow) {
                return res.status(400).render('reset-password', { title: 'Update Password', error: GENERIC_RESET_ERROR, token });
            }

            if (resetRow.used_at || new Date(resetRow.expires_at).getTime() <= Date.now()) {
                return res.status(400).render('reset-password', { title: 'Update Password', error: GENERIC_RESET_ERROR, token });
            }

            const passwordHash = hashPassword(password);
            db.run(
                `UPDATE users SET password = ?, password_hash = ? WHERE id = ?`,
                ['__deprecated__', passwordHash, resetRow.user_id],
                updateErr => {
                    if (updateErr) {
                        return res.status(500).render('reset-password', { title: 'Update Password', error: GENERIC_RESET_ERROR, token });
                    }

                    db.run(
                        `UPDATE password_reset_tokens SET used_at = ? WHERE id = ?`,
                        [new Date().toISOString(), resetRow.id],
                        () => {
                            invalidateResetTokens(resetRow.user_id);
                            logAudit(resetRow.user_id, 'RESET_PASSWORD', 'auth', resetRow.user_id.toString(), req);
                            res.redirect('/login?success=Password updated successfully.');
                        }
                    );
                }
            );
        }
    );
});

app.get('/tickets', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const query = String(req.query.q || '').trim();
    const params = [req.session.user.id];
    let sql = `SELECT * FROM tickets WHERE owner_id = ?`;

    if (query) {
        sql += ` AND (title LIKE ? OR description LIKE ?)`;
        params.push(`%${query}%`, `%${query}%`);
    }

    db.all(sql, params, (err, rows) => {
        if (err) {
            return res.render('index', { error: 'Database error fetching tickets.' });
        }

        res.render('tickets', { title: 'Support Tickets', tickets: rows, search: query });
    });
});

app.get('/audit', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    if (req.session.user.role !== 'ADMIN') {
        return res.status(403).render('index', { error: 'Access denied: administrative access required.' });
    }

    db.all(`SELECT * FROM audit_logs ORDER BY timestamp DESC`, [], (err, rows) => {
        if (err) {
            return res.render('index', { error: 'Database error fetching logs.' });
        }

        res.render('audit', { title: 'Audit Tracker', logs: rows });
    });
});

app.get('/profile', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    db.get(
        `SELECT * FROM users WHERE id = ?`,
        [req.session.user.id],
        (err, user) => {
            if (err || !user) {
                return res.redirect('/login');
            }

            res.render('profile', { title: 'My Identity', user });
        }
    );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server (v2-fixed) running on http://localhost:${PORT}`);
});
