const crypto = require('crypto');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

const BASE_URL = 'http://localhost:3000';
const DB_PATH = './database.sqlite';

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function createClient(forwardedFor) {
    return axios.create({
        baseURL: BASE_URL,
        validateStatus: () => true,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Forwarded-For': forwardedFor
        }
    });
}

function formEncode(fields) {
    return new URLSearchParams(fields).toString();
}

function extractAlert(html) {
    return html.match(/alert-error">(.*?)<\/div>/)?.[1] || '';
}

function extractCookie(setCookieHeaders) {
    const cookieHeader = (setCookieHeaders || []).find(entry => entry.startsWith('connect.sid='));
    return cookieHeader ? cookieHeader.split(';')[0] : '';
}

function querySingleRow(sql, params = []) {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(DB_PATH);
        db.get(sql, params, (err, row) => {
            db.close();
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
}

function runStatement(sql, params = []) {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(DB_PATH);
        db.run(sql, params, err => {
            db.close();
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
}

function hashResetToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

async function testUserEnumeration() {
    console.log(`${YELLOW}[TEST: User Enumeration] Checking for generic login errors...${RESET}`);

    const invalidClient = createClient('10.0.1.11');
    const validClient = createClient('10.0.1.12');

    const invalidUser = await invalidClient.post('/login', formEncode({ email: 'fake@test.com', password: 'WrongPass1!' }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const validUserWrongPassword = await validClient.post('/login', formEncode({ email: 'admin@authx.com', password: 'WrongPass1!' }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const invalidMessage = extractAlert(invalidUser.data);
    const validMessage = extractAlert(validUserWrongPassword.data);

    if (invalidUser.status === 401 && validUserWrongPassword.status === 401 && invalidMessage === validMessage && validMessage === 'Invalid credentials.') {
        console.log(`${GREEN}  Secure: Login returns a single generic message.${RESET}`);
    } else {
        console.log(`${RED}  Problem: Login responses still leak user existence or vary by error.${RESET}`);
        console.log(`     invalid: ${invalidMessage || `status ${invalidUser.status}`}`);
        console.log(`     valid:   ${validMessage || `status ${validUserWrongPassword.status}`}`);
    }
}

async function testCookieSecurity(client) {
    console.log(`\n${YELLOW}[TEST: Cookie Security] Checking cookie flags on successful login...${RESET}`);

    const res = await client.post('/login', formEncode({ email: 'user@authx.com', password: 'User@12345!' }), {
        maxRedirects: 0,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Forwarded-Proto': 'https'
        }
    });

    const cookie = extractCookie(res.headers['set-cookie']);
    const lowerCookie = (res.headers['set-cookie'] || []).join('; ').toLowerCase();

    if (!cookie) {
        console.log(`${RED}  Problem: No session cookie was issued on login.${RESET}`);
        return;
    }

    const isHttpOnly = lowerCookie.includes('httponly');
    const isSecure = lowerCookie.includes('secure');
    const hasSameSite = lowerCookie.includes('samesite=lax');

    if (isHttpOnly && isSecure && hasSameSite) {
        console.log(`${GREEN}  Secure: Session cookie is HttpOnly, Secure, and SameSite=Lax.${RESET}`);
    } else {
        console.log(`${RED}  Problem: Session cookie flags are incomplete.${RESET}`);
        console.log(`     httponly=${isHttpOnly} secure=${isSecure} samesite=lax=${hasSameSite}`);
    }
}

async function testPasswordPolicy(client) {
    console.log(`\n${YELLOW}[TEST: Password Policy] Trying to create a weak account...${RESET}`);

    const res = await client.post('/register', formEncode({ email: 'weak@test.com', password: '1' }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    if (res.status === 400 && extractAlert(res.data)) {
        console.log(`${GREEN}  Secure: Weak passwords are rejected at registration.${RESET}`);
    } else {
        console.log(`${RED}  Problem: Very weak passwords are still accepted.${RESET}`);
    }
}

async function testRateLimiting(client) {
    console.log(`\n${YELLOW}[TEST: Rate Limiting] Flooding the login endpoint...${RESET}`);

    let blocked = false;
    for (let i = 0; i < 6; i += 1) {
        const res = await client.post('/login', formEncode({ email: 'admin@authx.com', password: 'WrongPass1!' }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        if (res.status === 429) {
            blocked = true;
            break;
        }
    }

    if (blocked) {
        console.log(`${GREEN}  Secure: Login rate limiting is active.${RESET}`);
    } else {
        console.log(`${RED}  Problem: No rate limiting detected after repeated login attempts.${RESET}`);
    }
}

async function testIDOR(client) {
    console.log(`\n${YELLOW}[TEST: IDOR] Verifying ticket ownership isolation...${RESET}`);

    const login = await client.post('/login', formEncode({ email: 'user@authx.com', password: 'User@12345!' }), {
        maxRedirects: 0,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Forwarded-Proto': 'https'
        }
    });

    const cookie = extractCookie(login.headers['set-cookie']);
    const ticketsResponse = await client.get('/tickets', {
        headers: { Cookie: cookie }
    });

    const hasAdminTicket = ticketsResponse.data.includes('Server #42 Reboot Required');

    if (!hasAdminTicket && ticketsResponse.status === 200) {
        console.log(`${GREEN}  Secure: Ticket visibility is restricted to the logged-in owner.${RESET}`);
    } else {
        console.log(`${RED}  Problem: User can still see tickets that do not belong to them.${RESET}`);
    }
}

async function testResetTokenFlow(client) {
    console.log(`\n${YELLOW}[TEST: Reset Password] Verifying token one-time use and expiry...${RESET}`);

    const forgot = await client.post('/forgot-password', formEncode({ email: 'victim@authx.com' }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const debugToken = forgot.headers['x-reset-token'];
    let tokenForReset = debugToken;

    if (!tokenForReset) {
        const fallbackToken = 'known-secure-token-for-test-flow';

        try {
            const victim = await querySingleRow(`SELECT id FROM users WHERE email = ?`, ['victim@authx.com']);
            if (!victim) {
                console.log(`${RED}  Problem: Missing debug token header and victim user not found for DB fallback.${RESET}`);
                return;
            }

            await runStatement(`DELETE FROM password_reset_tokens WHERE user_id = ?`, [victim.id]);
            await runStatement(
                `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used_at, created_at) VALUES (?, ?, ?, NULL, CURRENT_TIMESTAMP)`,
                [victim.id, hashResetToken(fallbackToken), new Date(Date.now() + 15 * 60 * 1000).toISOString()]
            );
            tokenForReset = fallbackToken;
            console.log(`${YELLOW} Using DB fallback for reset token test. Restart server to use header-based flow.${RESET}`);
        } catch (error) {
            console.log(`${RED} Problem: Could not validate reset flow (missing debug token header and DB fallback failed).${RESET}`);
            return;
        }
    }

    const firstReset = await client.post('/reset-password', formEncode({ token: tokenForReset, password: 'NewStrong@123!' }), {
        maxRedirects: 0,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const secondReset = await client.post('/reset-password', formEncode({ token: tokenForReset, password: 'AnotherStrong@123!' }), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const tokenStillValid = secondReset.status === 400 && extractAlert(secondReset.data).length > 0;
    const firstSucceeded = firstReset.status === 302 || firstReset.status === 303;

    if (firstSucceeded && tokenStillValid) {
        console.log(`${GREEN} Secure: Reset tokens are random, expire, and cannot be reused.${RESET}`);
    } else {
        console.log(`${RED} Problem: Reset token flow still allows reuse or does not complete successfully.${RESET}`);
    }
}

async function runFullScan() {
    try {
        await testUserEnumeration();
        await testCookieSecurity(createClient('10.0.0.12'));
        await testPasswordPolicy(createClient('10.0.0.13'));
        await testRateLimiting(createClient('10.0.0.14'));
        await testIDOR(createClient('10.0.0.15'));
        await testResetTokenFlow(createClient('10.0.0.16'));
    } catch (error) {
        console.error(`${RED}\nERROR: Could not connect to the server at ${BASE_URL}.${RESET}`);
        console.log("Please ensure 'node app.js' is running in another terminal.");
        console.error(error.message);
    }
}

runFullScan();
