const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

async function testUserEnumeration() {
    console.log(`${YELLOW}[TEST: User Enumeration] Checking for specific error messages...${RESET}`);

    // Test invalid email
    const resInvalid = await axios.post(`${BASE_URL}/login`, 'email=fake@test.com&password=wrong', {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    // Test valid email with wrong password
    const resValid = await axios.post(`${BASE_URL}/login`, 'email=admin@authx.com&password=wrong', {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const isDifferent = resInvalid.data !== resValid.data;
    if (isDifferent) {
        console.log(`${RED}  ❌ VULNERABILITY FOUND: Distinct error messages detected!${RESET}`);
        console.log(`     Invalid user: "${resInvalid.data.match(/alert-error">(.*?)<\/div>/)?.[1] || 'Unknown'}"`);
        console.log(`     Valid user:   "${resValid.data.match(/alert-error">(.*?)<\/div>/)?.[1] || 'Unknown'}"`);
    } else {
        console.log(`${GREEN}  ✅ Secure: Error messages are uniform.${RESET}`);
    }
}

async function testCookieSecurity() {
    console.log(`\n${YELLOW}[TEST: Cookie Security] Checking security flags...${RESET}`);
    const res = await axios.get(BASE_URL);
    const cookies = res.headers['set-cookie'] || [];

    if (cookies.length === 0) {
        console.log(`${YELLOW}  ⚠️  Warning: No session cookie set yet.${RESET}`);
        return;
    }

    const sid = cookies.find(c => c.includes('connect.sid'));
    if (sid) {
        const isHttpOnly = sid.toLowerCase().includes('httponly');
        const isSecure = sid.toLowerCase().includes('secure');

        if (!isHttpOnly) console.log(`${RED}  ❌ VULNERABILITY FOUND: Cookie is NOT HttpOnly! (XSS risk)${RESET}`);
        else console.log(`${GREEN}  ✅ Secure: HttpOnly flag is set.${RESET}`);

        if (!isSecure) console.log(`${RED}  ❌ VULNERABILITY FOUND: Cookie is NOT Secure! (MITM risk)${RESET}`);
        else console.log(`${GREEN}  ✅ Secure: Secure flag is set.${RESET}`);
    }
}

async function testPasswordPolicy() {
    console.log(`\n${YELLOW}[TEST: Password Policy] Attempting to register weak account...${RESET}`);
    const res = await axios.post(`${BASE_URL}/register`, 'email=weak@test.com&password=1', {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        maxRedirects: 0,
        validateStatus: false
    });

    // If it redirects to login or mentions success, the weak password was accepted
    if (res.headers.location?.includes('/login') || res.status === 200) {
        console.log(`${RED}  ❌ VULNERABILITY FOUND: Very weak password (1 character) accepted!${RESET}`);
    } else {
        console.log(`${GREEN}  ✅ Secure: Weak password rejected.${RESET}`);
    }
}

async function testRateLimiting() {
    console.log(`\n${YELLOW}[TEST: Rate Limiting] Flooding login endpoint...${RESET}`);
    const attempts = 20;
    let blocked = false;

    for (let i = 0; i < attempts; i++) {
        const res = await axios.post(`${BASE_URL}/login`, 'email=admin@authx.com&password=wrong', {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            validateStatus: false
        });
        if (res.status === 429) {
            blocked = true;
            break;
        }
    }

    if (blocked) {
        console.log(`${GREEN}  ✅ Secure: Rate limiting is active (429 Too Many Requests detected).${RESET}`);
    } else {
        console.log(`${RED}  ❌ VULNERABILITY FOUND: No rate limiting detected after ${attempts} attempts!${RESET}`);
    }
}

async function testIDOR() {
    console.log(`\n${YELLOW}[TEST: IDOR] Checking ticket ownership isolation...${RESET}`);

    // First, login as regular user
    const instance = axios.create({ baseURL: BASE_URL, withCredentials: true });
    await instance.post('/login', 'email=user@authx.com&password=password', {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const res = await instance.get('/tickets');
    const hasAdminTicket = res.data.includes('Server #42 Reboot Required');

    if (hasAdminTicket) {
        console.log(`${RED}  ❌ VULNERABILITY FOUND: IDOR detected! User can see admin tickets.${RESET}`);
    } else {
        console.log(`${GREEN}  ✅ Secure: Proper ownership isolation.${RESET}`);
    }
}

async function runFullScan() {
    try {
        await testUserEnumeration();
        await testCookieSecurity();
        await testPasswordPolicy();
        await testRateLimiting();
        await testIDOR();
    } catch (error) {
        console.error(`${RED}\nERROR: Could not connect to the server at ${BASE_URL}.${RESET}`);
        console.log("Please ensure 'node app.js' is running in another terminal.");
    }
}

runFullScan();