const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `scrypt$${salt}$${derived}`;
}

db.serialize(() => {
    db.run('PRAGMA foreign_keys = ON');

    db.run('DROP TABLE IF EXISTS password_reset_tokens');
    db.run('DROP TABLE IF EXISTS audit_logs');
    db.run('DROP TABLE IF EXISTS tickets');
    db.run('DROP TABLE IF EXISTS users');

    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'USER',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        locked BOOLEAN DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT
    )`);

    db.run(`CREATE TABLE tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT CHECK(severity IN ('LOW', 'MED', 'HIGH')),
        status TEXT CHECK(status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED')) DEFAULT 'OPEN',
        owner_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        resource_id TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    const seededUsers = [
        ['admin@authx.com', 'Admin@12345!', 'ADMIN'],
        ['user@authx.com', 'User@12345!', 'USER'],
        ['victim@authx.com', 'Victim@12345!', 'USER']
    ];

    const insertUser = db.prepare(`INSERT INTO users (email, password_hash, role, locked, failed_attempts, locked_until) VALUES (?, ?, ?, 0, 0, NULL)`);

    for (const [email, password, role] of seededUsers) {
        insertUser.run(email, hashPassword(password), role);
    }

    insertUser.finalize();

    db.run(`INSERT INTO tickets (title, description, severity, status, owner_id) VALUES 
        ('Server #42 Reboot Required', 'The node in datacenter region-2 is showing signs of memory leaks.', 'HIGH', 'OPEN', 1),
        ('Database Backup Failure', 'Automatic nightly backup for the SQL cluster failed with error 0x88. Immediate investigation required.', 'HIGH', 'OPEN', 1),
        ('Critical Security Patch', 'Apply urgent security patch to all internal Windows workstations.', 'HIGH', 'IN_PROGRESS', 1),
        ('VPN Connection Issues', 'Employees in the London office are reporting intermittent disconnects from the Global VPN.', 'MED', 'OPEN', 2),
        ('Payroll Access Error', 'Manager cannot access the quarterly report module due to 503 errors.', 'MED', 'IN_PROGRESS', 3),
        ('HR Portal Bug', 'Employees cannot update their home address in the profile settings.', 'MED', 'RESOLVED', 3),
        ('New Laptop for Mark', 'Asset tag requesting MacBook Pro with 64GB RAM.', 'LOW', 'OPEN', 2),
        ('Printer Jam in Floor 3', 'The main office printer has a persistent paper jam in tray 2.', 'LOW', 'OPEN', 3),
        ('Forgot My Badge', 'Employee logged a ticket to get a temporary access card for today.', 'LOW', 'RESOLVED', 2)
    `);

    console.log('Database initialized');
});

db.close();
