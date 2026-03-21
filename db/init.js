const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

db.serialize(() => {
    // 1. Users Table (Vulnerable: storing plaintext password)
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'USER',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        locked BOOLEAN DEFAULT 0
    )`);

    // 2. Tickets Table
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
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

    // 3. Audit Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT,
        resource_id TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // 4. Password Reset Tokens (Vulnerable: simple tokens, no expiration)
    db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT NOT NULL,
        used BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Insert dummy data
    db.run(`INSERT OR IGNORE INTO users (email, password, role) VALUES 
        ('admin@authx.com', 'admin123', 'ADMIN'),
        ('user@authx.com', 'password', 'USER'),
        ('victim@authx.com', '12345678', 'USER')
    `);

    // Insert dummy tickets
    db.run(`INSERT OR IGNORE INTO tickets (title, description, severity, status, owner_id) VALUES 
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

    console.log("Database initialized");
});

db.close();
