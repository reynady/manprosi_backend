import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';

// Ensure data directory exists
const dbPath = path.resolve('data/app.db');
const dir = path.dirname(dbPath);
if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
}

// Initialize Database
const db = new Database(dbPath); // Add { verbose: console.log } for debugging if needed

// Enable foreign keys
db.pragma('foreign_keys = ON');

export function initDB() {
    console.log(`✅ Connected to SQLite at ${dbPath}`);
    initTables();
}

export function initTables() {
    const schemas = [
        `CREATE TABLE IF NOT EXISTS user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )`,
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_role_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_role_id) REFERENCES user_roles(id)
        )`,
        `CREATE TABLE IF NOT EXISTS lands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            location_name TEXT,
            size REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS sensors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            sensor_type TEXT,
            unit TEXT,
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS sensor_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id INTEGER,
            value REAL,
            recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sensor_id) REFERENCES sensors(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS plants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            quantity INTEGER,
            seed_id INTEGER,
            planted_at DATETIME,
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS valves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS pumps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS pest_controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            status TEXT DEFAULT 'no_action',
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS seeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        )`,
        `CREATE TABLE IF NOT EXISTS automations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            automation_type TEXT,
            sensor_id INTEGER,
            sensor_value REAL,
            pump_id INTEGER,
            valve_id INTEGER,
            dispense_amount REAL,
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`,
        `CREATE TABLE IF NOT EXISTS recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            land_id INTEGER,
            name TEXT,
            description TEXT,
            rec_type TEXT,
            seed_id INTEGER,
            created_by INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (land_id) REFERENCES lands(id) ON DELETE CASCADE
        )`
    ];

    schemas.forEach(sql => db.prepare(sql).run());
    console.log('✅ Tables initialized');

    // Seed roles if empty
    const roleCount = db.prepare('SELECT COUNT(*) as count FROM user_roles').get().count;
    if (roleCount === 0) {
        console.log('Seeding user_roles...');
        const insertRole = db.prepare('INSERT INTO user_roles (name) VALUES (?)');
        insertRole.run('admin');      // id 1
        insertRole.run('consultant'); // id 2
        insertRole.run('client');     // id 3
    }

    // Helper to seed user
    const createUser = (username, password, roleName) => {
        const role = db.prepare('SELECT id FROM user_roles WHERE name = ?').get(roleName);
        if (!role) {
            console.error(`Role ${roleName} not found, skipping user seed for ${username}`);
            return;
        }

        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user) {
            console.log(`Seeding user: ${username}...`);
            const hash = bcrypt.hashSync(password, 10);
            db.prepare('INSERT INTO users (username, password, user_role_id) VALUES (?, ?, ?)').run(username, hash, role.id);
        } else {
            // Ensure role is correct (fix if user exists but has wrong role / stale data)
            if (user.user_role_id !== role.id) {
                console.log(`Fixing role for user ${username} (Current: ${user.user_role_id}, Target: ${role.id})...`);
                db.prepare('UPDATE users SET user_role_id = ? WHERE id = ?').run(role.id, user.id);
            }
        }
    };

    // Ensure roles map correctly to what frontend expects
    // Admin -> admin
    // Consultant -> consultant
    // Farmer -> client
    createUser('admin', 'admin123', 'admin');
    createUser('consultant', 'consultant123', 'consultant');
    createUser('farmer', 'farmer123', 'client'); // Farmer is 'client' role
}

export default db;
