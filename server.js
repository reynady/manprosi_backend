import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import makeRecommendationsRouter from './modules/recommendations/index.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://127.0.0.1:5173',
    'http://localhost:5173',
    'http://127.0.0.1:3000'
  ],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Database connection
let db;
async function initDB() {
  try {
    db = await mysql.createConnection({
      host: process.env.DB_HOST || '127.0.0.1',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'palm_oil_monitoring',
    });
    console.log('✅ Database connected');
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.log('💡 Pastikan database sudah dibuat dan dikonfigurasi dengan benar');
    process.exit(1);
  }
}

// Helper: check if a table has a column (uses information_schema)
async function tableHasColumn(table, column) {
  try {
    const dbName = process.env.DB_NAME || 'palm_oil_monitoring';
    const [rows] = await db.execute(
      'SELECT COUNT(*) AS cnt FROM information_schema.columns WHERE table_schema = ? AND table_name = ? AND column_name = ?',
      [dbName, table, column]
    );
    return rows[0].cnt > 0;
  } catch (err) {
    // If information_schema is not accessible, conservatively assume column exists
    return true;
  }
}

// Auth middleware
async function requireAuth(req, res, next) {
  const userId = req.cookies.userId;
  if (!userId) {
    return res.status(401).json({ success: false, error: 'Not authenticated' });
  }
  
  try {
    const [users] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      return res.status(401).json({ success: false, error: 'User not found' });
    }
    // Attach user and load role name to make role checks easier
    const user = users[0];
    const [roles] = await db.execute('SELECT name FROM user_roles WHERE id = ?', [user.user_role_id]);
    user.role = roles[0]?.name?.toLowerCase() || 'client';
    req.user = user;
    next();
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
}

// Authorization middleware: require specific role(s)
function requireRole(expected) {
  // expected can be a string or array of strings
  const allowed = Array.isArray(expected) ? expected.map((r) => r.toLowerCase()) : [expected.toLowerCase()];
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, error: 'Not authenticated' });
    const userRole = (req.user.role || '').toLowerCase();
    if (!allowed.includes(userRole)) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    next();
  };
}

// Routes

// Health check
app.get('/', (req, res) => {
  res.json({ success: true, message: 'Palm Oil Monitoring API is running' });
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password are required' });
    }

    const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    // Get role name
    const [roles] = await db.execute('SELECT name FROM user_roles WHERE id = ?', [user.user_role_id]);
    const role = roles[0]?.name?.toLowerCase() || 'client';

    // Set cookie
    res.cookie('userId', user.id, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: 'lax'
    });
    res.json({
      success: true,
      data: {
        id: user.id,
        username: user.username,
        role: role,
        user_role_id: user.user_role_id
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get current user
app.get('/me', requireAuth, async (req, res) => {
  try {
    const [roles] = await db.execute('SELECT name FROM user_roles WHERE id = ?', [req.user.user_role_id]);
    const role = roles[0]?.name?.toLowerCase() || 'client';

    res.json({
      success: true,
      data: {
        id: req.user.id,
        username: req.user.username,
        role: role,
        user_role_id: req.user.user_role_id
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('userId');
  res.json({ success: true, message: 'Logged out successfully' });
});

// Users routes (Admin only)
// Admin-only: list users
app.get('/users', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const [users] = await db.execute(`
      SELECT u.id, u.username, u.user_role_id, ur.name as role_name, u.created_at, u.updated_at
      FROM users u
      JOIN user_roles ur ON u.user_role_id = ur.id
      ORDER BY u.id
    `);

    res.json({ success: true, data: users });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Admin-only: create user
app.post('/users', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { username, password, user_role_id } = req.body;

    if (!username || !password || !user_role_id) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'INSERT INTO users (username, password, user_role_id) VALUES (?, ?, ?)',
      [username, hashedPassword, user_role_id]
    );

    res.json({ success: true, data: { id: result.insertId, username, user_role_id } });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ success: false, error: 'Username already exists' });
    }
    res.status(500).json({ success: false, error: error.message });
  }
});

// Admin-only: delete user
app.delete('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    await db.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get single user (admin only)
app.get('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT u.id, u.username, u.user_role_id, ur.name as role_name, u.created_at, u.updated_at
      FROM users u
      JOIN user_roles ur ON u.user_role_id = ur.id
      WHERE u.id = ?
    `, [req.params.id]);

    if (!rows || rows.length === 0) return res.status(404).json({ success: false, error: 'User not found' });

    res.json({ success: true, data: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update user (admin only)
app.put('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {
  try {
    const { username, user_role_id } = req.body;
    if (!username || !user_role_id) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    await db.execute('UPDATE users SET username = ?, user_role_id = ? WHERE id = ?', [username, user_role_id, req.params.id]);

    const [rows] = await db.execute('SELECT id, username, user_role_id FROM users WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Lands routes
app.get('/users/:userId/lands', requireAuth, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    
    // Check if user can access this data
    if (req.user.user_role_id !== 1 && req.user.id !== userId) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const [lands] = await db.execute('SELECT * FROM lands WHERE user_id = ?', [userId]);
    res.json({ success: true, data: lands });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/lands', requireAuth, async (req, res) => {
  try {
    const { user_id, location_name, size } = req.body;

    if (!user_id || !location_name || !size) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }

    // Check permission
    if (req.user.user_role_id !== 1 && req.user.id !== user_id) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const [result] = await db.execute(
      'INSERT INTO lands (user_id, location_name, size) VALUES (?, ?, ?)',
      [user_id, location_name, size]
    );

    res.json({ success: true, data: { id: result.insertId, user_id, location_name, size } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/lands/:id', requireAuth, async (req, res) => {
  try {
    const landId = req.params.id;
    
    // Check ownership
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) {
      return res.status(404).json({ success: false, error: 'Land not found' });
    }

    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    await db.execute('DELETE FROM lands WHERE id = ?', [landId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Sensors routes
app.get('/lands/:landId/sensors', requireAuth, async (req, res) => {
  try {
    const landId = req.params.landId;
    
    // Check land ownership
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) {
      return res.status(404).json({ success: false, error: 'Land not found' });
    }

    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const [sensors] = await db.execute('SELECT * FROM sensors WHERE land_id = ?', [landId]);
    res.json({ success: true, data: sensors });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create sensor
app.post('/sensors', requireAuth, async (req, res) => {
  try {
    const { land_id, name, sensor_type, unit } = req.body;
    if (!land_id || !name || !sensor_type) return res.status(400).json({ success: false, error: 'Missing required fields' });

    // Check ownership
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });

    const [result] = await db.execute('INSERT INTO sensors (land_id, name, sensor_type, unit) VALUES (?, ?, ?, ?)', [land_id, name, sensor_type, unit || null]);
    res.json({ success: true, data: { id: result.insertId, land_id, name, sensor_type, unit } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Plants routes
app.get('/lands/:landId/plants', requireAuth, async (req, res) => {
  try {
    const landId = req.params.landId;
    
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) {
      return res.status(404).json({ success: false, error: 'Land not found' });
    }

    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const [plants] = await db.execute('SELECT * FROM plants WHERE land_id = ?', [landId]);
    res.json({ success: true, data: plants });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create plant
app.post('/plants', requireAuth, async (req, res) => {
  try {
    const { land_id, name, quantity, seed_id, planted_at } = req.body;
    if (!land_id || !name || !quantity) return res.status(400).json({ success: false, error: 'Missing required fields' });

    // Check ownership
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });

    const [result] = await db.execute('INSERT INTO plants (land_id, name, quantity, seed_id, planted_at) VALUES (?, ?, ?, ?, ?)', [land_id, name, quantity, seed_id || null, planted_at || null]);
    res.json({ success: true, data: { id: result.insertId, land_id, name, quantity, seed_id, planted_at } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Valves create
app.post('/valves', requireAuth, async (req, res) => {
  try {
    const { land_id, name } = req.body;
    if (!land_id || !name) return res.status(400).json({ success: false, error: 'Missing required fields' });
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [result] = await db.execute('INSERT INTO valves (land_id, name) VALUES (?, ?)', [land_id, name]);
    res.json({ success: true, data: { id: result.insertId, land_id, name } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Pumps create
app.post('/pumps', requireAuth, async (req, res) => {
  try {
    const { land_id, name } = req.body;
    if (!land_id || !name) return res.status(400).json({ success: false, error: 'Missing required fields' });
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [result] = await db.execute('INSERT INTO pumps (land_id, name) VALUES (?, ?)', [land_id, name]);
    res.json({ success: true, data: { id: result.insertId, land_id, name } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Pest controls create
app.post('/pest-controls', requireAuth, async (req, res) => {
  try {
    const { land_id, name, status } = req.body;
    if (!land_id || !name) return res.status(400).json({ success: false, error: 'Missing required fields' });
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [result] = await db.execute('INSERT INTO pest_controls (land_id, name, status) VALUES (?, ?, ?)', [land_id, name, status || 'no_action']);
    res.json({ success: true, data: { id: result.insertId, land_id, name, status: status || 'no_action' } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Seeds create
app.post('/seeds', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'Missing seed name' });
    const [result] = await db.execute('INSERT INTO seeds (name) VALUES (?)', [name]);
    res.json({ success: true, data: { id: result.insertId, name } });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, error: 'Seed already exists' });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get seeds list
app.get('/seeds', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM seeds ORDER BY name');
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update seed
app.put('/seeds/:id', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'Missing seed name' });
    const [rows] = await db.execute('SELECT * FROM seeds WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Seed not found' });
    // Only allow consultants or admins to modify seeds
    const roleName = (req.user.role || '').toLowerCase();
    if (req.user.user_role_id !== 1 && roleName !== 'consultant') {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    await db.execute('UPDATE seeds SET name = ? WHERE id = ?', [name, req.params.id]);
    const [updated] = await db.execute('SELECT * FROM seeds WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: updated[0] });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, error: 'Seed already exists' });
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete seed
app.delete('/seeds/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM seeds WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Seed not found' });
    // Only allow consultants or admins to delete seeds
    const roleName = (req.user.role || '').toLowerCase();
    if (req.user.user_role_id !== 1 && roleName !== 'consultant') {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    await db.execute('DELETE FROM seeds WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get single seed
app.get('/seeds/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM seeds WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Seed not found' });
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Recommendations (consultant) ---
// Recommendations routes are implemented in a separate module for modularity and testability.
// The router will be mounted after DB initialization in startServer().

// --- Valves / Pumps / Pest-controls list by land ---
app.get('/lands/:landId/valves', requireAuth, async (req, res) => {
  try {
    const landId = req.params.landId;
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [rows] = await db.execute('SELECT * FROM valves WHERE land_id = ?', [landId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/lands/:landId/pumps', requireAuth, async (req, res) => {
  try {
    const landId = req.params.landId;
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [rows] = await db.execute('SELECT * FROM pumps WHERE land_id = ?', [landId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/lands/:landId/pest-controls', requireAuth, async (req, res) => {
  try {
    const landId = req.params.landId;
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [rows] = await db.execute('SELECT * FROM pest_controls WHERE land_id = ?', [landId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Single sensor endpoints ---
app.get('/sensors/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM sensors WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Sensor not found' });
    const sensor = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [sensor.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: sensor });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/sensors/:id/latest', requireAuth, async (req, res) => {
  try {
    const sensorId = req.params.id;
    const [rows] = await db.execute('SELECT * FROM sensors WHERE id = ?', [sensorId]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Sensor not found' });
    const sensor = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [sensor.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [values] = await db.execute('SELECT * FROM sensor_values WHERE sensor_id = ? ORDER BY recorded_at DESC LIMIT 1', [sensorId]);
    if (values.length === 0) return res.status(404).json({ success: false, error: 'No sensor values' });
    res.json({ success: true, data: values[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/sensors/:id', requireAuth, async (req, res) => {
  try {
    const { name, sensor_type, unit } = req.body;
    const [rows] = await db.execute('SELECT * FROM sensors WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Sensor not found' });
    const sensor = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [sensor.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('UPDATE sensors SET name = ?, sensor_type = ?, unit = ? WHERE id = ?', [name || sensor.name, sensor_type || sensor.sensor_type, unit || sensor.unit, req.params.id]);
    const [updated] = await db.execute('SELECT * FROM sensors WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: updated[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/sensors/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM sensors WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Sensor not found' });
    const sensor = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [sensor.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('DELETE FROM sensors WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Valves / Pumps / Pest single and delete endpoints ---
app.get('/valves/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM valves WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Valve not found' });
    const valve = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [valve.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: valve });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/valves/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM valves WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Valve not found' });
    const valve = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [valve.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('DELETE FROM valves WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/pumps/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM pumps WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Pump not found' });
    const pump = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [pump.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: pump });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/pumps/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM pumps WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Pump not found' });
    const pump = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [pump.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('DELETE FROM pumps WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/pest-controls/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM pest_controls WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Pest control not found' });
    const pest = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [pest.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: pest });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/pest-controls/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM pest_controls WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Pest control not found' });
    const pest = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [pest.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('DELETE FROM pest_controls WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Plants single endpoints ---
app.get('/plants/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM plants WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Plant not found' });
    const plant = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [plant.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: plant });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/plants/:id', requireAuth, async (req, res) => {
  try {
    const { name, quantity, seed_id, planted_at } = req.body;
    const [rows] = await db.execute('SELECT * FROM plants WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Plant not found' });
    const plant = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [plant.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('UPDATE plants SET name = ?, quantity = ?, seed_id = ?, planted_at = ? WHERE id = ?', [name || plant.name, quantity || plant.quantity, seed_id || plant.seed_id, planted_at || plant.planted_at, req.params.id]);
    const [updated] = await db.execute('SELECT * FROM plants WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: updated[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/plants/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM plants WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Plant not found' });
    const plant = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [plant.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('DELETE FROM plants WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// --- Automations ---
// List automations for a land
app.get('/lands/:landId/automations', requireAuth, async (req, res) => {
  try {
    const landId = req.params.landId;
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [landId]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [rows] = await db.execute('SELECT * FROM automations WHERE land_id = ?', [landId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create automation
app.post('/automations', requireAuth, async (req, res) => {
  try {
    const { land_id, name, automation_type, sensor_id, sensor_value, pump_id, valve_id, dispense_amount } = req.body;
    if (!land_id || !name || !automation_type) return res.status(400).json({ success: false, error: 'Missing required fields' });
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    const [result] = await db.execute(
      'INSERT INTO automations (land_id, name, automation_type, sensor_id, sensor_value, pump_id, valve_id, dispense_amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [land_id, name, automation_type, sensor_id || null, sensor_value || null, pump_id || null, valve_id || null, dispense_amount || null]
    );
    res.json({ success: true, data: { id: result.insertId, land_id, name, automation_type, sensor_id, sensor_value, pump_id, valve_id, dispense_amount } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get automation by id
app.get('/automations/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM automations WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Automation not found' });
    const auto = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [auto.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: auto });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update automation
app.put('/automations/:id', requireAuth, async (req, res) => {
  try {
    const { name, automation_type, sensor_id, sensor_value, pump_id, valve_id, dispense_amount } = req.body;
    const [rows] = await db.execute('SELECT * FROM automations WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Automation not found' });
    const auto = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [auto.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('UPDATE automations SET name = ?, automation_type = ?, sensor_id = ?, sensor_value = ?, pump_id = ?, valve_id = ?, dispense_amount = ? WHERE id = ?', [name || auto.name, automation_type || auto.automation_type, sensor_id || auto.sensor_id, sensor_value || auto.sensor_value, pump_id || auto.pump_id, valve_id || auto.valve_id, dispense_amount || auto.dispense_amount, req.params.id]);
    const [updated] = await db.execute('SELECT * FROM automations WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: updated[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete automation
app.delete('/automations/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM automations WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Automation not found' });
    const auto = rows[0];
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [auto.land_id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('DELETE FROM automations WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Automation history (simple stub: return recent actions if any)
app.get('/automations/:id/history', requireAuth, async (req, res) => {
  try {
    const automationId = req.params.id;
    const [rows] = await db.execute('SELECT * FROM automations WHERE id = ?', [automationId]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'Automation not found' });
    // For now return empty history array (frontend expects array)
    res.json({ success: true, data: [] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get single land by id
app.get('/lands/:id', requireAuth, async (req, res) => {
  try {
    const [lands] = await db.execute('SELECT * FROM lands WHERE id = ?', [req.params.id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    const land = lands[0];
    if (req.user.user_role_id !== 1 && req.user.id !== land.user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    res.json({ success: true, data: land });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update land
app.put('/lands/:id', requireAuth, async (req, res) => {
  try {
    const { location_name, size } = req.body;
    const [lands] = await db.execute('SELECT user_id FROM lands WHERE id = ?', [req.params.id]);
    if (lands.length === 0) return res.status(404).json({ success: false, error: 'Land not found' });
    if (req.user.user_role_id !== 1 && req.user.id !== lands[0].user_id) return res.status(403).json({ success: false, error: 'Forbidden' });
    await db.execute('UPDATE lands SET location_name = ?, size = ? WHERE id = ?', [location_name, size, req.params.id]);
    const [rows] = await db.execute('SELECT * FROM lands WHERE id = ?', [req.params.id]);
    res.json({ success: true, data: rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start server
async function startServer() {
  await initDB();
  // Mount recommendations router (requires DB and auth middleware)
  try {
    const recRouter = makeRecommendationsRouter(db);
    app.use('/recommendations', requireAuth, recRouter);
    console.log('✅ Recommendations router mounted at /recommendations');
  } catch (err) {
    console.error('Failed to mount recommendations router:', err);
  }
  
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://127.0.0.1:${PORT}`);
    console.log(`📝 Make sure frontend is running on http://localhost:3000`);
  });
}

startServer().catch(console.error);


