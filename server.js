const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_me';

// --- DATABASE SETUP (RENDER PERSISTENT DISK SUPPORT) ---
let dbDirectory;
if (process.env.RENDER) {
    dbDirectory = '/var/data';
    if (!fs.existsSync(dbDirectory)) {
        fs.mkdirSync(dbDirectory, { recursive: true });
    }
} else {
    dbDirectory = __dirname;
}

const dbPath = path.join(dbDirectory, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database at:', dbPath);
    }
});

// --- INITIALIZE DATABASE TABLES & SEED DEFAULT ADMIN ---
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'customer'
    )`, async () => {
        // Auto-create default admin account on startup if none exists
        db.get(`SELECT * FROM users WHERE role = 'admin'`, async (err, row) => {
            if (!row) {
                try {
                    const hashedPassword = await bcrypt.hash('admin123', 10);
                    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`, 
                        ['admin', hashedPassword, 'admin'], 
                        (insertErr) => {
                            if (!insertErr) {
                                console.log('Default admin account auto-created: username: admin / password: admin123');
                            }
                        }
                    );
                } catch (hashErr) {
                    console.error('Error hashing default admin password:', hashErr);
                }
            }
        });
    });

    db.run(`CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        heyzine_url TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
});

// --- AUTHENTICATION MIDDLEWARE ---
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// --- SHARED LOGIN HANDLER ---
function handleLogin(req, res) {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Invalid username or password.' });
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ error: 'Invalid username or password.' });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role }, 
                JWT_SECRET, 
                { expiresIn: '24h' }
            );
            return res.json({ message: 'Login successful!', token, role: user.role });
        } catch (compareErr) {
            return res.status(500).json({ error: 'Server error processing password.' });
        }
    });
}

// --- API ROUTES ---

// 1. Status Check
app.get('/api/status', (req, res) => {
    res.json({ status: '501Books server is running successfully!' });
});

// 2. Public Registration Route
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const userRole = role || 'customer';
        const query = `INSERT INTO users (username, password, role) VALUES (?, ?, ?)`;
        
        db.run(query, [username, hashedPassword, userRole], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Username already exists or database error.' });
            }
            console.log(`New user registered: ${username} (Role: ${userRole})`);
            res.json({ message: 'User registered successfully!', userId: this.lastID });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// 3. Login Routes
app.post('/api/login', handleLogin);
app.post('/login', handleLogin);

// 4. Get Current User Profile
app.get('/api/me', verifyToken, (req, res) => {
    res.json(req.user);
});

// 5. Get Books for Logged-in User
app.get('/api/books', verifyToken, (req, res) => {
    const userId = req.user.id;
    const query = `SELECT * FROM books WHERE user_id = ?`;
    
    db.all(query, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to retrieve books.' });
        }
        res.json(rows);
    });
});

app.get('/api/customer/books', verifyToken, (req, res) => {
    const userId = req.user.id;
    const query = `SELECT * FROM books WHERE user_id = ?`;
    
    db.all(query, [userId], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to retrieve books.' });
        }
        res.json(rows);
    });
});

// 6. Admin Route: Get All Users
app.get('/api/admin/users', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const query = `SELECT id, username, role FROM users`;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to retrieve users.' });
        }
        res.json(rows);
    });
});

app.get('/api/admin/customers', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const query = `SELECT id, username, role FROM users`;
    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to retrieve customers.' });
        }
        res.json(rows);
    });
});

// 7. Admin Route: Create a New Customer Account
app.post('/api/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')`;
        
        db.run(query, [username, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Username already exists or database error.' });
            }
            res.json({ message: 'Customer account created successfully!', userId: this.lastID });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error during customer creation.' });
    }
});

// 8. Admin Route: Delete a User / Customer Account (NEW)
app.delete('/api/admin/users/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const userId = req.params.id;
    // First remove associated books to keep database clean
    db.run(`DELETE FROM books WHERE user_id = ?`, [userId], (bookErr) => {
        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err || this.changes === 0) {
                return res.status(404).json({ error: 'User not found or database error.' });
            }
            console.log(`Admin deleted user ID: ${userId}`);
            res.json({ message: 'User account deleted successfully!' });
        });
    });
});

app.delete('/api/admin/customers/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const userId = req.params.id;
    db.run(`DELETE FROM books WHERE user_id = ?`, [userId], () => {
        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err || this.changes === 0) {
                return res.status(404).json({ error: 'Customer not found.' });
            }
            res.json({ message: 'Customer deleted successfully!' });
        });
    });
});

// 9. Admin Route: Change/Update User Password (NEW)
app.put('/api/admin/users/:id/password', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const userId = req.params.id;
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ error: 'New password is required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, userId], function(err) {
            if (err || this.changes === 0) {
                return res.status(404).json({ error: 'User not found or database error.' });
            }
            console.log(`Admin updated password for user ID: ${userId}`);
            res.json({ message: 'Password updated successfully!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error updating password.' });
    }
});

app.put('/api/admin/customers/:id/password', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const userId = req.params.id;
    const { password } = req.body;
    if (!password) {
        return res.status(400).json({ error: 'New password is required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedPassword, userId], function(err) {
            if (err || this.changes === 0) {
                return res.status(404).json({ error: 'User not found.' });
            }
            res.json({ message: 'Password updated successfully!' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error updating password.' });
    }
});

// 10. Admin Route: Assign a Book / Heyzine Link to a User
app.post('/api/admin/books', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const { user_id, title, heyzine_url } = req.body;
    if (!user_id || !title || !heyzine_url) {
        return res.status(400).json({ error: 'User ID, title, and Heyzine URL are required.' });
    }

    const query = `INSERT INTO books (user_id, title, heyzine_url) VALUES (?, ?, ?)`;
    db.run(query, [user_id, title, heyzine_url], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to add book.' });
        }
        res.json({ message: 'Book added successfully!', bookId: this.lastID });
    });
});

// --- SAFETY NET: Force JSON for missing API routes ---
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: `API endpoint not found: ${req.baseUrl}` });
});

// --- FRONTEND CATCH-ALL ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- SERVER LISTENING ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`501Books server is live and listening on port ${PORT}`);
});