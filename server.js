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
        author TEXT,
        heyzine_url TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, () => {
        // Safe migration if table already existed without 'author' column
        db.run(`ALTER TABLE books ADD COLUMN author TEXT`, (alterErr) => {
            // Ignored if column already exists
        });
    });
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

// --- ULTRA-ROBUST PASSWORD CHANGE HANDLER ---
function handlePasswordChange(req, res) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    console.log("INCOMING PASSWORD CHANGE REQUEST BODY:", req.body);

    let identifier = req.body.userId || req.body.user_id || req.body.id || req.body.customer_id || req.body.username || req.body.customer || req.body.name || req.params.id;
    let password = req.body.password || req.body.newPassword || req.body.new_password || req.body.pass;

    if (!identifier && req.body && Object.keys(req.body).length > 0) {
        const keys = Object.keys(req.body);
        for (let k of keys) {
            const lower = k.toLowerCase();
            if (lower.includes('user') || lower.includes('id') || lower.includes('name') || lower.includes('customer')) {
                identifier = req.body[k];
            }
            if (lower.includes('pass')) {
                password = req.body[k];
            }
        }
        if (!identifier && keys.length >= 1) identifier = req.body[keys[0]];
        if (!password && keys.length >= 2) password = req.body[keys[1]];
    }

    if (!identifier || password === undefined || password === null || password === '') {
        return res.status(400).json({ error: `User identifier and password are required. Received keys: ${Object.keys(req.body || {}).join(', ')}` });
    }

    bcrypt.hash(String(password), 10, (hashErr, hashedPassword) => {
        if (hashErr) {
            return res.status(500).json({ error: 'Server error processing password.' });
        }

        const query = isNaN(identifier) 
            ? `UPDATE users SET password = ? WHERE username = ?` 
            : `UPDATE users SET password = ? WHERE id = ?`;

        db.run(query, [hashedPassword, identifier], function(err) {
            if (err) {
                console.error("Database error updating password:", err);
                return res.status(500).json({ error: 'Database error updating password.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: `User not found for identifier: ${identifier}` });
            }
            console.log(`Admin updated password for user identifier: ${identifier}`);
            res.json({ message: 'Password updated successfully!' });
        });
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

// 8. Admin Route: Delete a User / Customer Account
app.delete('/api/admin/users/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    const userId = req.params.id;
    db.run(`DELETE FROM books WHERE user_id = ?`, [userId], () => {
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

// 9. Admin Route: Change/Update User Password
app.put('/api/admin/change-customer-password', verifyToken, handlePasswordChange);
app.post('/api/admin/change-customer-password', verifyToken, handlePasswordChange);

app.put('/api/admin/users/:id/password', verifyToken, handlePasswordChange);
app.put('/api/admin/customers/:id/password', verifyToken, handlePasswordChange);

// 10. Admin Route: Assign a Book / Heyzine Link to a User (Ultra-Flexible + Author Support)
app.post('/api/admin/books', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    console.log("INCOMING BOOK ASSIGNMENT BODY:", req.body);

    const identifier = req.body.user_id || req.body.userId || req.body.id || req.body.customer_id || req.body.username || req.body.customer;
    const title = req.body.title || req.body.bookTitle;
    const author = req.body.author || req.body.bookAuthor || '';
    const heyzine_url = req.body.heyzine_url || req.body.heyzineUrl || req.body.url || req.body.link;

    if (!identifier || !title || !heyzine_url) {
        return res.status(400).json({ error: 'User ID, title, and Heyzine URL are required.' });
    }

    const userQuery = isNaN(identifier) 
        ? `SELECT id FROM users WHERE username = ?` 
        : `SELECT id FROM users WHERE id = ?`;

    db.get(userQuery, [identifier], (err, userRow) => {
        if (err || !userRow) {
            return res.status(404).json({ error: 'Selected customer account not found.' });
        }

        const userId = userRow.id;
        const insertQuery = `INSERT INTO books (user_id, title, author, heyzine_url) VALUES (?, ?, ?, ?)`;
        
        db.run(insertQuery, [userId, title, author, heyzine_url], function(dbErr) {
            if (dbErr) {
                console.error("Database error adding book:", dbErr);
                return res.status(500).json({ error: 'Failed to add book to database.' });
            }
            console.log(`Admin assigned book "${title}" by "${author}" to user ID: ${userId}`);
            res.json({ message: 'Book added successfully!', bookId: this.lastID });
        });
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