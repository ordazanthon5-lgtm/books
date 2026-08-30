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
        current_page INTEGER DEFAULT 1,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, () => {
        db.run(`ALTER TABLE books ADD COLUMN author TEXT`, (alterErr) => {});
        db.run(`ALTER TABLE books ADD COLUMN current_page INTEGER DEFAULT 1`, (alterErr) => {});
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

// --- PASSWORD CHANGE HANDLER ---
function handlePasswordChange(req, res) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access forbidden. Admins only.' });
    }

    let identifier = req.body.userId || req.body.user_id || req.body.id || req.body.customer_id || req.body.username;
    let password = req.body.password || req.body.newPassword || req.body.new_password;

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
        return res.status(400).json({ error: 'User identifier and password are required.' });
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
                return res.status(500).json({ error: 'Database error updating password.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: `User not found for identifier: ${identifier}` });
            }
            res.json({ message: 'Password updated successfully!' });
        });
    });
}

// --- API ROUTES ---

app.get('/api/status', (req, res) => {
    res.json({ status: '501Books server is running successfully!' });
});

app.post('/api/login', handleLogin);
app.post('/login', handleLogin);

app.get('/api/me', verifyToken, (req, res) => {
    res.json(req.user);
});

app.get('/api/books', verifyToken, (req, res) => {
    db.all(`SELECT * FROM books WHERE user_id = ?`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve books.' });
        res.json(rows);
    });
});

app.get('/api/customer/books', verifyToken, (req, res) => {
    db.all(`SELECT * FROM books WHERE user_id = ?`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve books.' });
        res.json(rows);
    });
});

// Save Book Bookmark / Current Page
app.post('/api/customer/books/:id/bookmark', verifyToken, (req, res) => {
    if (req.user.role !== 'customer') {
        return res.status(403).json({ error: 'Access forbidden. Customers only.' });
    }
    const bookId = req.params.id;
    const { page } = req.body;
    if (!page) {
        return res.status(400).json({ error: 'Page number is required.' });
    }

    db.run(`UPDATE books SET current_page = ? WHERE id = ? AND user_id = ?`, [page, bookId, req.user.id], function(err) {
        if (err || this.changes === 0) {
            return res.status(404).json({ error: 'Book not found or database error.' });
        }
        res.json({ message: 'Bookmark saved successfully!' });
    });
});

app.get('/api/admin/users', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    db.all(`SELECT id, username, role FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve users.' });
        res.json(rows);
    });
});

app.get('/api/admin/customers', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    db.all(`SELECT id, username, role FROM users`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve customers.' });
        res.json(rows);
    });
});

app.post('/api/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')`, [username, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: 'Username already exists.' });
            res.json({ message: 'Customer created successfully!', userId: this.lastID });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error.' });
    }
});

app.delete('/api/admin/users/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    const userId = req.params.id;
    db.run(`DELETE FROM books WHERE user_id = ?`, [userId], () => {
        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err || this.changes === 0) return res.status(404).json({ error: 'User not found.' });
            res.json({ message: 'User deleted successfully!' });
        });
    });
});

app.delete('/api/admin/customers/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    const userId = req.params.id;
    db.run(`DELETE FROM books WHERE user_id = ?`, [userId], () => {
        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err || this.changes === 0) return res.status(404).json({ error: 'Customer not found.' });
            res.json({ message: 'Customer deleted successfully!' });
        });
    });
});

app.put('/api/admin/change-customer-password', verifyToken, handlePasswordChange);
app.post('/api/admin/change-customer-password', verifyToken, handlePasswordChange);
app.put('/api/admin/users/:id/password', verifyToken, handlePasswordChange);

app.post('/api/admin/books', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });

    const identifier = req.body.user_id || req.body.userId || req.body.id || req.body.customer_id || req.body.username;
    const title = req.body.title || req.body.bookTitle;
    const author = req.body.author || req.body.bookAuthor || '';
    const heyzine_url = req.body.heyzine_url || req.body.heyzineUrl || req.body.url || req.body.link;

    if (!identifier || !title || !heyzine_url) {
        return res.status(400).json({ error: 'User ID, title, and Heyzine URL are required.' });
    }

    const userQuery = isNaN(identifier) ? `SELECT id FROM users WHERE username = ?` : `SELECT id FROM users WHERE id = ?`;

    db.get(userQuery, [identifier], (err, userRow) => {
        if (err || !userRow) return res.status(404).json({ error: 'Customer not found.' });

        db.run(`INSERT INTO books (user_id, title, author, heyzine_url) VALUES (?, ?, ?, ?)`, [userRow.id, title, author, heyzine_url], function(dbErr) {
            if (dbErr) return res.status(500).json({ error: 'Failed to add book.' });
            res.json({ message: 'Book added successfully!', bookId: this.lastID });
        });
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`501Books server live on port ${PORT}`);
});