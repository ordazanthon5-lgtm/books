const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '501books_super_secret_key_change_in_production';

// Database Initialization
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Database connection error:', err);
    else console.log('Connected to SQLite database.');
});

// Create Database Tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'customer'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        url TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Seed default admin account if not existing (Default: admin / admin123)
    db.get(`SELECT * FROM users WHERE username = 'admin'`, async (err, row) => {
        if (!row) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            db.run(`INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, [hashedPassword], () => {
                console.log('Default admin account created: admin / admin123');
            });
        }
    });
});

// Middleware Configuration
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin permission required.' });
    }
    next();
}

// API Routes

// Login Endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: 'Invalid username or password.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid username or password.' });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    });
});

// Get Current Logged-in User Profile
app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

// ADMIN ONLY: Change Own Admin Password
app.post('/api/admin/change-password', authenticateToken, requireAdmin, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password are required.' });
    }

    db.get(`SELECT * FROM users WHERE id = ?`, [req.user.id], async (err, user) => {
        if (err || !user) return res.status(500).json({ error: 'User not found.' });

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Incorrect current password.' });

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET password = ? WHERE id = ?`, [hashedNewPassword, req.user.id], (err) => {
            if (err) return res.status(500).json({ error: 'Failed to update password.' });
            res.json({ message: 'Admin password updated successfully!' });
        });
    });
});

// ADMIN ONLY: Reset/Change Any Customer's Password
app.post('/api/admin/change-customer-password', authenticateToken, requireAdmin, async (req, res) => {
    const { customerId, newPassword } = req.body;
    if (!customerId || !newPassword) {
        return res.status(400).json({ error: 'Customer selection and new password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(`UPDATE users SET password = ? WHERE id = ? AND role = 'customer'`, [hashedPassword, customerId], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to update customer password.' });
            if (this.changes === 0) return res.status(404).json({ error: 'Customer not found.' });
            res.json({ message: 'Customer password updated successfully!' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error during password reset.' });
    }
});

// ADMIN: Get all Customer Accounts
app.get('/api/admin/customers', authenticateToken, requireAdmin, (req, res) => {
    const query = `
        SELECT users.id, users.username, COUNT(books.id) as bookCount 
        FROM users 
        LEFT JOIN books ON users.id = books.user_id 
        WHERE users.role = 'customer' 
        GROUP BY users.id
    `;
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch customers.' });
        res.json(rows);
    });
});

// ADMIN: Create New Customer Account
app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')`, [username, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Username already exists.' });
                }
                return res.status(500).json({ error: 'Failed to create customer.' });
            }
            res.json({ message: 'Customer account created successfully!', userId: this.lastID });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error during user creation.' });
    }
});

// ADMIN: Delete Customer Account & Assigned Books
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    db.run(`DELETE FROM users WHERE id = ? AND role = 'customer'`, [userId], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete customer.' });
        res.json({ message: 'Customer account and assigned books deleted.' });
    });
});

// ADMIN: Add Heyzine Flipbook & Assign to Customer
app.post('/api/admin/books', authenticateToken, requireAdmin, (req, res) => {
    let { userId, title, author, url } = req.body;

    if (!userId || !title || !author || !url) {
        return res.status(400).json({ error: 'Customer, Title, Author, and Heyzine Link are required.' });
    }

    const iframeSrcMatch = url.match(/src=["']([^"']+)["']/i);
    if (iframeSrcMatch) {
        url = iframeSrcMatch[1];
    }

    db.run(
        `INSERT INTO books (title, author, url, user_id) VALUES (?, ?, ?, ?)`,
        [title, author, url.trim(), userId],
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to save book to database.' });
            res.json({ message: 'Heyzine book assigned successfully!', bookId: this.lastID });
        }
    );
});

// CUSTOMER: Fetch Assigned Books
app.get('/api/customer/books', authenticateToken, (req, res) => {
    db.all(`SELECT id, title, author, url FROM books WHERE user_id = ?`, [req.user.id], (err, books) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch library books.' });
        res.json(books);
    });
});

// SPA Fallback Route
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});

// Start Express Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Default Admin Account -> Username: admin | Password: admin123`);
});