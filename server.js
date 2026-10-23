const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const NodeCache = require('node-cache');

const app = express();
const searchCache = new NodeCache({ stdTTL: 3600 }); // Cache search queries for 1 hour

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_me';

// --- HARDCODED EMAIL TRANSPORTER CONFIGURATION ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: '501customercaare@gmail.com',
        pass: 'hphi eqxe uoaq fgol'
    }
});

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

// --- INITIALIZE DATABASE TABLES & GUARANTEE ADMIN ACCOUNT ---
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'customer'
    )`, async () => {
        db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);`, () => {});

        try {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            db.run(`INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')
                    ON CONFLICT(username) DO UPDATE SET password = ?, role = 'admin'`, 
                [hashedPassword, hashedPassword], 
                (err) => {
                    if (!err) {
                        console.log('Admin account verified/updated: admin / admin123');
                    } else {
                        console.error('Error ensuring admin user:', err);
                    }
                }
            );
        } catch (hashErr) {
            console.error('Error hashing default admin password:', hashErr);
        }
    });

    db.run(`CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        author TEXT,
        heyzine_url TEXT,
        cover_url TEXT,
        current_page INTEGER DEFAULT 1,
        is_completed BOOLEAN DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, () => {
        db.run(`ALTER TABLE books ADD COLUMN author TEXT`, (alterErr) => {});
        db.run(`ALTER TABLE books ADD COLUMN cover_url TEXT`, (alterErr) => {});
        db.run(`ALTER TABLE books ADD COLUMN current_page INTEGER DEFAULT 1`, (alterErr) => {});
        db.run(`ALTER TABLE books ADD COLUMN is_completed BOOLEAN DEFAULT 0`, (alterErr) => {});
    });

    db.run(`CREATE TABLE IF NOT EXISTS signup_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT,
        whatsapp TEXT,
        email TEXT,
        password TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (!err) console.log('Signup requests table ready.');
    });

    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => {
        if (!err) console.log('Sessions table ready.');
    });
});

// --- AUTHENTICATION MIDDLEWARE ---
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }

        db.get(`SELECT * FROM sessions WHERE token = ?`, [token], (dbErr, sessionRow) => {
            if (dbErr || !sessionRow) {
                return res.status(403).json({ error: 'Session expired. Account logged in from another device.' });
            }

            db.get(`SELECT username, role FROM users WHERE id = ?`, [decodedUser.id], (userErr, dbUser) => {
                if (userErr || !dbUser) {
                    return res.status(403).json({ error: 'User no longer exists.' });
                }

                req.user = { id: decodedUser.id, username: dbUser.username, role: dbUser.role };
                next();
            });
        });
    });
}

// --- SHARED LOGIN HANDLER ---
function handleLogin(req, res) {
    let { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    username = username.trim();
    password = password.trim();

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
                JWT_SECRET
            );

            db.run(`INSERT INTO sessions (user_id, token) VALUES (?, ?)`, [user.id, token], (insertErr) => {
                if (insertErr) {
                    return res.status(500).json({ error: 'Database error recording session.' });
                }

                db.all(`SELECT id FROM sessions WHERE user_id = ? ORDER BY created_at DESC`, [user.id], (selErr, rows) => {
                    if (!selErr && rows && rows.length > 2) {
                        const oldSessionIds = rows.slice(2).map(r => r.id);
                        const placeholders = oldSessionIds.map(() => '?').join(',');
                        db.run(`DELETE FROM sessions WHERE id IN (${placeholders})`, oldSessionIds, () => {});
                    }

                    return res.json({ message: 'Login successful!', token, role: user.role });
                });
            });
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

    let identifier = req.body.userId || req.body.customerId || req.body.user_id || req.body.id || req.body.customer_id || req.body.username;
    let password = req.body.password || req.body.newPassword || req.body.new_password;

    if (!identifier || password === undefined || password === null || password === '') {
        return res.status(400).json({ error: 'User identifier and password are required.' });
    }

    const trimmedPassword = String(password).trim();

    bcrypt.hash(trimmedPassword, 10, (hashErr, hashedPassword) => {
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

// --- WORLDWIDE BOOK SEARCH PROXY (USING OPEN LIBRARY) ---
app.get('/api/books/search', async (req, res) => {
    const query = req.query.q?.toLowerCase().trim();
    if (!query || query.length < 2) {
        return res.json({ items: [] });
    }

    if (searchCache.has(query)) {
        return res.json(searchCache.get(query));
    }

    try {
        const response = await fetch(`https://openlibrary.org/search.json?q=${encodeURIComponent(query)}&limit=5`, {
            headers: {
                'User-Agent': '501BooksApp/1.0 (admin@501books.com)'
            }
        });
        
        if (!response.ok) {
            return res.status(response.status).json({ error: 'Search service busy. Please try again.' });
        }

        const data = await response.json();
        
        const items = (data.docs || []).map(doc => {
            const title = doc.title || 'Unknown Title';
            const author = doc.author_name ? doc.author_name.join(', ') : 'Unknown Author';
            const coverId = doc.cover_i;
            const cover = coverId 
                ? `https://covers.openlibrary.org/b/id/${coverId}-M.jpg` 
                : 'https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?auto=format&fit=crop&w=500&q=80';
            
            return {
                volumeInfo: {
                    title: title,
                    authors: [author],
                    imageLinks: { thumbnail: cover },
                    description: doc.first_sentence ? doc.first_sentence.join(' ') : `A book titled ${title} by ${author}.`
                }
            };
        });

        const resultPayload = { items };
        searchCache.set(query, resultPayload);
        res.json(resultPayload);
    } catch (err) {
        console.error('Open Library proxy search error:', err);
        res.status(500).json({ error: 'Failed to fetch search results' });
    }
});

app.post('/api/login', handleLogin);
app.post('/login', handleLogin);

app.post('/api/signup', async (req, res) => {
    let { fullName, whatsapp, email, password } = req.body;
    if (!fullName || !whatsapp || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    const trimmedFullName = fullName.trim();
    const trimmedPassword = password.trim();

    try {
        const hashedPassword = await bcrypt.hash(trimmedPassword, 10);
        
        db.run(
            `INSERT INTO signup_requests (fullname, whatsapp, email, password) VALUES (?, ?, ?, ?)`,
            [trimmedFullName, whatsapp, email, hashedPassword],
            (err) => { if (err) console.error('Error saving to signup_requests:', err); }
        );

        db.run(
            `INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')
             ON CONFLICT(username) DO UPDATE SET password = ?`,
            [trimmedFullName, hashedPassword, hashedPassword],
            function(dbErr) {
                if (dbErr) {
                    return res.status(400).json({ error: 'An account with this name already exists or database error.' });
                }

                const newUserId = this.lastID;
                const defaultBookTitle = "SAMPLE BOOK (Lover Her Wild)";
                const defaultBookAuthor = "Atticus";
                const defaultBookEpubUrl = "https://pub-937728d8eaaa44d38ec534532f9c4ca4.r2.dev/love%20her%20wild%20Real.epub";
                const defaultBookCoverUrl = "https://d28hgpri8am2if.cloudfront.net/book_images/onix/cvr9781501171239/love-her-wild-9781501171239_hr.jpg";

                db.run(
                    `INSERT INTO books (user_id, title, author, heyzine_url, cover_url) VALUES (?, ?, ?, ?, ?)`,
                    [newUserId, defaultBookTitle, defaultBookAuthor, defaultBookEpubUrl, defaultBookCoverUrl],
                    (bookErr) => { if (bookErr) console.error('Error seeding default book:', bookErr); }
                );

                const adminMailOptions = {
                    from: '501customercaare@gmail.com',
                    to: '501customercaare@gmail.com',
                    subject: '📖 New 501Books Account Created',
                    text: `A new user has successfully created an account:\n\nFull Name (Username): ${trimmedFullName}\nWhatsApp: ${whatsapp}\nEmail: ${email}\nPassword: ${trimmedPassword}`
                };
                transporter.sendMail(adminMailOptions, (mailErr) => { if (mailErr) console.error(mailErr); });

                const customerMailOptions = {
                    from: '501customercaare@gmail.com',
                    to: email,
                    subject: 'Welcome to 501Books!',
                    text: `Hello ${trimmedFullName},\n\nWelcome to 501Books! Here are your account credentials:\n- Username: ${trimmedFullName}\n- Password: ${trimmedPassword}\n\nEnjoy reading!`
                };
                transporter.sendMail(customerMailOptions, (customerMailErr) => { if (customerMailErr) console.error(customerMailErr); });

                res.json({ message: 'Account Created' });
            }
        );
    } catch (hashErr) {
        res.status(500).json({ error: 'Server error processing request.' });
    }
});

// --- BOOK REQUEST ENDPOINT (INCLUDES USER ACCOUNT EMAIL & WHATSAPP PHONE NUMBER) ---
app.post('/api/request-book', verifyToken, (req, res) => {
    const { title, author, description, cover } = req.body;
    if (!title) {
        return res.status(400).json({ error: 'Book title is required.' });
    }

    const requestedBy = req.user.username;
    const userId = req.user.id;

    // Fetch user's signup request details (email and whatsapp) from database
    db.get(`SELECT email, whatsapp FROM signup_requests WHERE fullname = ? ORDER BY created_at DESC LIMIT 1`, [requestedBy], (userErr, userRow) => {
        const userEmail = userRow && userRow.email ? userRow.email : 'Not provided / Admin created';
        const userWhatsapp = userRow && userRow.whatsapp ? userRow.whatsapp : 'Not provided';

        const mailOptions = {
            from: '501customercaare@gmail.com',
            to: '501bookreq@gmail.com',
            subject: `[501Books Request] ${title}`,
            html: `
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                    <h2 style="color: #EF233C;">New Book Request</h2>
                    <div style="background-color: #f7f9fa; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                        <h3 style="margin-top: 0; color: #0D1B2A;">Customer Account Information:</h3>
                        <p style="margin: 5px 0;"><strong>Username (Full Name):</strong> ${requestedBy}</p>
                        <p style="margin: 5px 0;"><strong>Account E-Mail:</strong> <a href="mailto:${userEmail}">${userEmail}</a></p>
                        <p style="margin: 5px 0;"><strong>WhatsApp Phone Number:</strong> ${userWhatsapp}</p>
                        <p style="margin: 5px 0;"><strong>User ID:</strong> ${userId}</p>
                    </div>
                    <hr style="border: none; border-top: 1px solid #ccc; margin: 20px 0;">
                    <h3>Requested Book Details</h3>
                    <div style="display: flex; gap: 20px; align-items: flex-start;">
                        <img src="${cover || ''}" alt="Book Cover" style="width: 120px; border-radius: 4px; border: 1px solid #ddd;" />
                        <div>
                            <h4 style="margin: 0 0 5px 0; font-size: 18px; color: #0D1B2A;">${title}</h4>
                            <p style="margin: 0 0 10px 0; color: #666;"><strong>Author:</strong> ${author || 'Not specified'}</p>
                            <p style="font-size: 14px; color: #444; line-height: 1.4;"><strong>Description:</strong> ${description || 'No description available.'}</p>
                        </div>
                    </div>
                </div>
            `
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) {
                console.error('Error sending book request email:', err);
                return res.status(500).json({ error: 'Failed to send book request email.' });
            }
            res.json({ message: 'Request sent successfully!' });
        });
    });
});

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

app.delete('/api/customer/books/:id', verifyToken, (req, res) => {
    if (req.user.role !== 'customer') {
        return res.status(403).json({ error: 'Access forbidden. Customers only.' });
    }
    const bookId = req.params.id;
    db.run(`DELETE FROM books WHERE id = ? AND user_id = ?`, [bookId, req.user.id], function(err) {
        if (err || this.changes === 0) {
            return res.status(404).json({ error: 'Book not found or database error.' });
        }
        res.json({ message: 'Book deleted successfully!' });
    });
});

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

app.post('/api/customer/books/:id/complete', verifyToken, (req, res) => {
    if (req.user.role !== 'customer') {
        return res.status(403).json({ error: 'Access forbidden. Customers only.' });
    }
    const bookId = req.params.id;
    const { isCompleted } = req.body;

    const query = `UPDATE books SET is_completed = ? WHERE id = ? AND user_id = ?`;
    db.run(query, [isCompleted ? 1 : 0, bookId, req.user.id], function(err) {
        if (err || this.changes === 0) {
            return res.status(404).json({ error: 'Book not found or database error.' });
        }
        res.json({ message: 'Book status updated successfully!' });
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

app.get('/api/admin/signup-requests', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    db.all(`SELECT id, fullname, whatsapp, email, created_at FROM signup_requests ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve signup requests.' });
        res.json(rows);
    });
});

app.post('/api/admin/users', verifyToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only.' });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

    try {
        const hashedPassword = await bcrypt.hash(String(password).trim(), 10);
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')`, [username.trim(), hashedPassword], function(err) {
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
    const cover_url = req.body.cover_url || req.body.coverUrl || req.body.cover || '';

    if (!identifier || !title || !heyzine_url) {
        return res.status(400).json({ error: 'User ID, title, and Heyzine URL are required.' });
    }

    const userQuery = isNaN(identifier) ? `SELECT id FROM users WHERE username = ?` : `SELECT id FROM users WHERE id = ?`;

    db.get(userQuery, [identifier], (err, userRow) => {
        if (err || !userRow) return res.status(404).json({ error: 'Customer not found.' });

        db.run(`INSERT INTO books (user_id, title, author, heyzine_url, cover_url) VALUES (?, ?, ?, ?, ?)`, [userRow.id, title, author, heyzine_url, cover_url], function(dbErr) {
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