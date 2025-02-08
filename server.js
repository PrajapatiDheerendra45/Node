const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const cors = require('cors');
const app = express();
const multer = require('multer');  // Add multer for file handling
const path = require('path');      // To manage file paths
const fs = require('fs');

// Ensure the uploads directory exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}


app.use(cors());
app.use(express.json());

// MySQL Connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Praja@123',
    database: 'user_management',
});

// Connect to DB
db.connect(err => {
    if (err) throw err;
    console.log('Connected to MySQL');
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// 1. Login auth with email, password, token generation
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM newusers WHERE email = ?', [email], (err, result) => {
        if (err) throw err;
        if (result.length === 0) return res.status(400).json({ message: 'User not found' });
        const user = result[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
            const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' });
            res.json({ token });
        });
    });
});


// Register a new user
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Store files in 'uploads' directory
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Give unique file names
    },
});

const upload = multer({ storage });

// Register a new user (with file upload)
app.post('/register', upload.single('profileImage'), (req, res) => {
    const { email, password } = req.body;
    const profileImage = req.file ? req.file.path : null;  // Save the file path in the database

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    // Check if user already exists
    db.query('SELECT * FROM newusers WHERE email = ?', [email], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) throw err;

            // Insert user into the database (storing file path)
            db.query('INSERT INTO newusers (email, password, profileImage) VALUES (?, ?, ?)',
                [email, hashedPassword, profileImage],
                (err, result) => {
                    if (err) throw err;
                    res.json({ message: 'User registered successfully' });
                });
        });
    });
});


// 2. Create, Update, Delete user
app.post('/user', (req, res) => {
    const { email, password, profileImage } = req.body;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;
        db.query('INSERT INTO newusers (email, password, profileImage) VALUES (?, ?, ?)',
            [email, hashedPassword, profileImage],
            (err, result) => {
                if (err) throw err;
                res.json({ message: 'User created successfully' });
            });
    });
});

app.put('/user/:id', upload.single('profileImage'), (req, res) => {
    const { email } = req.body;
    let profileImage = req.body.profileImage; // Default to existing profileImage

    // If a new file is uploaded, update profileImage with the file path
    if (req.file) {
        profileImage = req.file.path;
    }

    db.query(
        'UPDATE newusers SET email = ?, profileImage = ? WHERE id = ?',
        [email, profileImage, req.params.id],
        (err, result) => {
            if (err) {
                console.error('Update error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            res.json({ message: 'User updated successfully' });
        }
    );
});

app.delete('/user/:id', (req, res) => {
    db.query('DELETE FROM newusers WHERE id = ?', [req.params.id], (err, result) => {
        if (err) throw err;
        res.json({ message: 'User deleted successfully' });
    });
});


app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    db.query('SELECT id, email, profileImage FROM newusers WHERE id = ?', [userId], (err, result) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (result.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(result[0]); // Send user data as response
    });
});

// 3. Fetch newusers from third-party API and store them


app.get('/newusers', (req, res) => {
    db.query('SELECT id, email, profileImage FROM newusers', (err, result) => {
        if (err) throw err;
        res.json(result);  // Send the result back as a JSON response
    });
});

app.listen(5000, () => {
    console.log('Server running on port 5000');
});
