/**
 * server.js - Crash-Proof Setup
 * Serves Frontend + Backend on the SAME Port
 */
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// --- CRITICAL: PREVENT CRASHES ---
process.on('uncaughtException', (err) => console.error('Caught exception:', err));
process.on('unhandledRejection', (reason) => console.error('Unhandled Rejection:', reason));

// --- SETUP FOLDERS ---
// We use 'materials' for storage
const DATA_DIR = path.join(__dirname, 'materials');
const META_FILE = path.join(__dirname, 'metadata.json');
const USERS_FILE = path.join(__dirname, 'users.json');

// Ensure folders exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const SUBJECTS = [
  'Artificial_Intelligence', 'Operating_System', 'Nosql',
  'Probability_Maths', 'Java_Programming', 'Advanced_mern'
];

// Initialize Subjects
SUBJECTS.forEach(sub => {
    const dir = path.join(DATA_DIR, sub);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Initialize Users (Default: 123)
if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = SUBJECTS.map(sub => ({
        username: sub.toLowerCase().replace(/_/g, ''), 
        password: '123',
        subject: sub
    }));
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

// Initialize Metadata
if (!fs.existsSync(META_FILE)) {
    fs.writeFileSync(META_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// 👉 CRUCIAL: Serve the 'public' folder where index.html lives
app.use(express.static(path.join(__dirname, 'public')));

// --- HELPERS ---
const getMetadata = () => { try { return JSON.parse(fs.readFileSync(META_FILE)); } catch(e){ return {}; }};
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e){ return []; }};

const sessions = {}; // In-memory sessions

// --- UPLOAD CONFIG ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const subject = req.body.subject;
        if (!subject || !SUBJECTS.includes(subject)) return cb(new Error('Invalid Subject'));
        const dir = path.join(DATA_DIR, subject);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// --- API ROUTES ---

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = getUsers().find(u => u.username === username && u.password === password);
    
    if (!user) return res.status(401).json({ success: false, error: 'Invalid Credentials' });
    
    const token = crypto.randomBytes(16).toString('hex');
    sessions[token] = { username: user.username, subject: user.subject };
    res.json({ success: true, token, subject: user.subject, username: user.username });
});

// Get Files
app.get('/api/files', (req, res) => {
    const metadata = getMetadata();
    const result = {};

    SUBJECTS.forEach(sub => {
        const dir = path.join(DATA_DIR, sub);
        try {
            if (fs.existsSync(dir)) {
                result[sub] = fs.readdirSync(dir).map(f => {
                    const stats = fs.statSync(path.join(dir, f));
                    const key = `${sub}/${f}`;
                    return {
                        name: f,
                        size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                        uploadedAt: metadata[key]?.uploadedAt || stats.birthtime,
                        downloads: metadata[key]?.downloads || 0
                    };
                });
            } else { result[sub] = []; }
        } catch (e) { result[sub] = []; }
    });
    res.json(result);
});

// Upload
app.post('/api/upload', upload.single('file'), (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!sessions[token] || sessions[token].subject !== req.body.subject) {
        return res.status(403).json({ error: 'Unauthorized or Subject Mismatch' });
    }
    
    if(req.file) {
        const metadata = getMetadata();
        const key = `${req.body.subject}/${req.file.originalname}`;
        metadata[key] = { uploadedAt: new Date(), downloads: 0, uploadedBy: sessions[token].username };
        saveMetadata(metadata);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'No file provided' });
    }
});

// Download & Preview
app.get('/api/file/:subject/:filename', (req, res) => {
    const filePath = path.join(DATA_DIR, req.params.subject, req.params.filename);
    if(fs.existsSync(filePath)) {
        if(req.query.action !== 'preview') {
            const meta = getMetadata();
            const key = `${req.params.subject}/${req.params.filename}`;
            if(!meta[key]) meta[key] = {};
            meta[key].downloads = (meta[key].downloads || 0) + 1;
            saveMetadata(meta);
        }
        res.sendFile(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

// Delete
app.delete('/api/file', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
    
    const { subject, filename } = req.body;
    if (sessions[token].subject !== subject) return res.status(403).json({ error: 'Permission Denied' });

    const filePath = path.join(DATA_DIR, subject, filename);
    if(fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Not found' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    // Client just clears token
    res.json({ success: true });
});

// 👉 FALLBACK: Handles any route not defined above by serving index.html
// This is what makes the frontend load!
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});