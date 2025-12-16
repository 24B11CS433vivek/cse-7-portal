/**
 * server.js - Crash-Proof Version
 * Serves Frontend + Backend together
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
// If a file error happens, this keeps the server alive
process.on('uncaughtException', (err) => console.error('Caught exception:', err));
process.on('unhandledRejection', (reason) => console.error('Unhandled Rejection:', reason));

// --- CONFIGURATION ---
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

// Initialize Users
if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = SUBJECTS.map(sub => ({
        username: sub.toLowerCase().replace(/_/g, ''), 
        password: '123',
        subject: sub
    }));
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

if (!fs.existsSync(META_FILE)) fs.writeFileSync(META_FILE, JSON.stringify({}));

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// 👉 IMPORTANT: Serve the 'public' folder (Your Frontend)
app.use(express.static(path.join(__dirname, 'public')));

// --- HELPERS ---
const getMetadata = () => { try { return JSON.parse(fs.readFileSync(META_FILE)); } catch(e){ return {}; }};
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e){ return []; }};

const sessions = {};

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

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = getUsers().find(u => u.username === username && u.password === password);
    
    if (!user) return res.status(401).json({ success: false, error: 'Invalid Credentials' });
    
    const token = crypto.randomBytes(16).toString('hex');
    sessions[token] = { username: user.username, subject: user.subject };
    res.json({ success: true, token, subject: user.subject, username: user.username });
});

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
                        type: path.extname(f), // Added for icon logic
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

app.post('/api/upload', upload.single('file'), (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!sessions[token] || sessions[token].subject !== req.body.subject) {
        return res.status(403).json({ error: 'Unauthorized' });
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

// Rename Route
app.post('/api/rename', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
    
    const { subject, oldName, newName } = req.body;
    if (sessions[token].subject !== subject) return res.status(403).json({ error: 'Permission Denied' });

    const oldPath = path.join(DATA_DIR, subject, oldName);
    const newPath = path.join(DATA_DIR, subject, newName);

    if (fs.existsSync(oldPath) && !fs.existsSync(newPath)) {
        fs.renameSync(oldPath, newPath);
        // Update metadata
        const metadata = getMetadata();
        const oldKey = `${subject}/${oldName}`;
        const newKey = `${subject}/${newName}`;
        if (metadata[oldKey]) {
            metadata[newKey] = metadata[oldKey];
            delete metadata[oldKey];
            saveMetadata(metadata);
        }
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Rename failed' });
    }
});

// Change Password
app.post('/api/change-password', (req, res) => {
    const token = req.headers['x-auth-token'];
    if (!sessions[token]) return res.status(401).json({ error: 'Unauthorized' });

    const { oldPassword, newPassword } = req.body;
    const users = getUsers();
    const idx = users.findIndex(u => u.username === sessions[token].username);
    
    if (idx !== -1 && users[idx].password === oldPassword) {
        users[idx].password = newPassword;
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Incorrect old password' });
    }
});

app.post('/api/logout', (req, res) => {
    res.json({ success: true });
});

// 👉 CATCH-ALL: This makes the frontend load properly
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});