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
const PUBLIC_DIR = path.join(__dirname, 'public');
const META_FILE = path.join(__dirname, 'metadata.json');
const USERS_FILE = path.join(__dirname, 'users.json');

// EXACT Folder Names
const SUBJECTS = [
  'Artificial_Intelligence',
  'Operating_System',
  'Nosql',
  'Probability_Maths',
  'Java_Programming',
  'Advanced_mern'
];

// --- INITIALIZATION ---
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
SUBJECTS.forEach(sub => {
  const dir = path.join(DATA_DIR, sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Create Users
if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = SUBJECTS.map(sub => ({
        username: sub.toLowerCase().replace(/_/g, ''), 
        password: '123',
        subject: sub
    }));
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

// Create Metadata
if (!fs.existsSync(META_FILE)) fs.writeFileSync(META_FILE, JSON.stringify({}));

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// 👉 SERVE FRONTEND (This makes index.html work)
app.use(express.static(PUBLIC_DIR));

// --- HELPERS ---
const getMetadata = () => { try { return JSON.parse(fs.readFileSync(META_FILE)); } catch(e){ return {}; }};
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => { try { return JSON.parse(fs.readFileSync(USERS_FILE)); } catch(e){ return []; }};
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

const sessions = {};

// --- AUTH MIDDLEWARE ---
const requireAuth = (req, res, next) => {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }
  req.user = sessions[token];
  next();
};

// --- MULTER ---
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

const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// --- API ROUTES ---

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ success: false, error: 'Invalid Credentials' });
  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = { username: user.username, subject: user.subject };
  res.json({ success: true, token, subject: user.subject, username: user.username });
});

// Logout
app.post('/api/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if(token) delete sessions[token];
    res.json({ success: true });
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
                    type: path.extname(f).toLowerCase(),
                    size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                    uploadedAt: metadata[key]?.uploadedAt || stats.birthtime,
                    downloads: metadata[key]?.downloads || 0
                };
            });
        } else { result[sub] = []; }
    } catch(e) { result[sub] = []; }
  });
  res.json(result);
});

// Check Duplicate
app.post('/api/check-duplicate', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Subject mismatch' });
    const filePath = path.join(DATA_DIR, subject, filename);
    res.json({ exists: fs.existsSync(filePath) });
});

// Upload
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    if (req.user.subject !== req.body.subject) {
        fs.unlinkSync(req.file.path);
        return res.status(403).json({ error: 'Permission Denied' });
    }
    const metadata = getMetadata();
    const key = `${req.body.subject}/${req.file.originalname}`;
    metadata[key] = { uploadedAt: new Date(), downloads: 0, uploadedBy: req.user.username };
    saveMetadata(metadata);
    res.json({ success: true });
});

// Download
app.get('/api/file/:subject/:filename', (req, res) => {
    const filePath = path.join(DATA_DIR, req.params.subject, req.params.filename);
    if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
    if (req.query.action !== 'preview') {
        const metadata = getMetadata();
        const key = `${req.params.subject}/${req.params.filename}`;
        if (!metadata[key]) metadata[key] = {};
        metadata[key].downloads = (metadata[key].downloads || 0) + 1;
        saveMetadata(metadata);
    }
    res.sendFile(filePath);
});

// Delete
app.delete('/api/file', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Permission Denied' });
    const filePath = path.join(DATA_DIR, subject, filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        res.json({ success: true });
    } else { res.status(404).json({ error: 'File not found' }); }
});

// Rename
app.post('/api/rename', requireAuth, (req, res) => {
    const { subject, oldName, newName } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Permission Denied' });
    const oldPath = path.join(DATA_DIR, subject, oldName);
    const newPath = path.join(DATA_DIR, subject, newName);
    if (!fs.existsSync(oldPath)) return res.status(404).json({ error: 'File not found' });
    if (fs.existsSync(newPath)) return res.status(400).json({ error: 'Name exists' });
    fs.renameSync(oldPath, newPath);
    res.json({ success: true });
});

// Change Password
app.post('/api/change-password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const users = getUsers();
    const idx = users.findIndex(u => u.username === req.user.username);
    if (idx !== -1 && users[idx].password === oldPassword) {
        users[idx].password = newPassword;
        saveUsers(users);
        res.json({ success: true });
    } else { res.status(400).json({ error: 'Incorrect old password' }); }
});

// 👇👇👇 THE CRITICAL FIX 👇👇👇
// This replaces app.get('*') which caused your crash
// It ensures your frontend loads if the user refreshes the page
aapp.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});