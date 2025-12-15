/**
 * server.js - Complete Backend for Study Material Portal
 */
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
// const mime = require('mime-types'); // Optional, express handles basic mime types well

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURATION ---
const DATA_DIR = path.join(__dirname, 'materials');
const PUBLIC_DIR = path.join(__dirname, 'public');
const META_FILE = path.join(__dirname, 'metadata.json');
const USERS_FILE = path.join(__dirname, 'users.json');

const SUBJECTS = [
  'Artificial_Intelligence',
  'Operating_System',
  'Nosql',
  'Probability_Maths',
  'Java_Programming',
  'Coding_Lab'
];

// --- INITIALIZATION ---
// Create directories
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
SUBJECTS.forEach(sub => {
  const dir = path.join(DATA_DIR, sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Create Users File if missing
if (!fs.existsSync(USERS_FILE)) {
  const defaultUsers = SUBJECTS.map(sub => ({
    username: sub.toLowerCase().replace(/_/g, ''),
    password: '123', // Default password
    subject: sub
  }));
  fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
  console.log('⚠️ users.json created with default password: 123');
}

// Create Metadata File if missing
if (!fs.existsSync(META_FILE)) {
  fs.writeFileSync(META_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(PUBLIC_DIR)); // Serves index.html, css, js

// --- HELPERS ---
const getMetadata = () => JSON.parse(fs.readFileSync(META_FILE));
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

// In-memory sessions
const sessions = {};

// Auth Middleware
const requireAuth = (req, res, next) => {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Unauthorized. Please login again.' });
  }
  req.user = sessions[token];
  next();
};

// --- MULTER CONFIG (Permissions Check) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // We can't easily check headers inside diskStorage destination in all versions,
    // so we rely on the route handler to validate, but we organize by subject here.
    const subject = req.body.subject;
    if (!SUBJECTS.includes(subject)) {
        return cb(new Error('Invalid Subject'));
    }
    const dir = path.join(DATA_DIR, subject);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, file.originalname)
});

const upload = multer({ 
    storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});


// --- ROUTES ---

// 1. Serve Frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// 2. Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) return res.status(401).json({ success: false, error: 'Invalid Credentials' });

  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = { username: user.username, subject: user.subject };
  res.json({ success: true, token, subject: user.subject, username: user.username });
});

// 3. Logout
app.post('/api/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if(token) delete sessions[token];
    res.json({ success: true });
});

// 4. Get Files (Public)
app.get('/api/files', (req, res) => {
  const metadata = getMetadata();
  const result = {};

  SUBJECTS.forEach(sub => {
    const dir = path.join(DATA_DIR, sub);
    if (!fs.existsSync(dir)) {
        result[sub] = [];
        return;
    }
    
    try {
        const files = fs.readdirSync(dir);
        result[sub] = files.map(f => {
            const filePath = path.join(dir, f);
            const stats = fs.statSync(filePath);
            const key = `${sub}/${f}`;
            
            return {
                name: f,
                type: path.extname(f).toLowerCase(),
                size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                uploadedAt: metadata[key]?.uploadedAt || stats.birthtime,
                downloads: metadata[key]?.downloads || 0
            };
        });
    } catch (e) {
        result[sub] = [];
    }
  });

  res.json(result);
});

// 5. Download / Preview
app.get('/api/file/:subject/:filename', (req, res) => {
    const { subject, filename } = req.params;
    const { action } = req.query; // ?action=preview
    const filePath = path.join(DATA_DIR, subject, filename);

    if (!fs.existsSync(filePath)) return res.status(404).send('File not found');

    // Update download count if it's a download (not just preview)
    if (action !== 'preview') {
        const metadata = getMetadata();
        const key = `${subject}/${filename}`;
        if (!metadata[key]) metadata[key] = {};
        metadata[key].downloads = (metadata[key].downloads || 0) + 1;
        saveMetadata(metadata);
        res.download(filePath);
    } else {
        res.sendFile(filePath);
    }
});

// 6. Check Duplicate (Protected)
app.post('/api/check-duplicate', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Mismatch subject' });
    
    const filePath = path.join(DATA_DIR, subject, filename);
    res.json({ exists: fs.existsSync(filePath) });
});

// 7. Upload File (Protected)
app.post('/api/upload', requireAuth, (req, res) => {
    const uploadSingle = upload.single('file');

    uploadSingle(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: 'No file provided' });
        
        // Double check permission match
        if (req.user.subject !== req.body.subject) {
            fs.unlinkSync(req.file.path); // Delete unauthorised upload
            return res.status(403).json({ error: 'You can only upload for your subject' });
        }

        // Update Metadata
        const metadata = getMetadata();
        const key = `${req.body.subject}/${req.file.originalname}`;
        metadata[key] = {
            uploadedAt: new Date(),
            downloads: 0,
            uploadedBy: req.user.username
        };
        saveMetadata(metadata);

        res.json({ success: true });
    });
});

// 8. Delete File (Protected)
app.delete('/api/file', requireAuth, (req, res) => {
    const { subject, filename } = req.body;

    if (req.user.subject !== subject) return res.status(403).json({ error: 'Permission Denied' });

    const filePath = path.join(DATA_DIR, subject, filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        
        // Clean metadata
        const metadata = getMetadata();
        delete metadata[`${subject}/${filename}`];
        saveMetadata(metadata);
        
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// 9. Rename File (Protected)
app.post('/api/rename', requireAuth, (req, res) => {
    const { subject, oldName, newName } = req.body;

    if (req.user.subject !== subject) return res.status(403).json({ error: 'Permission Denied' });
    if (!oldName || !newName) return res.status(400).json({ error: 'Names required' });

    const oldPath = path.join(DATA_DIR, subject, oldName);
    const newPath = path.join(DATA_DIR, subject, newName);

    if (!fs.existsSync(oldPath)) return res.status(404).json({ error: 'File not found' });
    if (fs.existsSync(newPath)) return res.status(400).json({ error: 'New name already exists' });

    // Rename file
    fs.renameSync(oldPath, newPath);

    // Update metadata key
    const metadata = getMetadata();
    if (metadata[`${subject}/${oldName}`]) {
        metadata[`${subject}/${newName}`] = metadata[`${subject}/${oldName}`];
        delete metadata[`${subject}/${oldName}`];
        saveMetadata(metadata);
    }

    res.json({ success: true });
});

// 10. Change Password (Protected)
app.post('/api/change-password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    
    const users = getUsers();
    const idx = users.findIndex(u => u.username === req.user.username);

    if (idx === -1) return res.status(404).json({ error: 'User not found' });
    if (users[idx].password !== oldPassword) return res.status(400).json({ error: 'Incorrect old password' });

    users[idx].password = newPassword;
    saveUsers(users);

    res.json({ success: true });
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});