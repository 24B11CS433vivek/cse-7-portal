/**
 * server.js - Backend for Study Material Portal
 * Fixed: Multer Ordering, Permissions, and User Mapping
 */
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// --- CONFIGURATION ---
const DATA_DIR = path.join(__dirname, 'materials');
const PUBLIC_DIR = path.join(__dirname, 'public');
const META_FILE = path.join(__dirname, 'metadata.json');
const USERS_FILE = path.join(__dirname, 'users.json');

// EXACT Folder Names (Do not change these keys)
const SUBJECTS = [
  'Artificial_Intelligence',
  'Operating_System',
  'Nosql',
  'Probability_Maths',
  'Java_Programming',
  'Coding_Lab'
];

// --- INITIALIZATION ---
// 1. Create Directories
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
SUBJECTS.forEach(sub => {
  const dir = path.join(DATA_DIR, sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// 2. Create Users (Reset on start to ensure you have access)
// Maps "artificialintelligence" -> "Artificial_Intelligence" folder
const defaultUsers = SUBJECTS.map(sub => ({
  username: sub.toLowerCase().replace(/_/g, ''), 
  password: '123',
  subject: sub
}));

fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
console.log('✅ Users Initialized. Password for all is: 123');

// 3. Create Metadata
if (!fs.existsSync(META_FILE)) {
  fs.writeFileSync(META_FILE, JSON.stringify({}));
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// --- HELPERS ---
const getMetadata = () => JSON.parse(fs.readFileSync(META_FILE));
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

// Session Store
const sessions = {};

// Auth Middleware
const requireAuth = (req, res, next) => {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }
  req.user = sessions[token];
  next();
};

// --- MULTER (FILE UPLOAD) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // req.body.subject must be sent BEFORE the file in Frontend
    const subject = req.body.subject;
    
    if (!subject || !SUBJECTS.includes(subject)) {
        return cb(new Error('Invalid Subject: ' + subject));
    }
    
    // Create folder if missing (Double check)
    const dir = path.join(DATA_DIR, subject);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB Limit
});

// --- ROUTES ---

// 1. Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();
  const user = users.find(u => u.username === username && u.password === password);

  if (!user) return res.status(401).json({ success: false, error: 'Invalid Credentials' });

  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = { username: user.username, subject: user.subject };
  
  res.json({ success: true, token, subject: user.subject, username: user.username });
});

// 2. Logout
app.post('/api/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if(token) delete sessions[token];
    res.json({ success: true });
});

// 3. Get Files (Public)
app.get('/api/files', (req, res) => {
  const metadata = getMetadata();
  const result = {};

  SUBJECTS.forEach(sub => {
    const dir = path.join(DATA_DIR, sub);
    if (fs.existsSync(dir)) {
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
    } else {
        result[sub] = [];
    }
  });
  res.json(result);
});

// 4. Download / Preview
app.get('/api/file/:subject/:filename', (req, res) => {
    const { subject, filename } = req.params;
    const { action } = req.query; 
    const filePath = path.join(DATA_DIR, subject, filename);

    if (!fs.existsSync(filePath)) return res.status(404).send('File not found');

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

// 5. Check Duplicate
app.post('/api/check-duplicate', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Subject mismatch' });
    const filePath = path.join(DATA_DIR, subject, filename);
    res.json({ exists: fs.existsSync(filePath) });
});

// 6. Upload (Protected & Scoped)
app.post('/api/upload', requireAuth, (req, res) => {
    // Wrapper to catch multer errors
    const uploadSingle = upload.single('file');

    uploadSingle(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        // STRICT Permission Check
        if (req.user.subject !== req.body.subject) {
            fs.unlinkSync(req.file.path); // Delete if they cheated
            return res.status(403).json({ error: 'Permission Denied: You cannot upload to this subject.' });
        }

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

// 7. Delete (Protected & Scoped)
app.delete('/api/file', requireAuth, (req, res) => {
    const { subject, filename } = req.body;

    if (req.user.subject !== subject) return res.status(403).json({ error: 'Permission Denied' });

    const filePath = path.join(DATA_DIR, subject, filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        const metadata = getMetadata();
        delete metadata[`${subject}/${filename}`];
        saveMetadata(metadata);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// 8. Rename (Protected & Scoped)
app.post('/api/rename', requireAuth, (req, res) => {
    const { subject, oldName, newName } = req.body;
    
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Permission Denied' });

    const oldPath = path.join(DATA_DIR, subject, oldName);
    const newPath = path.join(DATA_DIR, subject, newName);

    if (!fs.existsSync(oldPath)) return res.status(404).json({ error: 'File not found' });
    if (fs.existsSync(newPath)) return res.status(400).json({ error: 'New name already exists' });

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
});

// 9. Change Password
app.post('/api/change-password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const users = getUsers();
    const idx = users.findIndex(u => u.username === req.user.username);

    if (idx !== -1 && users[idx].password === oldPassword) {
        users[idx].password = newPassword;
        saveUsers(users);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Incorrect old password' });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});