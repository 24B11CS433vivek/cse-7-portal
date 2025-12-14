/**
 * server.js - Backend for Study Material Portal
 */
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const mime = require('mime-types');

const app = express();
const PORT = 3000;

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
// 1. Create Directories
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
SUBJECTS.forEach(sub => {
    const dir = path.join(DATA_DIR, sub);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// 2. Create Default Users (if not exists)
if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = SUBJECTS.map(sub => ({
        username: sub.toLowerCase().replace(/_/g, ''), // e.g., 'nosql'
        password: 'admin', // Default password
        subject: sub
    }));
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
    console.log('✅ Default users created in users.json (Pass: admin)');
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// In-memory session store
const sessions = {}; 

// --- HELPERS ---
const getMetadata = () => fs.existsSync(META_FILE) ? JSON.parse(fs.readFileSync(META_FILE)) : {};
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

// Auth Middleware
const requireAuth = (req, res, next) => {
    const token = req.headers['x-auth-token'];
    if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });
    req.user = sessions[token];
    next();
};

// --- MULTER CONFIG ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Double check auth inside multer
        const token = req.headers['x-auth-token'];
        const user = sessions[token];
        if (!user || user.subject !== req.body.subject) {
            return cb(new Error('Permission Denied'));
        }
        cb(null, path.join(DATA_DIR, req.body.subject));
    },
    filename: (req, file, cb) => {
        // Use original name
        cb(null, file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    fileFilter: (req, file, cb) => {
        const allowed = /pdf|doc|docx|ppt|pptx|jpg|jpeg|png/;
        const ext = path.extname(file.originalname).toLowerCase().replace('.', '');
        if (allowed.test(ext)) return cb(null, true);
        cb(new Error('Invalid file type'));
    }
});

// --- ROUTES ---

// 1. Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const users = getUsers();
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        const token = crypto.randomBytes(16).toString('hex');
        sessions[token] = { username: user.username, subject: user.subject };
        res.json({ success: true, token, subject: user.subject, username: user.username });
    } else {
        res.status(401).json({ success: false, message: 'Invalid Credentials' });
    }
});

// 2. Change Password (Secure)
app.post('/api/change-password', requireAuth, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const users = getUsers();
    const idx = users.findIndex(u => u.username === req.user.username);
    
    if (idx !== -1) {
        // Verify Old Password
        if (users[idx].password !== oldPassword) {
            return res.status(401).json({ error: 'Incorrect Old Password' });
        }

        // Update to New Password
        users[idx].password = newPassword;
        saveUsers(users);
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'User not found' });
    }
});

// 3. Get Files
app.get('/api/files', (req, res) => {
    const metadata = getMetadata();
    const result = {};

    SUBJECTS.forEach(sub => {
        const dir = path.join(DATA_DIR, sub);
        const files = fs.readdirSync(dir);
        
        result[sub] = files.map(f => {
            const filepath = path.join(dir, f);
            const stats = fs.statSync(filepath);
            const key = `${sub}/${f}`;
            return {
                name: f,
                size: (stats.size / 1024 / 1024).toFixed(2) + ' MB',
                type: path.extname(f).toLowerCase(),
                uploadedAt: metadata[key]?.uploadedAt || stats.birthtime,
                downloads: metadata[key]?.downloads || 0
            };
        }).sort((a,b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    });
    res.json(result);
});

// 4. Upload File
app.post('/api/upload', (req, res) => {
    const uploadSingle = upload.single('file');
    
    uploadSingle(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: 'No file provided' });

        const { subject } = req.body;
        const key = `${subject}/${req.file.originalname}`;
        const metadata = getMetadata();
        
        metadata[key] = { uploadedAt: new Date(), downloads: 0 };
        saveMetadata(metadata);
        
        res.json({ success: true });
    });
});

// 5. Check Duplicate
app.post('/api/check-duplicate', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Denied' });
    
    const exists = fs.existsSync(path.join(DATA_DIR, subject, filename));
    res.json({ exists });
});

// 6. Delete File
app.delete('/api/file', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Denied' });

    const p = path.join(DATA_DIR, subject, filename);
    if (fs.existsSync(p)) {
        fs.unlinkSync(p);
        const metadata = getMetadata();
        delete metadata[`${subject}/${filename}`];
        saveMetadata(metadata);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// 7. Rename File
app.post('/api/rename', requireAuth, (req, res) => {
    const { subject, oldName, newName } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: 'Denied' });

    // Prevent extension change
    if (path.extname(oldName) !== path.extname(newName)) {
        return res.status(400).json({ error: 'Extension must remain the same' });
    }

    const oldPath = path.join(DATA_DIR, subject, oldName);
    const newPath = path.join(DATA_DIR, subject, newName);

    if (fs.existsSync(newPath)) return res.status(400).json({ error: 'File name already exists' });

    if (fs.existsSync(oldPath)) {
        fs.renameSync(oldPath, newPath);
        
        // Migrate Metadata
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
        res.status(404).json({ error: 'File not found' });
    }
});

// 8. Serve File (Preview/Download)
app.get('/api/file/:subject/:filename', (req, res) => {
    const { subject, filename } = req.params;
    const p = path.join(DATA_DIR, subject, filename);

    if (fs.existsSync(p)) {
        // Update Count
        const metadata = getMetadata();
        const key = `${subject}/${filename}`;
        if (!metadata[key]) metadata[key] = { uploadedAt: new Date(), downloads: 0 };
        metadata[key].downloads++;
        saveMetadata(metadata);

        // Serve
        const type = mime.lookup(p) || 'application/octet-stream';
        res.setHeader('Content-Type', type);
        
        // Inline for PDF/Images, Attachment for others
        if (req.query.action === 'preview' && (type === 'application/pdf' || type.startsWith('image/'))) {
            res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
        } else {
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        }
        
        fs.createReadStream(p).pipe(res);
    } else {
        res.status(404).send('Not Found');
    }
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));