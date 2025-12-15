/**
 * server.js - 100% Working Backend
 */
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 1. CONFIGURATION & SETUP ---
const DATA_DIR = path.join(__dirname, 'materials');
const PUBLIC_DIR = path.join(__dirname, 'public');
const META_FILE = path.join(__dirname, 'metadata.json');
const USERS_FILE = path.join(__dirname, 'users.json');

// Exact Subject Keys (Must match Frontend)
const SUBJECTS = [
  'Artificial_Intelligence',
  'Operating_System',
  'Nosql',
  'Probability_Maths',
  'Java_Programming',
  'Coding_Lab'
];

// Ensure Directories Exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

SUBJECTS.forEach(sub => {
  const dir = path.join(DATA_DIR, sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Initialize Users (Reset on every restart to ensure you have access)
const defaultUsers = SUBJECTS.map(sub => ({
  username: sub.toLowerCase().replace(/_/g, ''), // e.g. artificialintelligence
  password: '123',
  subject: sub
}));
// Always overwrite users.json on start so you know the passwords
fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
console.log('✅ Users Reset. Password is: 123');

// Initialize Metadata
if (!fs.existsSync(META_FILE)) {
  fs.writeFileSync(META_FILE, JSON.stringify({}));
}

// --- 2. MIDDLEWARE ---
app.use(cors());
app.use(express.json()); // Crucial for Login to work
app.use(express.static(PUBLIC_DIR)); // Serves the Frontend

// --- 3. HELPERS ---
const getMetadata = () => JSON.parse(fs.readFileSync(META_FILE));
const saveMetadata = (data) => fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));
const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = (data) => fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

// In-Memory Sessions
const sessions = {};

// Auth Check Middleware
const requireAuth = (req, res, next) => {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Session expired. Please Login again.' });
  }
  req.user = sessions[token];
  next();
};

// Multer Storage (File Uploads)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const subject = req.body.subject;
    // Security: Validate subject exists
    if (!SUBJECTS.includes(subject)) {
      return cb(new Error('Invalid Subject'));
    }
    const dir = path.join(DATA_DIR, subject);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname); // Keep original name
  }
});

const upload = multer({ storage });

// --- 4. ROUTES ---

// serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = getUsers();
  
  // Find user
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    const token = crypto.randomBytes(16).toString('hex');
    sessions[token] = { username: user.username, subject: user.subject };
    console.log(`✅ Login Success: ${username}`);
    res.json({ success: true, token, subject: user.subject, username: user.username });
  } else {
    console.log(`❌ Login Failed: ${username}`);
    res.status(401).json({ success: false, error: 'Invalid Username or Password' });
  }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
    const token = req.headers['x-auth-token'];
    if(token) delete sessions[token];
    res.json({ success: true });
});

// CHANGE PASSWORD
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

// GET FILES (Visible to Everyone)
app.get('/api/files', (req, res) => {
  const metadata = getMetadata();
  const result = {};

  SUBJECTS.forEach(sub => {
    const dir = path.join(DATA_DIR, sub);
    if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        result[sub] = files.map(f => {
            const stats = fs.statSync(path.join(dir, f));
            const key = `${sub}/${f}`;
            return {
                name: f,
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

// DOWNLOAD FILE (Direct & Independent)
app.get('/api/file/:subject/:filename', (req, res) => {
    const { subject, filename } = req.params;
    const filePath = path.join(DATA_DIR, subject, filename);

    if (fs.existsSync(filePath)) {
        // Increment Download Count
        const metadata = getMetadata();
        const key = `${subject}/${filename}`;
        if (!metadata[key]) metadata[key] = {};
        metadata[key].downloads = (metadata[key].downloads || 0) + 1;
        saveMetadata(metadata);

        // Send file
        res.download(filePath); 
    } else {
        res.status(404).send("File Not Found");
    }
});

// UPLOAD (Faculty Only)
app.post('/api/upload', requireAuth, (req, res) => {
    const uploadSingle = upload.single('file');

    uploadSingle(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: "No file sent" });

        // Security Check
        if (req.user.subject !== req.body.subject) {
             fs.unlinkSync(req.file.path);
             return res.status(403).json({ error: "Access Denied: You can only upload for " + req.user.subject });
        }

        // Save Metadata
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

// DELETE (Faculty Only)
app.delete('/api/file', requireAuth, (req, res) => {
    const { subject, filename } = req.body;

    if (req.user.subject !== subject) {
        return res.status(403).json({ error: "Access Denied" });
    }

    const filePath = path.join(DATA_DIR, subject, filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        const metadata = getMetadata();
        delete metadata[`${subject}/${filename}`];
        saveMetadata(metadata);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "File not found" });
    }
});

// RENAME (Faculty Only)
app.post('/api/rename', requireAuth, (req, res) => {
    const { subject, oldName, newName } = req.body;
    if (req.user.subject !== subject) return res.status(403).json({ error: "Access Denied" });

    const oldPath = path.join(DATA_DIR, subject, oldName);
    const newPath = path.join(DATA_DIR, subject, newName);

    if (fs.existsSync(oldPath) && !fs.existsSync(newPath)) {
        fs.renameSync(oldPath, newPath);
        // update metadata logic
        const metadata = getMetadata();
        const oldKey = `${subject}/${oldName}`;
        const newKey = `${subject}/${newName}`;
        if(metadata[oldKey]) {
            metadata[newKey] = metadata[oldKey];
            delete metadata[oldKey];
            saveMetadata(metadata);
        }
        res.json({ success: true });
    } else {
        res.status(400).json({ error: "Rename failed (File missing or Name taken)" });
    }
});

// Check Duplicate
app.post('/api/check-duplicate', requireAuth, (req, res) => {
    const { subject, filename } = req.body;
    const filePath = path.join(DATA_DIR, subject, filename);
    res.json({ exists: fs.existsSync(filePath) });
});

// Start
app.listen(PORT, () => {
    console.log(`✅ Server Started on Port ${PORT}`);
    console.log(`📂 Serving public folder: ${PUBLIC_DIR}`);
});