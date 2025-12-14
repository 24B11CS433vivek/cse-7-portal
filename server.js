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
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
SUBJECTS.forEach(sub => {
  const dir = path.join(DATA_DIR, sub);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

if (!fs.existsSync(USERS_FILE)) {
  const defaultUsers = SUBJECTS.map(sub => ({
    username: sub.toLowerCase().replace(/_/g, ''),
    password: 'admin',
    subject: sub
  }));
  fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ⭐ ROOT ROUTE (THIS WAS THE ISSUE)
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// In-memory sessions
const sessions = {};

// --- HELPERS ---
const getMetadata = () =>
  fs.existsSync(META_FILE) ? JSON.parse(fs.readFileSync(META_FILE)) : {};

const saveMetadata = data =>
  fs.writeFileSync(META_FILE, JSON.stringify(data, null, 2));

const getUsers = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers = data =>
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));

const requireAuth = (req, res, next) => {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions[token]) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = sessions[token];
  next();
};

// --- MULTER ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const token = req.headers['x-auth-token'];
    const user = sessions[token];
    if (!user || user.subject !== req.body.subject) {
      return cb(new Error('Permission Denied'));
    }
    cb(null, path.join(DATA_DIR, req.body.subject));
  },
  filename: (req, file, cb) => cb(null, file.originalname)
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

// --- ROUTES ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = getUsers().find(
    u => u.username === username && u.password === password
  );

  if (!user) return res.status(401).json({ success: false });

  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = { username: user.username, subject: user.subject };
  res.json({ success: true, token, subject: user.subject });
});

app.get('/api/files', (req, res) => {
  const metadata = getMetadata();
  const result = {};

  SUBJECTS.forEach(sub => {
    const dir = path.join(DATA_DIR, sub);
    if (!fs.existsSync(dir)) return (result[sub] = []);
    result[sub] = fs.readdirSync(dir).map(f => ({
      name: f,
      size:
        (fs.statSync(path.join(dir, f)).size / 1024 / 1024).toFixed(2) + ' MB',
      downloads: metadata[`${sub}/${f}`]?.downloads || 0
    }));
  });

  res.json(result);
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
