const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5501;

const users = [
  {
    username: 'abhayrajtyagi',
    passwordHash: bcrypt.hashSync('Abhay@2026', 10),
    email: 'abhayrajtyagi207@gmail.com',
  }
];

const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });

const documentFiles = [
  {
    name: 'Abhay Raj Tyagi - Resume',
    file: 'cv.pdf.pdf',
    type: 'PDF'
  }
];

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/\s+/g, '_');
    cb(null, `${Date.now()}-${safeName}`);
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf')) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'));
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'artdev-private-docs-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 1000 * 60 * 60 }
}));

app.use((req, res, next) => {
  if (req.path.toLowerCase().endsWith('.pdf') && !req.session?.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

app.use(express.static(path.join(__dirname)));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait a bit and try again.' }
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const passwordMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  req.session.user = { username: user.username, email: user.email };
  res.json({ ok: true, redirect: '/documents.html' });
});

app.get('/api/documents', requireLogin, (req, res) => {
  const uploadedFiles = fs.readdirSync(uploadDir)
    .filter((file) => file.toLowerCase().endsWith('.pdf'))
    .map((file) => ({
      name: file.replace(/\.[^.]+$/, '').replace(/_/g, ' '),
      file,
      type: 'PDF'
    }));

  res.json([...documentFiles, ...uploadedFiles]);
});

app.post('/api/upload', requireLogin, upload.single('document'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Please upload a PDF file.' });
  }

  res.json({ ok: true, file: req.file.filename, message: 'Document uploaded successfully.' });
});

app.get('/api/download/:file', requireLogin, (req, res) => {
  const requestedFile = path.basename(req.params.file);
  const candidatePaths = [
    path.join(__dirname, requestedFile),
    path.join(uploadDir, requestedFile)
  ];

  const safeFilePath = candidatePaths.find((filePath) => fs.existsSync(filePath));

  if (!safeFilePath) {
    return res.status(404).json({ error: 'Document not found' });
  }

  res.download(safeFilePath, requestedFile);
});

app.get('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/documents.html', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/dashboard.html');
  }
  res.sendFile(path.join(__dirname, 'documents.html'));
});

app.listen(PORT, () => {
  console.log(`Secure document vault running on http://localhost:${PORT}`);
});
