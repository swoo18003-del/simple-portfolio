const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5501;
const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret =
  process.env.SESSION_SECRET || 'artdev-private-docs-session-secret';
const smtpHost = process.env.SMTP_HOST || '';
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpSecure = String(process.env.SMTP_SECURE || 'false') === 'true';
const smtpUser = process.env.SMTP_USER || '';
const smtpPass = process.env.SMTP_PASS || '';
const contactToEmail = process.env.CONTACT_TO_EMAIL || 'abhayrajtyagi207@gmail.com';
const contactFromEmail = process.env.CONTACT_FROM_EMAIL || smtpUser || contactToEmail;

const users = [
  {
    username: 'abhayrajtyagi',
    passwordHash: bcrypt.hashSync('Abhay@2026', 10),
    email: 'abhayrajtyagi207@gmail.com',
  }
];

const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const messageStore = path.join(__dirname, 'contact-messages.json');
const canSendMail = Boolean(smtpHost && smtpPort && smtpUser && smtpPass && contactToEmail);
const mailTransport = canSendMail
  ? nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: {
        user: smtpUser,
        pass: smtpPass
      }
    })
  : null;

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
if (isProduction) {
  app.set('trust proxy', 1);
}
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 1000 * 60 * 60
  }
}));

app.use((req, res, next) => {
  if (req.path.toLowerCase().endsWith('.pdf') && !req.session?.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

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

function storeContactMessage(entry) {
  let existingMessages = [];
  if (fs.existsSync(messageStore)) {
    try {
      existingMessages = JSON.parse(fs.readFileSync(messageStore, 'utf8'));
      if (!Array.isArray(existingMessages)) {
        existingMessages = [];
      }
    } catch (error) {
      existingMessages = [];
    }
  }

  existingMessages.push(entry);
  fs.writeFileSync(messageStore, JSON.stringify(existingMessages, null, 2));
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

app.post('/api/contact', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim();
  const message = String(req.body.message || '').trim();

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Name, email, and message are required.' });
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const contactEntry = {
    id: Date.now(),
    name,
    email,
    message,
    receivedAt: new Date().toISOString()
  };

  storeContactMessage(contactEntry);

  if (!mailTransport) {
    return res.status(503).json({
      error: 'Email delivery is not configured yet. Add SMTP settings in Render to receive contact messages.'
    });
  }

  try {
    await mailTransport.sendMail({
      from: contactFromEmail,
      to: contactToEmail,
      replyTo: email,
      subject: `New portfolio enquiry from ${name}`,
      text: [
        `Name: ${name}`,
        `Email: ${email}`,
        '',
        'Message:',
        message
      ].join('\n'),
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #111;">
          <h2>New portfolio enquiry</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Message:</strong></p>
          <p>${message.replace(/\n/g, '<br>')}</p>
        </div>
      `
    });

    res.json({ ok: true, message: 'Message sent successfully. I will get back to you soon.' });
  } catch (error) {
    console.error('Contact email send failed:', error);
    res.status(502).json({
      error: 'Message was saved, but email delivery failed. Check SMTP settings in Render.'
    });
  }
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

app.use(express.static(path.join(__dirname)));

app.listen(PORT, () => {
  console.log(`Secure document vault running on http://localhost:${PORT}`);
});
