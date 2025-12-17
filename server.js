const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'logins.json');

app.use(express.json());

function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, '[]', 'utf8');
  }
}

function readEntries() {
  ensureDataFile();
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('Failed to read data file:', err);
    return [];
  }
}

function writeEntries(entries) {
  ensureDataFile();
  fs.writeFileSync(DATA_FILE, JSON.stringify(entries, null, 2), 'utf8');
}

function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .pbkdf2Sync(secret, salt, 120000, 64, 'sha512')
    .toString('hex');
  return `${salt}:${hash}`;
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/login', (req, res) => {
  const { identifier, password } = req.body || {};

  if (!identifier || typeof identifier !== 'string' || identifier.trim().length < 3) {
    return res.status(400).json({ message: 'Identifier is required.' });
  }

  const entry = {
    id: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'),
    identifier: identifier.trim(),
    createdAt: new Date().toISOString(),
  };

  if (password) {
    entry.passwordHash = hashSecret(String(password));
  }

  const entries = readEntries();
  entries.push(entry);
  writeEntries(entries);

  return res.status(201).json({ ok: true, id: entry.id });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

