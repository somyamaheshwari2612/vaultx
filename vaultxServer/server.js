require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { db, STORAGE_DIR, purgeFile, purgeSweep } = require('./db');
const passwords = require('./passwords');
const { authorizeDownload, requireOwner, logAccess, fileState, remainingViews, sha256 } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';
const MAX_MB = Number(process.env.MAX_UPLOAD_MB || 50);
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000;

app.set('trust proxy', true);
app.use(cors({ origin: true }));            // open for hackathon LAN; lock down in prod
app.use(express.json({ limit: '1mb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_MB * 1024 * 1024 } });

const rid = (n) => crypto.randomBytes(n).toString('base64url');
const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

app.get('/api/health', (_req, res) => res.json({ ok: true, hash: passwords.name, time: Date.now() }));

// ---------- USER PUBLIC-KEY DIRECTORY ----------
app.post('/api/users/register', (req, res) => {
  const { username, publicKeyPem, fingerprint } = req.body || {};
  if (!USERNAME_RE.test(username || '') || !publicKeyPem || !fingerprint)
    return res.status(400).json({ error: 'invalid_input' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username))
    return res.status(409).json({ error: 'username_taken' });
  db.prepare('INSERT INTO users VALUES (?,?,?,?)').run(username, publicKeyPem, fingerprint, Date.now());
  res.status(201).json({ ok: true, username, fingerprint });
});

app.get('/api/users/:username/pubkey', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(req.params.username);
  if (!u) return res.status(404).json({ error: 'user_not_found' });
  res.json({ username: u.username, publicKeyPem: u.public_key_pem, fingerprint: u.fingerprint });
});

// ---------- UPLOAD ----------
// multipart/form-data: file field "encryptedBlob" + text fields
app.post('/api/vault/upload', upload.single('encryptedBlob'), async (req, res, next) => {
  try {
    const b = req.body;
    if (!req.file || !b.ivB64) return res.status(400).json({ error: 'missing_blob_or_iv' });

    let mode = String(b.shareMode || '').toLowerCase();
    mode = ['registered', 'a'].includes(mode) ? 'registered' : ['anyone', 'b', 'link'].includes(mode) ? 'anyone' : null;
    if (!mode) return res.status(400).json({ error: 'invalid_shareMode' });
    if (mode === 'registered' && !b.wrappedAesKeyB64) return res.status(400).json({ error: 'wrapped_key_required' });

    let expiresAt = null;
    if (b.expiresAt) {
      expiresAt = isNaN(Number(b.expiresAt)) ? Date.parse(b.expiresAt) : Number(b.expiresAt);
      if (!expiresAt || expiresAt <= Date.now()) return res.status(400).json({ error: 'expiry_in_past' });
      if (expiresAt - Date.now() > MAX_TTL_MS + 60000) return res.status(400).json({ error: 'expiry_over_7_days' });
    }
    const maxDl = Number(b.maxDownloads) > 0 ? Math.floor(Number(b.maxDownloads)) : null;

    const fileId = rid(9), ownerToken = rid(24);
    const blobPath = path.join(STORAGE_DIR, fileId + '.bin');
    fs.writeFileSync(blobPath, req.file.buffer);

    const secret = b.password || b.passwordHash;           // value from client; hashed again with Argon2id
    const pwHash = secret ? await passwords.hash(String(secret)) : null;

    db.transaction(() => {
      db.prepare(`INSERT INTO files (id, owner_token_hash, blob_path, size, iv_b64, encrypted_meta_b64,
                  share_mode, expires_at, max_downloads, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
        .run(fileId, sha256(ownerToken), blobPath, req.file.size, b.ivB64, b.encryptedMetaB64 || null,
             mode, expiresAt, maxDl, Date.now());
      db.prepare('INSERT INTO share_links (file_id, password_hash) VALUES (?,?)').run(fileId, pwHash);
      if (b.wrappedAesKeyB64)
        db.prepare('INSERT INTO recipient_keys (file_id, username, wrapped_aes_key_b64) VALUES (?,?,?)')
          .run(fileId, b.recipientUsername || null, b.wrappedAesKeyB64);
    })();
    res.status(201).json({ fileId, ownerToken });
  } catch (e) { next(e); }
});

// ---------- META (public, never counts as a download) ----------
app.get('/api/vault/:id/meta', (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!f) return res.status(404).json({ error: 'not_found' });
  const state = fileState(f);
  if (state !== 'active') return res.status(410).json({ error: state });
  const link = db.prepare('SELECT password_hash FROM share_links WHERE file_id=?').get(f.id);
  res.json({
    fileId: f.id, shareMode: f.share_mode, ivB64: f.iv_b64, encryptedMetaB64: f.encrypted_meta_b64,
    size: f.size, expiresAt: f.expires_at, maxDownloads: f.max_downloads,
    remainingViews: remainingViews(f), passwordRequired: !!(link && link.password_hash),
  });
});

// ---------- DOWNLOAD ----------
const consume = db.transaction((id) => {            // atomic: two simultaneous requests can't both take the last view
  const f = db.prepare('SELECT * FROM files WHERE id=?').get(id);
  if (fileState(f) !== 'active') return null;
  db.prepare('UPDATE files SET download_count=download_count+1 WHERE id=?').run(id);
  return { ...f, download_count: f.download_count + 1 };
});

app.post('/api/vault/:id/download', authorizeDownload, (req, res, next) => {
  try {
    const f = consume(req.params.id);
    if (!f) { logAccess(req.params.id, req, 'denied_limit_reached', 0); return res.status(410).json({ error: 'limit_reached' }); }
    if (!f.blob_path || !fs.existsSync(f.blob_path)) return res.status(410).json({ error: 'purged' });

    const blob = fs.readFileSync(f.blob_path);
    const rk = db.prepare('SELECT wrapped_aes_key_b64 FROM recipient_keys WHERE file_id=?').get(f.id);
    const remaining = remainingViews(f);
    logAccess(f.id, req, 'granted', remaining);

    res.json({
      encryptedBlob: blob.toString('base64'),          // base64 string -> decode to bytes on the client
      ivB64: f.iv_b64,
      encryptedMetaB64: f.encrypted_meta_b64,
      wrappedAesKeyB64: rk ? rk.wrapped_aes_key_b64 : null,
      remainingViews: remaining,
    });
    if (remaining === 0) purgeFile(f.id);               // burn-after-reading
  } catch (e) { next(e); }
});

// ---------- OWNER: LOGS / REVOKE / INSPECT ----------
app.get('/api/vault/:id/logs', requireOwner, (req, res) => {
  const f = req.vaultFile;
  const logs = db.prepare(`SELECT ts AS timestamp, ip, user_agent AS userAgent, auth_status AS authStatus,
                           remaining_views AS remainingViews FROM access_logs WHERE file_id=? ORDER BY id DESC`).all(f.id);
  res.json({ fileId: f.id, status: fileState(f), downloadCount: f.download_count, maxDownloads: f.max_downloads, logs });
});

app.delete('/api/vault/:id/revoke', requireOwner, (req, res) => {
  const f = req.vaultFile;
  db.prepare('UPDATE files SET revoked=1 WHERE id=?').run(f.id);
  purgeFile(f.id);                                      // wipes wrapped keys, share token/password, ciphertext
  logAccess(f.id, req, 'revoked_by_owner', 0);
  res.json({ ok: true, fileId: f.id, status: 'revoked' });
});

// Extra for Person 4's Hex Inspector: first 512 bytes of ciphertext only (never the full blob)
app.get('/api/vault/:id/inspect', (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!f) return res.status(404).json({ error: 'not_found' });
  if (!f.blob_path || !fs.existsSync(f.blob_path)) return res.status(410).json({ error: 'purged' });
  const fd = fs.openSync(f.blob_path, 'r'); const buf = Buffer.alloc(Math.min(512, f.size));
  fs.readSync(fd, buf, 0, buf.length, 0); fs.closeSync(fd);
  const hex = buf.toString('hex').match(/.{1,2}/g).join(' ');
  res.json({ fileId: f.id, hexPreview: hex, bytesShown: buf.length, totalBytes: f.size, ivB64: f.iv_b64,
    dbRow: { share_mode: f.share_mode, expires_at: f.expires_at, max_downloads: f.max_downloads,
             download_count: f.download_count, revoked: f.revoked, encrypted_meta_b64: f.encrypted_meta_b64 } });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file_too_large', maxMB: MAX_MB });
  res.status(500).json({ error: 'server_error' });
});

setInterval(() => { const n = purgeSweep(); if (n) console.log(`[purge] cleared ${n} blob(s)`); },
  Number(process.env.PURGE_INTERVAL_SEC || 30) * 1000);

app.listen(PORT, HOST, () => console.log(`VaultX server on http://${HOST}:${PORT} (hash: ${passwords.name})`));
