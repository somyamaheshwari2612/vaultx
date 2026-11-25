const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const STORAGE_DIR = path.join(__dirname, 'storage');
fs.mkdirSync(STORAGE_DIR, { recursive: true });

const db = new Database(process.env.DB_PATH || path.join(__dirname, 'vaultx.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  public_key_pem TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  owner_token_hash TEXT NOT NULL,
  blob_path TEXT,
  size INTEGER NOT NULL,
  iv_b64 TEXT NOT NULL,
  encrypted_meta_b64 TEXT,
  share_mode TEXT NOT NULL,            -- 'registered' | 'anyone'
  expires_at INTEGER,                  -- epoch ms, NULL = never
  max_downloads INTEGER,               -- NULL = unlimited
  download_count INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS recipient_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id TEXT NOT NULL,
  username TEXT,
  wrapped_aes_key_b64 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS share_links (
  file_id TEXT PRIMARY KEY,
  password_hash TEXT
);
CREATE TABLE IF NOT EXISTS access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  auth_status TEXT NOT NULL,
  remaining_views INTEGER
);
CREATE INDEX IF NOT EXISTS idx_logs_file ON access_logs(file_id);
`);

// Delete ciphertext + wrapped keys, keep the row (so audit logs still work).
function purgeFile(id) {
  const f = db.prepare('SELECT blob_path FROM files WHERE id=?').get(id);
  if (f && f.blob_path) { try { fs.unlinkSync(f.blob_path); } catch (_) {} }
  db.prepare('UPDATE files SET blob_path=NULL WHERE id=?').run(id);
  db.prepare('DELETE FROM recipient_keys WHERE file_id=?').run(id);
  db.prepare('UPDATE share_links SET password_hash=NULL WHERE file_id=?').run(id);
}

// Background TTL sweep: expired, revoked or burned files lose their blobs.
function purgeSweep() {
  const rows = db.prepare(`
    SELECT id FROM files WHERE blob_path IS NOT NULL AND (
      revoked=1 OR (expires_at IS NOT NULL AND expires_at<=?) OR
      (max_downloads IS NOT NULL AND download_count>=max_downloads))`).all(Date.now());
  rows.forEach((r) => purgeFile(r.id));
  return rows.length;
}

module.exports = { db, STORAGE_DIR, purgeFile, purgeSweep };
