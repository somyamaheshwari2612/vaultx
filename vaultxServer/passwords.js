// Argon2id by default; falls back to bcryptjs if the argon2 native build fails (Windows).
let impl;
try {
  const argon2 = require('argon2');
  impl = {
    name: 'argon2id',
    hash: (p) => argon2.hash(p, { type: argon2.argon2id }),
    verify: (h, p) => argon2.verify(h, p).catch(() => false),
  };
} catch (e) {
  const bcrypt = require('bcryptjs');
  impl = {
    name: 'bcrypt-fallback',
    hash: (p) => bcrypt.hash(p, 10),
    verify: (h, p) => bcrypt.compare(p, h).catch(() => false),
  };
}
module.exports = impl;
