// Pertahanan lapis kedua di sisi service (4.1 "Verifikasi ulang di service").
// 1) X-Gateway-Secret harus cocok  -> service tidak bisa diakses langsung.
// 2) Token wajib valid (tanda tangan RS256, issuer, masa berlaku) walau secret benar.
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('./config');

const publicKey = fs.readFileSync(config.keys.public); // service TIDAK punya private key

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a || '')).digest();
  const hb = crypto.createHash('sha256').update(String(b || '')).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function guard(req, res, next) {
  if (!safeEqual(req.get('x-gateway-secret'), config.gatewaySecret)) {
    return res.status(403).json({ error: 'Akses langsung ke service ditolak: X-Gateway-Secret tidak valid' });
  }
  const m = /^Bearer (.+)$/i.exec(req.get('authorization') || '');
  if (!m) return res.status(401).json({ error: 'Token tidak ada' });
  try {
    req.auth = jwt.verify(m[1], publicKey, { algorithms: ['RS256'], issuer: config.jwtIssuer });
  } catch (e) {
    return res.status(401).json({ error: 'Token tidak valid atau kedaluwarsa' });
  }
  next();
}

const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.auth.role)
    ? next()
    : res.status(403).json({ error: `Role '${req.auth.role}' tidak diizinkan di service ini` });

module.exports = { guard, requireRole };
