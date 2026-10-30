// Endpoint /auth/* — ditangani langsung oleh gateway (Policy Engine / Policy Administrator).
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../shared/db');
const config = require('../shared/config');
const audit = require('./audit');
const tokens = require('./tokens');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

const DUMMY_HASH = bcrypt.hashSync('dummy-untuk-menyamakan-waktu', 10);

const q = {
  user: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  insertRefresh: db.prepare(
    'INSERT INTO refresh_tokens (token_hash, user_id, device_id, expires_at) VALUES (?,?,?,?)'
  ),
  refresh: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
  revoke: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?'),
  revokeAllUser: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?'),
  client: db.prepare('SELECT * FROM service_clients WHERE client_id = ?'),
};

function respond(req, res, { status, body, subject, reason, device }) {
  audit.log({
    subject,
    endpoint: `${req.method} ${req.baseUrl}${req.path}`,
    device,
    result: status < 400 ? 'allow' : 'deny',
    reason,
  });
  res.status(status).json(body);
}

function issueSession(user, device) {
  const refresh = tokens.newRefreshToken();
  q.insertRefresh.run(tokens.hashToken(refresh), user.id, device, Date.now() + config.refreshTokenTtlMs);
  return {
    access_token: tokens.signAccess(user),
    token_type: 'Bearer',
    expires_in: config.accessTokenTtlSeconds,
    refresh_token: refresh,
  };
}

// POST /auth/login — kredensial valid DAN device terdaftar
router.post('/login', (req, res) => {
  const device = req.get('x-device-id') || null;
  const { username, password } = req.body || {};
  const subject = `user:${typeof username === 'string' ? username : '?'}`;
  const fail = (status, error, reason) => respond(req, res, { status, body: { error }, subject, reason, device });

  if (typeof username !== 'string' || typeof password !== 'string') {
    return fail(400, 'username dan password wajib diisi', 'body login tidak lengkap');
  }
  const user = q.user.get(username);
  // bandingkan hash walau user tidak ada, supaya waktu respons tidak membocorkan keberadaan user
  const ok = bcrypt.compareSync(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return fail(401, 'Kredensial salah', 'kredensial tidak valid');
  if (!device) return fail(403, 'Header X-Device-ID wajib', 'X-Device-ID tidak ada');
  if (!q.device.get(user.id, device)) {
    return fail(403, 'Device tidak terdaftar untuk user ini', 'device tidak terdaftar untuk user');
  }
  respond(req, res, { status: 200, body: issueSession(user, device), subject, reason: 'login berhasil: kredensial valid dan device terdaftar', device });
});

// POST /auth/refresh — refresh token valid & belum dicabut (rotasi: token lama langsung dicabut)
router.post('/refresh', (req, res) => {
  const device = req.get('x-device-id') || null;
  const rt = req.body && req.body.refresh_token;
  const fail = (status, reason, subject = 'anonymous') =>
    respond(req, res, { status, body: { error: 'Refresh token tidak valid' }, subject, reason, device });

  if (typeof rt !== 'string') return fail(400, 'refresh_token tidak ada');
  const row = q.refresh.get(tokens.hashToken(rt));
  if (!row) return fail(401, 'refresh token tidak dikenal');
  const user = q.userById.get(row.user_id);
  const subject = `user:${user.username}`;
  if (row.revoked) {
    // Token yang sudah dicabut dipakai lagi = indikasi pencurian (assume breach): cabut semua sesi user ini.
    q.revokeAllUser.run(user.id);
    return fail(401, 'refresh token sudah dicabut dipakai ulang; semua sesi user dicabut', subject);
  }
  if (row.expires_at < Date.now()) return fail(401, 'refresh token kedaluwarsa', subject);

  q.revoke.run(row.id);
  respond(req, res, { status: 200, body: issueSession(user, row.device_id), subject, reason: 'refresh berhasil (token lama dicabut)', device });
});

// POST /auth/logout — mencabut refresh token
router.post('/logout', (req, res) => {
  const device = req.get('x-device-id') || null;
  const rt = req.body && req.body.refresh_token;
  const fail = (status, reason, subject = 'anonymous') =>
    respond(req, res, { status, body: { error: 'Refresh token tidak valid' }, subject, reason, device });

  if (typeof rt !== 'string') return fail(400, 'refresh_token tidak ada');
  const row = q.refresh.get(tokens.hashToken(rt));
  if (!row || row.revoked || row.expires_at < Date.now()) return fail(401, 'refresh token tidak valid/sudah dicabut');
  q.revoke.run(row.id);
  const user = q.userById.get(row.user_id);
  respond(req, res, { status: 200, body: { message: 'Logout berhasil, refresh token dicabut' }, subject: `user:${user.username}`, reason: 'logout: refresh token dicabut', device });
});

// POST /auth/service — Service Nilai menukar client ID + secret dengan token service (5 menit, role: service)
router.post('/service', (req, res) => {
  const { client_id, client_secret } = req.body || {};
  const subject = `service:${typeof client_id === 'string' ? client_id : '?'}`;
  const fail = () =>
    respond(req, res, { status: 401, body: { error: 'Kredensial service salah' }, subject, reason: 'client ID/secret tidak valid' });

  if (typeof client_id !== 'string' || typeof client_secret !== 'string') return fail();
  const c = q.client.get(client_id);
  const ok = bcrypt.compareSync(client_secret, c ? c.secret_hash : DUMMY_HASH);
  if (!c || !ok) return fail();
  respond(req, res, {
    status: 200,
    body: { access_token: tokens.signService(client_id), token_type: 'Bearer', expires_in: config.serviceTokenTtlSeconds },
    subject,
    reason: 'token service diterbitkan',
  });
});

// Endpoint /auth/* lain: default deny
router.use((req, res) =>
  respond(req, res, { status: 404, body: { error: 'Endpoint tidak ada' }, subject: 'anonymous', reason: 'endpoint /auth tidak dikenal (default deny)', device: req.get('x-device-id') })
);

module.exports = router;
