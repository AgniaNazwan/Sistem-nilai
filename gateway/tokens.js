// Penerbitan & verifikasi token (bagian Policy Administrator).
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const config = require('../shared/config');

const privateKey = fs.readFileSync(config.keys.private);
const publicKey = fs.readFileSync(config.keys.public);
const opts = { algorithm: 'RS256', issuer: config.jwtIssuer };

// Access token user: berlaku 10 menit, berisi sub + role.
function signAccess(user) {
  return jwt.sign({ sub: user.username, role: user.role, type: 'user' }, privateKey, {
    ...opts,
    expiresIn: config.accessTokenTtl,
  });
}

// Token service: berlaku 5 menit, role: service.
function signService(clientId) {
  return jwt.sign({ sub: clientId, role: 'service', type: 'service' }, privateKey, {
    ...opts,
    expiresIn: config.serviceTokenTtl,
  });
}

function verify(token) {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'], issuer: config.jwtIssuer });
}

// Refresh token: string acak; yang disimpan di DB hanya hash-nya (agar bocornya DB tidak membocorkan token).
const newRefreshToken = () => crypto.randomBytes(48).toString('hex');
const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

module.exports = { signAccess, signService, verify, newRefreshToken, hashToken };
