// API GATEWAY = Policy Enforcement Point (PEP). Satu-satunya pintu masuk (port 3000).
// Alur tiap request: verifikasi token -> minta keputusan ke Policy Engine -> catat audit -> teruskan (+ X-Gateway-Secret).
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const config = require('../shared/config');
const audit = require('./audit');
const tokens = require('./tokens');
const policy = require('./policy');
const authRoutes = require('./authRoutes');

const app = express();
app.disable('x-powered-by');

// /auth/* ditangani gateway sendiri (PE/PA)
app.use('/auth', authRoutes);

function makeProxy(target) {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    on: {
      // setHeader menimpa X-Gateway-Secret kiriman client (kalau ada)
      proxyReq: (proxyReq) => proxyReq.setHeader('X-Gateway-Secret', config.gatewaySecret),
      error: (err, req, res) => {
        audit.log({ subject: 'gateway', endpoint: `${req.method} ${req.url}`, result: 'deny', reason: `service tujuan tidak dapat dihubungi: ${err.code || err.message}` });
        if (res.writeHead && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Service tujuan tidak tersedia' }));
        }
      },
    },
  });
}
const proxies = {
  nilai: makeProxy(config.serviceUrls.nilai),
  transkrip: makeProxy(config.serviceUrls.transkrip),
};

// PEP untuk semua endpoint selain /auth/*
app.use((req, res, next) => {
  const endpoint = `${req.method} ${req.path}`;
  const device = req.get('x-device-id') || null;
  const reject = (status, subject, reason) => {
    audit.log({ subject, endpoint, device, result: 'deny', reason });
    return res.status(status).json({ error: 'Akses ditolak', reason });
  };

  // 1) Autentikasi: token wajib & valid
  const m = /^Bearer (.+)$/i.exec(req.get('authorization') || '');
  if (!m) return reject(401, 'anonymous', 'token tidak ada');
  let claims;
  try {
    claims = tokens.verify(m[1]);
  } catch (e) {
    return reject(401, 'anonymous', e.name === 'TokenExpiredError' ? 'token kedaluwarsa' : 'token tidak valid');
  }
  const subject = `${claims.type}:${claims.sub}`;

  // 2) Otorisasi: keputusan Policy Engine
  const decision = policy.decide({
    subject: { sub: claims.sub, role: claims.role, type: claims.type },
    method: req.method,
    path: req.path,
    query: req.query,
    deviceId: device,
    now: new Date(),
  });
  if (!decision.allow) return reject(decision.status || 403, subject, decision.reason);

  // 3) Audit + 4) teruskan ke service
  audit.log({ subject, endpoint, device, result: 'allow', reason: decision.reason });
  return proxies[decision.service](req, res, next);
});

app.listen(config.ports.gateway, () =>
  console.log(`API Gateway (PEP) berjalan di :${config.ports.gateway}`)
);
