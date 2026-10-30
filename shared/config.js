// Konfigurasi bersama. Semua nilai bisa di-override lewat environment variable.
const path = require('path');
const root = path.join(__dirname, '..');

process.env.TZ = process.env.TZ || 'Asia/Jakarta';

function parseHours(s) {
  const m = /^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/.exec(s);
  if (!m) throw new Error('ACCESS_HOURS harus berformat "HH:MM-HH:MM", contoh "07:00-21:00"');
  return { start: +m[1] * 60 + +m[2], end: +m[3] * 60 + +m[4] };
}

const ports = {
  gateway: +process.env.GATEWAY_PORT || 3000,
  nilai: +process.env.NILAI_PORT || 3001,
  transkrip: +process.env.TRANSKRIP_PORT || 3002,
};

module.exports = {
  ports,
  gatewayUrl: `http://127.0.0.1:${ports.gateway}`,
  serviceUrls: {
    nilai: `http://127.0.0.1:${ports.nilai}`,
    transkrip: `http://127.0.0.1:${ports.transkrip}`,
  },
  dbPath: process.env.DB_PATH || path.join(root, 'data', 'nilai.db'),

  // Rahasia gateway -> service (4.1). GANTI di lingkungan nyata.
  gatewaySecret: process.env.GATEWAY_SECRET || 'dev-gateway-secret-ganti-di-produksi',

  // Kredensial Service Nilai untuk POST /auth/service (4.1)
  serviceClient: {
    id: process.env.SERVICE_CLIENT_ID || 'service-nilai',
    secret: process.env.SERVICE_CLIENT_SECRET || 'dev-service-secret-ganti-di-produksi',
  },

  // JWT RS256: gateway memegang private key, service hanya memegang public key.
  keys: {
    dir: path.join(root, 'keys'),
    private: path.join(root, 'keys', 'private.pem'),
    public: path.join(root, 'keys', 'public.pem'),
  },
  jwtIssuer: 'gateway',
  accessTokenTtl: '10m',
  accessTokenTtlSeconds: 10 * 60,
  serviceTokenTtl: '5m',
  serviceTokenTtlSeconds: 5 * 60,
  refreshTokenTtlMs: 24 * 60 * 60 * 1000, // 1 hari

  // Jam akses perubahan & finalisasi nilai (4.3), menit sejak 00:00. Mulai inklusif, akhir eksklusif.
  accessHours: parseHours(process.env.ACCESS_HOURS || '07:00-21:00'),
};
