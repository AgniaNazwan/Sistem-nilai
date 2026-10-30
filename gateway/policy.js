// POLICY ENGINE (PE): memutuskan allow/deny + alasan, berdasarkan Tabel 3 dan atribut dari database.
// Prinsip: default deny. Request yang tidak cocok dengan aturan mana pun ditolak.
const db = require('../shared/db');
const config = require('../shared/config');

const q = {
  user: db.prepare('SELECT id, username, role, nim FROM users WHERE username = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  kelas: db.prepare('SELECT id, dosen_id FROM kelas WHERE id = ?'),
  nilai: db.prepare(
    'SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'
  ),
};

const allow = (reason) => ({ allow: true, reason });
const deny = (reason, status = 403) => ({ allow: false, reason, status });

// 4.3 Jam akses (dapat diatur lewat ACCESS_HOURS)
function withinAccessHours(now) {
  const minutes = now.getHours() * 60 + now.getMinutes();
  return minutes >= config.accessHours.start && minutes < config.accessHours.end;
}
const hoursLabel = () => {
  const f = (m) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
  return `${f(config.accessHours.start)}-${f(config.accessHours.end)}`;
};

// --- Aturan per endpoint (Tabel 3) -------------------------------------------
const rules = [
  {
    method: 'GET', re: /^\/nilai\/?$/, service: 'nilai', roles: ['mahasiswa', 'dosen'],
    check(ctx, m, user) {
      if (user.role === 'mahasiswa') {
        if (ctx.query.nim && ctx.query.nim !== user.nim) return deny('mahasiswa hanya boleh melihat nilai miliknya sendiri');
        return allow('mahasiswa melihat nilai miliknya sendiri');
      }
      // dosen
      if (ctx.query.kelas_id !== undefined) {
        const kelas = /^\d+$/.test(String(ctx.query.kelas_id)) && q.kelas.get(+ctx.query.kelas_id);
        if (!kelas) return deny('kelas tidak ditemukan', 404);
        if (kelas.dosen_id !== user.id) return deny('dosen bukan pengampu kelas ini');
      }
      return allow('dosen melihat nilai kelas yang diampunya');
    },
  },
  {
    method: 'PUT', re: /^\/nilai\/(\d+)\/?$/, service: 'nilai', roles: ['dosen'],
    check(ctx, m, user) {
      const n = q.nilai.get(+m[1]);
      if (!n) return deny('data nilai tidak ditemukan', 404);
      if (n.dosen_id !== user.id) return deny('dosen bukan pengampu kelas dari nilai ini');
      if (n.final) return deny('nilai sudah final, tidak dapat diubah');
      if (!withinAccessHours(ctx.now)) return deny(`di luar jam akses (${hoursLabel()})`);
      return allow('dosen pengampu mengubah nilai yang belum final dalam jam akses');
    },
  },
  {
    method: 'POST', re: /^\/kelas\/(\d+)\/finalisasi\/?$/, service: 'nilai', roles: ['dosen'],
    check(ctx, m, user) {
      const kelas = q.kelas.get(+m[1]);
      if (!kelas) return deny('kelas tidak ditemukan', 404);
      if (kelas.dosen_id !== user.id) return deny('dosen bukan pengampu kelas ini');
      if (!withinAccessHours(ctx.now)) return deny(`di luar jam akses (${hoursLabel()})`);
      return allow('dosen pengampu memfinalisasi kelas dalam jam akses');
    },
  },
  {
    method: 'GET', re: /^\/transkrip\/([A-Za-z0-9_-]+)\/?$/, service: 'transkrip', roles: ['mahasiswa', 'admin'],
    check(ctx, m, user) {
      if (user.role === 'admin') return allow('admin melihat transkrip semua NIM');
      if (user.nim !== m[1]) return deny('mahasiswa hanya boleh melihat transkrip NIM sendiri');
      return allow('mahasiswa melihat transkrip NIM sendiri');
    },
  },
  {
    // Hanya token service. Token user mana pun ditolak (cek di tahap role).
    method: 'POST', re: /^\/transkrip\/sinkron\/?$/, service: 'transkrip', roles: ['service'],
    check: () => allow('token service sah memanggil sinkron transkrip'),
  },
];

/** Cari aturan untuk method + path. Dipakai juga gateway untuk memilih service tujuan. */
function matchRule(method, path) {
  for (const rule of rules) {
    if (rule.method !== method) continue;
    const m = rule.re.exec(path);
    if (m) return { rule, m };
  }
  return null;
}

/**
 * @param ctx { subject:{sub,role,type}, method, path, query, deviceId, now }
 * @returns { allow, reason, status?, service? }
 */
function decide(ctx) {
  const found = matchRule(ctx.method, ctx.path);
  if (!found) return deny('tidak ada kebijakan untuk endpoint ini (default deny)');
  const { rule, m } = found;
  const { subject } = ctx;

  let user = null;
  if (subject.type === 'user') {
    // Atribut diambil dari DATABASE, bukan hanya dari isi token.
    user = q.user.get(subject.sub);
    if (!user) return deny('user pada token tidak ada di database');
    if (user.role !== subject.role) return deny('role pada token tidak sesuai database');

    // 4.3 Verifikasi konteks: device terdaftar
    if (!ctx.deviceId) return deny('header X-Device-ID tidak ada');
    if (!q.device.get(user.id, ctx.deviceId)) return deny('device tidak terdaftar untuk user ini');
  } else if (subject.type !== 'service' || subject.role !== 'service') {
    return deny('jenis token tidak dikenal');
  }

  if (!rule.roles.includes(subject.role)) {
    return deny(`role '${subject.role}' tidak diizinkan untuk endpoint ini`);
  }

  const d = rule.check(ctx, m, user);
  return { ...d, service: rule.service };
}

module.exports = { decide, matchRule, withinAccessHours };
