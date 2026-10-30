// SERVICE TRANSKRIP (port 3002) — resource. Wajib X-Gateway-Secret + token valid.
const express = require('express');
const db = require('../shared/db');
const config = require('../shared/config');
const { guard, requireRole } = require('../shared/serviceGuard');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(guard);

const huruf = (n) => (n >= 80 ? 'A' : n >= 70 ? 'B' : n >= 60 ? 'C' : n >= 50 ? 'D' : 'E');

const q = {
  user: db.prepare('SELECT id, username, role, nim FROM users WHERE username = ?'),
  mhsByNim: db.prepare("SELECT nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'"),
  transkrip: db.prepare(
    'SELECT kelas_id, kode, nama_mk, nilai, huruf, synced_at FROM transkrip WHERE nim = ? ORDER BY kode'
  ),
  upsert: db.prepare(
    `INSERT INTO transkrip (nim, kelas_id, kode, nama_mk, nilai, huruf, synced_at) VALUES (?,?,?,?,?,?,?)
     ON CONFLICT (nim, kelas_id) DO UPDATE SET nilai = excluded.nilai, huruf = excluded.huruf, synced_at = excluded.synced_at`
  ),
};

// Hanya token service (role: service). Token user ditolak oleh requireRole.
app.post('/transkrip/sinkron', requireRole('service'), (req, res) => {
  const { kelas_id, kode, nama_mk, items } = req.body || {};
  const valid =
    Number.isInteger(kelas_id) && typeof kode === 'string' && typeof nama_mk === 'string' &&
    Array.isArray(items) && items.length > 0 && items.length <= 1000 &&
    items.every((i) => i && typeof i.nim === 'string' && typeof i.nilai === 'number' && i.nilai >= 0 && i.nilai <= 100);
  if (!valid) return res.status(400).json({ error: 'Payload sinkron tidak valid' });
  if (items.some((i) => !q.mhsByNim.get(i.nim))) return res.status(400).json({ error: 'Ada NIM yang tidak dikenal' });

  const now = new Date().toISOString();
  db.transaction(() => items.forEach((i) => q.upsert.run(i.nim, kelas_id, kode, nama_mk, i.nilai, huruf(i.nilai), now)))();
  res.json({ message: 'Transkrip disinkronkan', tersinkron: items.length });
});

app.get('/transkrip/:nim', requireRole('mahasiswa', 'admin'), (req, res) => {
  const user = q.user.get(req.auth.sub);
  if (!user) return res.status(403).json({ error: 'User tidak dikenal' });
  // Data-scoping: mahasiswa hanya NIM sendiri, admin semua NIM
  if (user.role === 'mahasiswa' && user.nim !== req.params.nim) {
    return res.status(403).json({ error: 'Mahasiswa hanya boleh melihat transkrip sendiri' });
  }
  const mhs = q.mhsByNim.get(req.params.nim);
  if (!mhs) return res.status(404).json({ error: 'NIM tidak ditemukan' });
  res.json({ nim: mhs.nim, nama: mhs.nama, mata_kuliah: q.transkrip.all(mhs.nim) });
});

app.use((req, res) => res.status(404).json({ error: 'Endpoint tidak ada' }));
app.listen(config.ports.transkrip, '127.0.0.1', () => console.log(`Service Transkrip berjalan di :${config.ports.transkrip}`));
