// SERVICE NILAI (port 3001) — resource. Tidak bisa diakses langsung: wajib X-Gateway-Secret + token valid.
const express = require('express');
const db = require('../shared/db');
const config = require('../shared/config');
const { guard, requireRole } = require('../shared/serviceGuard');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(guard); // gateway secret + verifikasi ulang token

const q = {
  user: db.prepare('SELECT id, username, role, nim FROM users WHERE username = ?'),
  nilaiMhs: db.prepare(
    `SELECT n.id, n.kelas_id, k.kode, k.nama AS mata_kuliah, n.nilai, n.final
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.nim = ? ORDER BY n.id`
  ),
  nilaiDosen: db.prepare(
    `SELECT n.id, n.kelas_id, k.kode, k.nama AS mata_kuliah, n.nim, u.nama, n.nilai, n.final
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.nim = n.nim
      WHERE k.dosen_id = ? AND (? IS NULL OR n.kelas_id = ?) ORDER BY n.id`
  ),
  nilaiById: db.prepare(
    'SELECT n.id, n.final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'
  ),
  updateNilai: db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?'),
  kelas: db.prepare('SELECT id, kode, nama, dosen_id FROM kelas WHERE id = ?'),
  nilaiKelas: db.prepare('SELECT id, nim, nilai, final FROM nilai WHERE kelas_id = ?'),
  setFinal: db.prepare('UPDATE nilai SET final = ? WHERE id = ?'),
};

// Data-scoping di service: walau gateway sudah memutuskan, service tetap membatasi data sesuai identitas pada token.
app.get('/nilai', requireRole('mahasiswa', 'dosen'), (req, res) => {
  const user = q.user.get(req.auth.sub);
  if (!user) return res.status(403).json({ error: 'User tidak dikenal' });
  if (user.role === 'mahasiswa') return res.json(q.nilaiMhs.all(user.nim));
  const kelasId = req.query.kelas_id !== undefined ? Number(req.query.kelas_id) : null;
  res.json(q.nilaiDosen.all(user.id, kelasId, kelasId));
});

app.put('/nilai/:id', requireRole('dosen'), (req, res) => {
  const user = q.user.get(req.auth.sub);
  const n = q.nilaiById.get(Number(req.params.id));
  const nilai = req.body && req.body.nilai;
  if (!n) return res.status(404).json({ error: 'Data nilai tidak ditemukan' });
  if (!user || n.dosen_id !== user.id) return res.status(403).json({ error: 'Bukan pengampu kelas ini' });
  if (n.final) return res.status(409).json({ error: 'Nilai sudah final' });
  if (typeof nilai !== 'number' || !Number.isFinite(nilai) || nilai < 0 || nilai > 100) {
    return res.status(400).json({ error: 'nilai harus angka 0-100' });
  }
  q.updateNilai.run(nilai, n.id);
  res.json({ id: n.id, nilai, final: 0 });
});

// --- Token service (didapat dari gateway lewat POST /auth/service, di-cache sampai hampir habis) ---
let cached = { token: null, expiresAt: 0 };
async function getServiceToken() {
  if (cached.token && Date.now() < cached.expiresAt - 30_000) return cached.token;
  const r = await fetch(`${config.gatewayUrl}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: config.serviceClient.id, client_secret: config.serviceClient.secret }),
  });
  if (!r.ok) throw new Error(`gagal mengambil token service (HTTP ${r.status})`);
  const j = await r.json();
  cached = { token: j.access_token, expiresAt: Date.now() + j.expires_in * 1000 };
  return cached.token;
}

// Panggilan antar-service TETAP lewat gateway (bukan langsung ke port 3002).
async function syncTranskrip(payload) {
  const token = await getServiceToken();
  const r = await fetch(`${config.gatewayUrl}/transkrip/sinkron`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  if (!r.ok) throw new Error(`sinkron transkrip ditolak/gagal (HTTP ${r.status})`);
  return r.json();
}

app.post('/kelas/:id/finalisasi', requireRole('dosen'), async (req, res) => {
  const user = q.user.get(req.auth.sub);
  const kelas = q.kelas.get(Number(req.params.id));
  if (!kelas) return res.status(404).json({ error: 'Kelas tidak ditemukan' });
  if (!user || kelas.dosen_id !== user.id) return res.status(403).json({ error: 'Bukan pengampu kelas ini' });

  const rows = q.nilaiKelas.all(kelas.id);
  if (rows.length === 0) return res.status(400).json({ error: 'Kelas belum memiliki nilai' });
  if (rows.some((r) => r.nilai === null)) return res.status(400).json({ error: 'Masih ada nilai kosong' });

  const toFinalize = rows.filter((r) => !r.final).map((r) => r.id);
  db.transaction(() => toFinalize.forEach((id) => q.setFinal.run(1, id)))();

  try {
    const hasil = await syncTranskrip({
      kelas_id: kelas.id,
      kode: kelas.kode,
      nama_mk: kelas.nama,
      items: rows.map((r) => ({ nim: r.nim, nilai: r.nilai })),
    });
    res.json({ message: 'Kelas difinalisasi dan transkrip disinkronkan', kelas_id: kelas.id, tersinkron: hasil.tersinkron });
  } catch (e) {
    // sinkron gagal: batalkan finalisasi supaya data konsisten
    db.transaction(() => toFinalize.forEach((id) => q.setFinal.run(0, id)))();
    res.status(502).json({ error: 'Finalisasi dibatalkan', detail: e.message });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Endpoint tidak ada' }));
app.listen(config.ports.nilai, '127.0.0.1', () => console.log(`Service Nilai berjalan di :${config.ports.nilai}`));
