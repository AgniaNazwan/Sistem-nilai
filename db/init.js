// Membuat skema, kunci JWT (jika belum ada), dan data awal (seed). Aman dijalankan berulang (me-reset data).
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const config = require('../shared/config');

// --- Kunci RS256 -------------------------------------------------------------
if (!fs.existsSync(config.keys.private)) {
  fs.mkdirSync(config.keys.dir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(config.keys.private, privateKey, { mode: 0o600 });
  fs.writeFileSync(config.keys.public, publicKey);
  console.log('Kunci RS256 dibuat di ./keys');
}

const db = require('../shared/db');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  nama TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nim TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  UNIQUE (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS kelas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kode TEXT NOT NULL,
  nama TEXT NOT NULL,
  dosen_id INTEGER NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nilai (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nim TEXT NOT NULL REFERENCES users(nim),
  kelas_id INTEGER NOT NULL REFERENCES kelas(id),
  nilai REAL,
  final INTEGER NOT NULL DEFAULT 0,
  UNIQUE (nim, kelas_id)
);
CREATE TABLE IF NOT EXISTS transkrip (
  nim TEXT NOT NULL REFERENCES users(nim),
  kelas_id INTEGER NOT NULL,
  kode TEXT NOT NULL,
  nama_mk TEXT NOT NULL,
  nilai REAL NOT NULL,
  huruf TEXT NOT NULL,
  synced_at TEXT NOT NULL,
  PRIMARY KEY (nim, kelas_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  subject TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device TEXT,
  result TEXT NOT NULL CHECK (result IN ('allow','deny')),
  reason TEXT NOT NULL
);
`);

// --- Seed --------------------------------------------------------------------
const seed = db.transaction(() => {
  for (const t of ['audit_log', 'refresh_tokens', 'transkrip', 'nilai', 'kelas', 'devices', 'service_clients', 'users']) {
    db.prepare(`DELETE FROM ${t}`).run();
  }
  db.prepare(`DELETE FROM sqlite_sequence`).run();

  const addUser = db.prepare('INSERT INTO users (username, nama, password_hash, role, nim) VALUES (?,?,?,?,?)');
  const addDevice = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?,?)');
  const hash = (p) => bcrypt.hashSync(p, 10);

  const users = [
    ['admin1', 'Admin Prodi', 'admin123', 'admin', null, 'DEV-ADMIN-01'],
    ['dosen1', 'Dr. Dosen Satu', 'dosen123', 'dosen', null, 'DEV-DOSEN1-01'],
    ['dosen2', 'Dr. Dosen Dua', 'dosen123', 'dosen', null, 'DEV-DOSEN2-01'],
    ['mhs1', 'Andi Pratama', 'mhs123', 'mahasiswa', '2022010001', 'DEV-MHS1-01'],
    ['mhs2', 'Budi Santoso', 'mhs123', 'mahasiswa', '2022010002', 'DEV-MHS2-01'],
    ['mhs3', 'Citra Lestari', 'mhs123', 'mahasiswa', '2022010003', 'DEV-MHS3-01'],
  ];
  const ids = {};
  for (const [u, nama, pw, role, nim, dev] of users) {
    const id = addUser.run(u, nama, hash(pw), role, nim).lastInsertRowid;
    ids[u] = id;
    addDevice.run(id, dev);
  }

  const addKelas = db.prepare('INSERT INTO kelas (kode, nama, dosen_id) VALUES (?,?,?)');
  const k1 = addKelas.run('KP70065004', 'Keamanan Informasi', ids.dosen1).lastInsertRowid;
  const k2 = addKelas.run('KP70065002', 'Basis Data', ids.dosen2).lastInsertRowid;

  const addNilai = db.prepare('INSERT INTO nilai (nim, kelas_id, nilai, final) VALUES (?,?,?,0)');
  const scores = { '2022010001': [85, 78], '2022010002': [72, 88], '2022010003': [90, 65] };
  for (const [nim, [a, b]] of Object.entries(scores)) {
    addNilai.run(nim, k1, a);
    addNilai.run(nim, k2, b);
  }

  db.prepare('INSERT INTO service_clients (client_id, secret_hash) VALUES (?,?)')
    .run(config.serviceClient.id, hash(config.serviceClient.secret));
});
seed();
console.log('Database siap:', config.dbPath);
console.log('Akun (username / password / device ID):');
console.log('  admin1 / admin123 / DEV-ADMIN-01');
console.log('  dosen1 / dosen123 / DEV-DOSEN1-01   (mengampu kelas 1)');
console.log('  dosen2 / dosen123 / DEV-DOSEN2-01   (mengampu kelas 2)');
console.log('  mhs1 / mhs123 / DEV-MHS1-01  NIM 2022010001');
console.log('  mhs2 / mhs123 / DEV-MHS2-01  NIM 2022010002');
console.log('  mhs3 / mhs123 / DEV-MHS3-01  NIM 2022010003');
