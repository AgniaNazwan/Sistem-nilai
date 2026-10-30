// Uji otomatis seluruh kebutuhan. Jalankan SETELAH server hidup (npm start), di terminal lain: npm test
// Catatan: skrip ini me-reset data seed di awal.
const { execSync } = require('child_process');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const config = require('../shared/config');

execSync('node db/init.js', { cwd: path.join(__dirname, '..'), stdio: 'ignore' });
const db = require('../shared/db');

const GW = config.gatewayUrl;
const SVC_NILAI = config.serviceUrls.nilai;
let pass = 0, fail = 0;
const check = (name, ok, extra = '') => {
  ok ? pass++ : fail++;
  console.log(`${ok ? '  PASS' : '  FAIL'}  ${name}${ok ? '' : '  -> ' + extra}`);
};
const section = (t) => console.log(`\n== ${t}`);

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(url, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  let json = null;
  try { json = await r.json(); } catch {}
  return { status: r.status, json };
}
const gw = (m, p, o) => call(m, GW + p, o);
async function login(u, pw, dev) {
  return gw('POST', '/auth/login', { device: dev, body: { username: u, password: pw } });
}

(async () => {
  const mins = new Date().getHours() * 60 + new Date().getMinutes();
  const inHours = mins >= config.accessHours.start && mins < config.accessHours.end;
  console.log(`Jam akses aktif: ${inHours ? 'DI DALAM' : 'DI LUAR'} rentang (${config.accessHours.start}-${config.accessHours.end} menit)`);

  section('4.1 Autentikasi & token');
  const adm = (await login('admin1', 'admin123', 'DEV-ADMIN-01')).json;
  const d1 = (await login('dosen1', 'dosen123', 'DEV-DOSEN1-01')).json;
  const d2 = (await login('dosen2', 'dosen123', 'DEV-DOSEN2-01')).json;
  const m1 = (await login('mhs1', 'mhs123', 'DEV-MHS1-01')).json;
  const m2 = (await login('mhs2', 'mhs123', 'DEV-MHS2-01')).json;
  check('login valid mengembalikan access+refresh token', !!(m1.access_token && m1.refresh_token && d1.access_token));
  const claims = jwt.decode(m1.access_token);
  check('access token berisi sub & role, masa berlaku 10 menit', claims.sub === 'mhs1' && claims.role === 'mahasiswa' && claims.exp - claims.iat === 600, JSON.stringify(claims));
  check('login password salah -> 401', (await login('mhs1', 'salah', 'DEV-MHS1-01')).status === 401);
  check('login device tidak terdaftar -> 403', (await login('mhs1', 'mhs123', 'DEV-MHS2-01')).status === 403);
  check('login tanpa X-Device-ID -> 403', (await login('mhs1', 'mhs123', undefined)).status === 403);

  const rf = await gw('POST', '/auth/refresh', { body: { refresh_token: m2.refresh_token } });
  check('refresh token valid -> access token baru', rf.status === 200 && !!rf.json.access_token);
  const reuse = await gw('POST', '/auth/refresh', { body: { refresh_token: m2.refresh_token } });
  check('refresh token lama (sudah dirotasi) ditolak', reuse.status === 401);
  const after = await gw('POST', '/auth/refresh', { body: { refresh_token: rf.json.refresh_token } });
  check('pemakaian ulang token dicabut mencabut seluruh sesi user', after.status === 401);
  const lg = await login('mhs3', 'mhs123', 'DEV-MHS3-01');
  check('logout mencabut refresh token', (await gw('POST', '/auth/logout', { body: { refresh_token: lg.json.refresh_token } })).status === 200);
  check('refresh setelah logout ditolak', (await gw('POST', '/auth/refresh', { body: { refresh_token: lg.json.refresh_token } })).status === 401);

  const st = await gw('POST', '/auth/service', { body: { client_id: config.serviceClient.id, client_secret: config.serviceClient.secret } });
  const sc = jwt.decode(st.json.access_token);
  check('token service: role service, berlaku 5 menit', st.status === 200 && sc.role === 'service' && sc.exp - sc.iat === 300);
  check('/auth/service secret salah -> 401', (await gw('POST', '/auth/service', { body: { client_id: config.serviceClient.id, client_secret: 'x' } })).status === 401);
  const svcTok = st.json.access_token;

  section('4.1 Gateway secret & verifikasi ulang di service');
  check('akses langsung ke service tanpa secret -> 403', (await call('GET', SVC_NILAI + '/nilai', { token: m1.access_token })).status === 403);
  check('secret benar tapi tanpa token -> 401', (await call('GET', SVC_NILAI + '/nilai', { headers: { 'X-Gateway-Secret': config.gatewaySecret } })).status === 401);
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const forged = jwt.sign({ sub: 'admin1', role: 'admin', type: 'user' }, privateKey, { algorithm: 'RS256', issuer: 'gateway', expiresIn: '5m' });
  check('secret benar + token palsu (kunci lain) di service -> 401', (await call('GET', SVC_NILAI + '/nilai', { token: forged, headers: { 'X-Gateway-Secret': config.gatewaySecret } })).status === 401);
  check('token palsu lewat gateway -> 401', (await gw('GET', '/transkrip/2022010001', { token: forged, device: 'DEV-ADMIN-01' })).status === 401);
  const expired = jwt.sign({ sub: 'mhs1', role: 'mahasiswa', type: 'user' }, fs.readFileSync(config.keys.private), { algorithm: 'RS256', issuer: 'gateway', expiresIn: -10 });
  check('token kedaluwarsa (kunci asli) di service -> 401', (await call('GET', SVC_NILAI + '/nilai', { token: expired, headers: { 'X-Gateway-Secret': config.gatewaySecret } })).status === 401);
  check('token kedaluwarsa lewat gateway -> 401', (await gw('GET', '/nilai', { token: expired, device: 'DEV-MHS1-01' })).status === 401);
  check('tanpa token lewat gateway -> 401', (await gw('GET', '/nilai')).status === 401);

  section('4.3 Device terdaftar');
  check('request tanpa X-Device-ID -> 403', (await gw('GET', '/nilai', { token: m1.access_token })).status === 403);
  check('device milik user lain -> 403', (await gw('GET', '/nilai', { token: m1.access_token, device: 'DEV-MHS2-01' })).status === 403);

  section('4.2 Kebijakan akses — mahasiswa');
  const n1 = await gw('GET', '/nilai', { token: m1.access_token, device: 'DEV-MHS1-01' });
  check('mahasiswa melihat nilai sendiri (hanya NIM miliknya)', n1.status === 200 && n1.json.length === 2, JSON.stringify(n1));
  check('mahasiswa minta nilai NIM lain -> 403', (await gw('GET', '/nilai?nim=2022010002', { token: m1.access_token, device: 'DEV-MHS1-01' })).status === 403);
  check('mahasiswa melihat transkrip NIM sendiri -> 200', (await gw('GET', '/transkrip/2022010001', { token: m1.access_token, device: 'DEV-MHS1-01' })).status === 200);
  check('mahasiswa melihat transkrip NIM lain -> 403', (await gw('GET', '/transkrip/2022010002', { token: m1.access_token, device: 'DEV-MHS1-01' })).status === 403);
  check('mahasiswa mengubah nilai -> 403', (await gw('PUT', '/nilai/1', { token: m1.access_token, device: 'DEV-MHS1-01', body: { nilai: 100 } })).status === 403);
  check('mahasiswa finalisasi -> 403', (await gw('POST', '/kelas/1/finalisasi', { token: m1.access_token, device: 'DEV-MHS1-01' })).status === 403);

  section('4.2 Kebijakan akses — admin');
  check('admin melihat transkrip semua NIM -> 200', (await gw('GET', '/transkrip/2022010003', { token: adm.access_token, device: 'DEV-ADMIN-01' })).status === 200);
  check('admin melihat /nilai -> 403', (await gw('GET', '/nilai', { token: adm.access_token, device: 'DEV-ADMIN-01' })).status === 403);
  check('admin mengubah nilai -> 403', (await gw('PUT', '/nilai/1', { token: adm.access_token, device: 'DEV-ADMIN-01', body: { nilai: 100 } })).status === 403);

  section('4.2 Kebijakan akses — dosen (kepemilikan data dari database)');
  const dn = await gw('GET', '/nilai?kelas_id=1', { token: d1.access_token, device: 'DEV-DOSEN1-01' });
  check('dosen1 melihat nilai kelas 1 (diampu) -> 200', dn.status === 200 && dn.json.length === 3);
  check('dosen1 melihat nilai kelas 2 (bukan miliknya) -> 403', (await gw('GET', '/nilai?kelas_id=2', { token: d1.access_token, device: 'DEV-DOSEN1-01' })).status === 403);
  check('dosen1 mengubah nilai kelas 2 (id 2) -> 403', (await gw('PUT', '/nilai/2', { token: d1.access_token, device: 'DEV-DOSEN1-01', body: { nilai: 99 } })).status === 403);
  check('dosen2 finalisasi kelas 1 -> 403', (await gw('POST', '/kelas/1/finalisasi', { token: d2.access_token, device: 'DEV-DOSEN2-01' })).status === 403);
  check('dosen tidak boleh baca transkrip -> 403', (await gw('GET', '/transkrip/2022010001', { token: d1.access_token, device: 'DEV-DOSEN1-01' })).status === 403);

  section('4.3 Jam akses + ubah & finalisasi');
  const put = await gw('PUT', '/nilai/1', { token: d1.access_token, device: 'DEV-DOSEN1-01', body: { nilai: 91 } });
  check(`dosen1 mengubah nilai kelas 1 -> ${inHours ? '200 (dalam jam)' : '403 (luar jam)'}`, put.status === (inHours ? 200 : 403), JSON.stringify(put));
  const fin = await gw('POST', '/kelas/1/finalisasi', { token: d1.access_token, device: 'DEV-DOSEN1-01' });
  check(`dosen1 finalisasi kelas 1 -> ${inHours ? '200 (dalam jam)' : '403 (luar jam)'}`, fin.status === (inHours ? 200 : 403), JSON.stringify(fin));

  if (inHours) {
    check('PUT setelah final -> 403 (nilai sudah final)', (await gw('PUT', '/nilai/1', { token: d1.access_token, device: 'DEV-DOSEN1-01', body: { nilai: 50 } })).status === 403);
    const tr = await gw('GET', '/transkrip/2022010001', { token: m1.access_token, device: 'DEV-MHS1-01' });
    const mk = tr.json && tr.json.mata_kuliah;
    check('setelah finalisasi, nilai masuk transkrip mahasiswa (sinkron lewat gateway)', tr.status === 200 && mk.length === 1 && mk[0].nilai === 91, JSON.stringify(tr));
    const tr2 = await gw('GET', '/transkrip/2022010002', { token: adm.access_token, device: 'DEV-ADMIN-01' });
    check('admin melihat transkrip mahasiswa lain hasil sinkron', tr2.status === 200 && tr2.json.mata_kuliah.length === 1);
  }

  section('4.2 /transkrip/sinkron hanya token service');
  const body = { kelas_id: 2, kode: 'KP70065002', nama_mk: 'Basis Data', items: [{ nim: '2022010001', nilai: 78 }] };
  check('token user (dosen) -> 403', (await gw('POST', '/transkrip/sinkron', { token: d1.access_token, device: 'DEV-DOSEN1-01', body })).status === 403);
  check('token user (admin) -> 403', (await gw('POST', '/transkrip/sinkron', { token: adm.access_token, device: 'DEV-ADMIN-01', body })).status === 403);
  check('token service -> 200', (await gw('POST', '/transkrip/sinkron', { token: svcTok, body })).status === 200);
  check('token service tidak bisa dipakai di endpoint user (GET /nilai) -> 403', (await gw('GET', '/nilai', { token: svcTok })).status === 403);
  check('token service tidak bisa mengubah nilai -> 403', (await gw('PUT', '/nilai/3', { token: svcTok, body: { nilai: 1 } })).status === 403);

  section('Default deny');
  check('endpoint tak dikenal -> 403', (await gw('GET', '/admin/rahasia', { token: adm.access_token, device: 'DEV-ADMIN-01' })).status === 403);
  check('/auth/* tak dikenal -> 404', (await gw('GET', '/auth/apapun')).status === 404);

  section('4.4 Audit log');
  const total = db.prepare('SELECT COUNT(*) c FROM audit_log').get().c;
  const allow = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE result='allow'").get().c;
  const deny = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE result='deny'").get().c;
  check(`audit log mencatat allow & deny (total ${total}: allow ${allow}, deny ${deny})`, allow > 0 && deny > 0);
  const bad = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE ts IS NULL OR subject IS NULL OR endpoint IS NULL OR reason IS NULL OR reason=''").get().c;
  check('setiap entri punya waktu, subjek, endpoint, hasil, alasan', bad === 0);
  check('entri deny menyimpan device & alasan', !!db.prepare("SELECT 1 FROM audit_log WHERE result='deny' AND device IS NOT NULL AND reason LIKE '%pengampu%'").get());

  console.log(`\nHasil: ${pass} lulus, ${fail} gagal`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
