// Menampilkan audit log terbaru:  npm run audit  [jumlah]
const db = require('../shared/db');
const n = Number(process.argv[2]) || 25;
const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(n).reverse();
console.table(rows.map((r) => ({ waktu: r.ts.slice(11, 19), subjek: r.subject, endpoint: r.endpoint, device: r.device, hasil: r.result, alasan: r.reason })));
