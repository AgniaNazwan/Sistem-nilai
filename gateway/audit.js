// Audit Log (4.4): setiap keputusan akses dicatat: waktu, subjek, endpoint, device, hasil, alasan.
const db = require('../shared/db');

const insert = db.prepare(
  'INSERT INTO audit_log (ts, subject, endpoint, device, result, reason) VALUES (?,?,?,?,?,?)'
);

function log({ subject, endpoint, device, result, reason }) {
  insert.run(new Date().toISOString(), subject || 'anonymous', endpoint, device || null, result, reason);
  const tag = result === 'allow' ? 'ALLOW' : 'DENY ';
  console.log(`[audit] ${tag} ${subject || 'anonymous'} ${endpoint} dev=${device || '-'} :: ${reason}`);
}

module.exports = { log };
