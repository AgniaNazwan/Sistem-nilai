// Menjalankan gateway + 2 service sekaligus dalam satu terminal (Ctrl+C untuk berhenti).
const { spawn } = require('child_process');
const path = require('path');
const root = path.join(__dirname, '..');
const apps = [
  ['nilai', 'service-nilai/index.js'],
  ['transkrip', 'service-transkrip/index.js'],
  ['gateway', 'gateway/index.js'],
];
const children = apps.map(([name, file]) => {
  const p = spawn(process.execPath, [path.join(root, file)], { cwd: root, env: process.env });
  const pipe = (stream, out) =>
    stream.on('data', (d) => d.toString().split('\n').filter(Boolean).forEach((l) => out.write(`[${name}] ${l}\n`)));
  pipe(p.stdout, process.stdout);
  pipe(p.stderr, process.stderr);
  p.on('exit', (c) => console.log(`[${name}] berhenti (kode ${c})`));
  return p;
});
const stop = () => { children.forEach((c) => c.kill()); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
