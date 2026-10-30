// Satu database SQLite bersama untuk gateway, Service Nilai, dan Service Transkrip.
// Memakai SQLite bawaan Node.js (node:sqlite, Node >= 22.13) sehingga TIDAK perlu kompilasi native.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const config = require('./config');

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
const db = new DatabaseSync(config.dbPath);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');

// Pembungkus transaksi sederhana: db.transaction(fn) mengembalikan fungsi yang dijalankan dalam BEGIN/COMMIT.
db.transaction = (fn) => (...args) => {
  db.exec('BEGIN');
  try {
    const result = fn(...args);
    db.exec('COMMIT');
    return result;
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
};

module.exports = db;
