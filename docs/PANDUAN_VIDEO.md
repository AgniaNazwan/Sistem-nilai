# Panduan Video Demo (6–9 menit)

Siapkan 2 terminal (server + perintah) dan editor kode. Perlihatkan **kode** lalu **hasilnya** untuk setiap poin.

| Menit | Isi | Tampilkan |
|---|---|---|
| 0:00–0:45 | Pengantar: skenario, arsitektur, 3 prinsip zero trust. Jalankan `npm run seed` dan `npm start` | Diagram arsitektur, struktur folder |
| 0:45–2:00 | **4.1 Token**: login dosen1, tunjukkan JWT di jwt.io (`sub`, `role`, `exp` 10 menit). Refresh, logout lalu refresh lagi (ditolak). `POST /auth/service` | `gateway/tokens.js`, `gateway/authRoutes.js` |
| 2:00–3:15 | **4.1 Gateway secret & verifikasi ulang**: curl langsung ke `:3001` (403); dengan secret tanpa token (401); token palsu (401). Jelaskan RS256: service hanya punya public key | `shared/serviceGuard.js`, `proxyReq` di `gateway/index.js` |
| 3:15–5:00 | **4.2 Kebijakan akses**: mhs1 lihat nilai sendiri (200) lalu transkrip NIM lain (403); admin lihat transkrip (200) tapi `/nilai` (403); dosen2 ubah nilai kelas dosen1 (403). Jelaskan PE membaca DB, bukan hanya token | `gateway/policy.js` (tabel `rules`, `check`) |
| 5:00–6:15 | **4.3 Konteks**: device salah (403). Jam akses: restart dengan `ACCESS_HOURS=03:00-03:01`, ubah nilai (403 luar jam), lalu kembalikan jam normal | `withinAccessHours`, `shared/config.js` |
| 6:15–7:45 | **Finalisasi & sinkron antar-service**: dosen1 finalisasi kelas 1, mhs1 lihat transkrip (nilai masuk), ubah nilai lagi (403 sudah final). Coba `POST /transkrip/sinkron` dengan token user (403) | `service-nilai/index.js` (`getServiceToken`, `syncTranskrip`), `service-transkrip/index.js` |
| 7:45–8:30 | **4.4 Audit log**: `npm run audit`, tunjukkan allow/deny beserta alasan | `gateway/audit.js` |
| 8:30–9:00 | Jalankan `npm test` (semua lulus) dan penutup | Output uji |

Tips: sebelum rekaman jalankan `npm run seed` agar data kembali awal (finalisasi tidak bisa dibatalkan). Simpan token ke variabel shell agar curl singkat.
