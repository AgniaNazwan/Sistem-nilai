# Sistem Nilai — Zero Trust Security

Tugas Praktikum Individu, Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.

API Gateway berperan sebagai **Policy Enforcement Point (PEP)** yang terpisah dari service, mengikuti NIST SP 800-207.
Stack: Node.js 22.13+ (disarankan 24), Express, `http-proxy-middleware`, `jsonwebtoken` (RS256), `bcryptjs`, SQLite bawaan Node.js (`node:sqlite`, tanpa kompilasi native).

## Cara menjalankan

```bash
npm install
npm run seed     # membuat database, kunci JWT, dan data awal (bisa diulang untuk reset data)
npm start        # menjalankan Gateway :3000, Service Nilai :3001, Service Transkrip :3002
```

Di terminal lain:

```bash
npm test         # 50 uji otomatis (me-reset data seed di awal)
npm run audit    # menampilkan audit log terbaru
```

Konfigurasi lewat environment variable (semua punya nilai bawaan untuk demo):

| Variabel | Bawaan | Fungsi |
|---|---|---|
| `ACCESS_HOURS` | `07:00-21:00` | Jam akses ubah/finalisasi nilai (zona waktu `TZ`, bawaan `Asia/Jakarta`) |
| `GATEWAY_SECRET` | `dev-gateway-secret-...` | Nilai header `X-Gateway-Secret` |
| `SERVICE_CLIENT_ID` / `SERVICE_CLIENT_SECRET` | `service-nilai` / `dev-service-secret-...` | Kredensial untuk `POST /auth/service` |
| `DB_PATH` | `./data/nilai.db` | Lokasi database |

Contoh demo di luar jam akses: `ACCESS_HOURS=03:00-03:01 npm start` (PowerShell: `$env:ACCESS_HOURS="03:00-03:01"; npm start`).
Setelah mengubah `ACCESS_HOURS`, `npm run seed` tidak wajib; cukup restart server.

## Akun dan device ID (data awal)

| Username | Password | Role | Device ID | Keterangan |
|---|---|---|---|---|
| admin1 | admin123 | admin | DEV-ADMIN-01 | |
| dosen1 | dosen123 | dosen | DEV-DOSEN1-01 | Mengampu kelas **1** (Keamanan Informasi) |
| dosen2 | dosen123 | dosen | DEV-DOSEN2-01 | Mengampu kelas **2** (Basis Data) |
| mhs1 | mhs123 | mahasiswa | DEV-MHS1-01 | NIM 2022010001 |
| mhs2 | mhs123 | mahasiswa | DEV-MHS2-01 | NIM 2022010002 |
| mhs3 | mhs123 | mahasiswa | DEV-MHS3-01 | NIM 2022010003 |

Service Nilai: client ID `service-nilai`, secret `dev-service-secret-ganti-di-produksi`.

## Struktur

```
gateway/            PEP + Policy Engine/Administrator
  index.js          alur PEP: verifikasi token -> keputusan -> audit -> proxy (+ X-Gateway-Secret)
  policy.js         Policy Engine: allow/deny + alasan (Tabel 3, device, jam akses, atribut dari DB)
  authRoutes.js     /auth/login, /refresh, /logout, /service
  tokens.js         penerbitan & verifikasi JWT, refresh token
  audit.js          audit log ke tabel audit_log
service-nilai/      Service Nilai (:3001), memanggil sinkron transkrip via gateway
service-transkrip/  Service Transkrip (:3002)
shared/             config, koneksi DB, serviceGuard (verifikasi ulang di service)
db/init.js          skema + seed + pembuatan kunci RS256
test/run-tests.js   uji otomatis
```

## Pemetaan kebutuhan ke kode

| Kebutuhan | Penerapan | Berkas |
|---|---|---|
| 4.1 Access token JWT 10 menit, `sub` + `role`, header Bearer | `signAccess`, verifikasi di gateway | `gateway/tokens.js`, `gateway/index.js` |
| 4.1 Refresh token 1 hari, di database, bisa dicabut, logout mencabut | hash SHA-256 disimpan di `refresh_tokens`; rotasi tiap refresh | `gateway/authRoutes.js` |
| 4.1 Token service dari `POST /auth/service` (5 menit, `role: service`) | `signService`; Service Nilai meminta & men-cache token | `gateway/authRoutes.js`, `service-nilai/index.js` (`getServiceToken`) |
| 4.1 Gateway secret | gateway menimpa `X-Gateway-Secret`; service menolak tanpa header ini | `gateway/index.js` (`proxyReq`), `shared/serviceGuard.js` |
| 4.1 Verifikasi ulang di service | service memverifikasi tanda tangan RS256, issuer, dan masa berlaku. Service hanya punya **public key** | `shared/serviceGuard.js` |
| 4.2 Kebijakan akses (Tabel 3) | tabel `rules` di Policy Engine; **default deny** | `gateway/policy.js` |
| 4.2 Kepemilikan data (kelas dosen, NIM mahasiswa) | PE membaca `users`, `kelas`, `nilai` dari DB, bukan dari token saja | `gateway/policy.js` |
| 4.3 Device terdaftar | cek `X-Device-ID` terhadap tabel `devices` pada login dan tiap request | `gateway/policy.js`, `gateway/authRoutes.js` |
| 4.3 Jam akses 07.00–21.00 (dapat dikonfigurasi) | `withinAccessHours` + `ACCESS_HOURS` | `gateway/policy.js`, `shared/config.js` |
| 4.4 Audit log | waktu, subjek, endpoint, device, hasil, alasan untuk setiap keputusan | `gateway/audit.js` |
| Panggilan antar-service lewat gateway | Service Nilai memanggil `GATEWAY/transkrip/sinkron` dengan token service | `service-nilai/index.js` (`syncTranskrip`) |

Prinsip zero trust yang diterapkan: *never trust, always verify* (token, device, dan konteks diperiksa di tiap request, termasuk antar-service),
*least privilege* (role + kepemilikan data + status nilai + jam), *assume breach* (service memverifikasi ulang token walau request datang dari gateway;
service tidak punya private key; refresh token yang dicabut lalu dipakai ulang mencabut seluruh sesi user).

## Contoh curl

```bash
# 1. Login (dosen1)
curl -s -X POST localhost:3000/auth/login -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DOSEN1-01" -d '{"username":"dosen1","password":"dosen123"}'
# simpan access_token ke variabel TOKEN

# 2. Lihat nilai kelas yang diampu
curl -s "localhost:3000/nilai?kelas_id=1" -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN1-01"

# 3. Ubah nilai (id nilai dari langkah 2)
curl -s -X PUT localhost:3000/nilai/1 -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN1-01" \
  -H "Content-Type: application/json" -d '{"nilai": 92}'

# 4. Finalisasi kelas (otomatis sinkron ke Service Transkrip lewat gateway)
curl -s -X POST localhost:3000/kelas/1/finalisasi -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN1-01"

# 5. Akses langsung ke service (harus ditolak 403)
curl -s localhost:3001/nilai -H "Authorization: Bearer $TOKEN"
```

## Catatan keamanan

- Secret bawaan hanya untuk demo; ganti lewat environment variable di lingkungan nyata.
- Respons penolakan menyertakan `reason` agar mudah didemokan; di produksi alasan rinci sebaiknya hanya masuk audit log.
