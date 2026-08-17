# ◈ SIDIK

**S**istem **I**dentifikasi **D**okumen, **I**maji, dan **K**onten — meja forensik digital mini untuk memeriksa indikasi manipulasi pada **gambar**, **teks**, dan **dokumen PDF**. 100% berjalan lokal, tanpa upload ke server manapun.

![Home](screenshots/01_home.png)

> ⚠️ **Disclaimer jujur:** ini alat heuristik berbasis aturan (rule-based), **bukan** model AI/ML dan **bukan** pengganti laboratorium forensik digital bersertifikat. Cocok untuk *triase awal* / *sanity check* sebelum verifikasi manual lebih lanjut — bukan untuk kebutuhan hukum/formal.

---

## Kenapa dibuat

Makin banyak dokumen, sertifikat, dan gambar palsu beredar (ijazah palsu, bukti transfer editan, sertifikat vendor abal-abal, dsb). Kebanyakan orang tidak punya akses ke tools forensik profesional. SIDIK mencoba menjembatani itu dengan teknik forensik dasar yang open dan bisa dijalankan siapa saja:

- **Error Level Analysis (ELA)** untuk gambar
- **Pembacaan metadata EXIF** (kamera, software editing, GPS)
- **Analisis pola linguistik** untuk teks (variasi kalimat, frasa berulang, pergeseran gaya bahasa)
- **Pembacaan struktur PDF** (incremental update / `%%EOF` ganda, metadata producer/creator, tanda tangan digital)


## Fitur

### 🖼 Bukti Gambar
- Ekstraksi metadata EXIF (perangkat, software, GPS, parameter kamera)
- Deteksi software editing populer (Photoshop, GIMP, Canva, Snapseed, dll.)
- **Error Level Analysis** — heatmap area dengan riwayat kompresi berbeda (indikasi tempel/sunting)

### 📝 Bukti Teks
- Variasi panjang kalimat (indikasi teks auto-generated/template)
- Rasio kosakata unik (deteksi pengulangan/templating)
- Deteksi frasa berulang & pergeseran gaya antar-paragraf
- Ekstraksi tanggal & angka penting untuk verifikasi manual

### 📄 Bukti Dokumen (PDF)
- Deteksi *incremental update* (penanda `%%EOF` ganda → indikasi dokumen disimpan ulang/diedit setelah revisi awal)
- Metadata Producer/Creator/Author + deteksi editor PDF online pihak ketiga
- Deteksi keberadaan tanda tangan digital (tanpa validasi kriptografis)
- Jumlah font unik vs jumlah halaman (indikasi konten gabungan)

Semua analisis menghasilkan laporan terstruktur:

```
STATUS KEASLIAN   : AMAN / MENCURIGAKAN / PALSU / TIDAK DAPAT DIVERIFIKASI
TINGKAT KEYAKINAN : 0–100% (indikatif, bukan probabilitas statistik formal)
TEMUAN UTAMA      : daftar temuan konkret
REKOMENDASI       : langkah verifikasi lanjutan
```

## Screenshot

| Gambar (ELA) | Dokumen PDF asli | Dokumen PDF hasil edit ulang |
|---|---|---|
| ![ELA](screenshots/03_analisis_ela.png) | ![PDF asli](screenshots/05_dokumen_asli.png) | ![PDF palsu](screenshots/06_dokumen_palsu.png) |

Lihat folder [`screenshots/`](screenshots) untuk contoh lengkap tiap mode.

## Dua versi, satu logika

| | `web/sidik.html` | `app.py` (Streamlit) |
|---|---|---|
| Instalasi | Tidak perlu — buka langsung di browser | `pip install` + `streamlit run` |
| Bukti Gambar | ✅ (EXIF + ELA via Canvas API) | ✅ (EXIF + ELA via Pillow/NumPy) |
| Bukti Teks | ✅ | ✅ |
| Bukti Dokumen PDF | ❌ | ✅ |
| Cocok untuk | Demo cepat, share ke non-teknis | Pemakaian rutin, ekstensi fitur |

## Instalasi & Menjalankan (versi Streamlit)

```bash
git clone https://github.com/<username>/sidik.git
cd sidik
pip install -r requirements.txt
streamlit run app.py
```

Buka `http://localhost:8501` di browser.

Untuk versi HTML, cukup buka `web/sidik.html` langsung di browser — tidak ada instalasi sama sekali.

## Batasan yang perlu disadari

- ELA paling efektif pada gambar **JPEG**; kurang definitif untuk PNG/format lossless lain.
- Heuristik teks (variasi kalimat, TTR, dll.) adalah **sinyal lemah** — tidak dimaksudkan untuk memvonis teks sebagai "buatan AI" secara pasti.
- Deteksi tanda tangan digital PDF hanya memeriksa **keberadaan objek tanda tangan**, bukan validitas kriptografisnya. Gunakan Adobe Acrobat Reader atau layanan validasi sertifikat resmi untuk itu.
- Tool ini dirancang untuk **konservatif** — lebih memilih status "MENCURIGAKAN"/"TIDAK DAPAT DIVERIFIKASI" daripada memvonis "PALSU" tanpa sinyal kuat.

## Roadmap ide pengembangan

- [ ] Dukungan dokumen Word (.docx) & gambar hasil scan multi-halaman
- [ ] Export laporan ke PDF
- [ ] Deteksi copy-move forgery (klon area dalam satu gambar)
- [ ] Mode batch (banyak file sekaligus)

## Lisensi
Rev

---

Dibangun sebagai proyek belajar forensik digital & keamanan siber. Kontribusi dan masukan terbuka lebar.
