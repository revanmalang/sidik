"""
SIDIK — Meja Forensik Digital (versi Streamlit)
Alat deteksi indikasi pemalsuan/manipulasi pada gambar & teks.
Seluruh analisis berjalan lokal di mesin yang menjalankan skrip ini.
"""

import io
import re
from collections import Counter
from datetime import datetime

import numpy as np
import streamlit as st
from PIL import Image, ImageChops
from PIL.ExifTags import TAGS
from pypdf import PdfReader

# ============================================================
# PAGE CONFIG & STYLE
# ============================================================
st.set_page_config(page_title="SIDIK", page_icon="🔎", layout="wide")

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

:root{
  --bg:#1B1D1F; --panel:#26282C; --ink:#DAD6C9; --ink-dim:#8B8B84; --ink-faint:#5C5D58;
  --line:#3A3C40; --kraft:#4E9A6E; --safe:#3FAE63; --warn:#D3A24B; --danger:#C1594F; --unknown:#9C9C94;
}
.stApp{ background:#1B1D1F; color:var(--ink); font-family:'IBM Plex Sans',sans-serif; }
header[data-testid="stHeader"]{ background:#1B1D1F !important; }
[data-testid="stToolbar"]{ visibility:hidden; }
h1,h2,h3,.stTabs [data-baseweb="tab"]{ font-family:'JetBrains Mono',monospace; }
.stTabs [data-baseweb="tab-list"]{ gap:4px; }
.stTabs [data-baseweb="tab"]{ background:#202225; border:1px solid var(--line); border-bottom:none;
  border-radius:6px 6px 0 0; color:var(--ink-faint); font-weight:700; font-size:12.5px; letter-spacing:.4px; }
.stTabs [aria-selected="true"]{ background:var(--panel); color:var(--kraft) !important; }
.stButton>button{ font-family:'JetBrains Mono',monospace; font-weight:700; letter-spacing:1px;
  background:var(--kraft); color:#1B1D1F; border:none; border-radius:3px; padding:10px 18px; }
.stButton>button:hover{ background:#63B686; color:#1B1D1F; }
.case-tag{ font-family:'JetBrains Mono',monospace; text-align:right; font-size:11px; color:var(--ink-faint);
  border:1px dashed var(--line); padding:6px 10px; border-radius:3px; background:rgba(0,0,0,0.15); }
.case-num{ display:block; font-size:13px; color:var(--kraft); margin-top:2px; font-weight:700; }
.readout{ background:rgba(0,0,0,0.18); border:1px solid var(--line); border-radius:3px; padding:14px 16px; }
.readout h4{ margin:0 0 10px; font-family:'JetBrains Mono',monospace; font-size:11px; letter-spacing:1.5px; color:var(--kraft); }
.meta-row{ display:flex; justify-content:space-between; gap:10px; font-family:'JetBrains Mono',monospace;
  font-size:12px; padding:5px 0; border-bottom:1px solid rgba(255,255,255,0.05); }
.meta-k{ color:var(--ink-faint); } .meta-v{ color:var(--ink); text-align:right; }
.meta-v.flag{ color:var(--warn); }
.report{ position:relative; margin-top:18px; background:rgba(0,0,0,0.2); border:1px solid var(--line);
  border-radius:3px; padding:20px 22px 22px; }
.stamp{ position:absolute; top:16px; right:18px; font-family:'JetBrains Mono',monospace; font-weight:800;
  font-size:13px; letter-spacing:1.5px; padding:9px 14px; border-radius:6px; border:2.5px solid currentColor;
  transform:rotate(-7deg); }
.field{ margin-top:16px; } .field-label{ font-family:'JetBrains Mono',monospace; font-size:10.5px;
  letter-spacing:1.5px; color:var(--ink-faint); margin-bottom:6px; }
.conf-bar-track{ height:8px; background:rgba(255,255,255,0.06); border-radius:6px; overflow:hidden; }
.conf-bar-fill{ height:100%; border-radius:6px; }
.conf-num{ font-family:'JetBrains Mono',monospace; font-size:12.5px; margin-top:5px; color:var(--ink-dim); }
.findings{ margin:0; padding-left:18px; font-size:13px; line-height:1.65; color:var(--ink); }
.findings li{ margin-bottom:6px; }
.recommend{ font-size:13px; line-height:1.65; color:var(--ink-dim); margin:0; }
footer{ visibility:hidden; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

if "exhibit_counter" not in st.session_state:
    st.session_state.exhibit_counter = 0
if "case_num" not in st.session_state:
    st.session_state.case_num = "— belum ada analisis —"


def next_case_number():
    st.session_state.exhibit_counter += 1
    ymd = datetime.now().strftime("%Y%m%d")
    st.session_state.case_num = f"SDK-{ymd}-{st.session_state.exhibit_counter:03d}"


# ============================================================
# HEADER
# ============================================================
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown(
        "<h1 style='margin-bottom:0;'>&#9670; SIDIK</h1>"
        "<p style='color:var(--ink-dim);margin-top:2px;'>Sistem Identifikasi Dokumen, Imaji &amp; Konten "
        "&middot; Analisis Zero-Trust &middot; Berjalan Lokal di Mesin Anda</p>",
        unsafe_allow_html=True,
    )
with col_h2:
    st.markdown(
        f"<div class='case-tag'>BERKAS KASUS №<span class='case-num'>{st.session_state.case_num}</span></div>",
        unsafe_allow_html=True,
    )

st.markdown("<hr style='border-color:#3A3C40;'>", unsafe_allow_html=True)

tab_img, tab_text, tab_pdf = st.tabs(["🖼 BUKTI GAMBAR", "📝 BUKTI TEKS", "📄 BUKTI DOKUMEN (PDF)"])

# ============================================================
# EDITING SOFTWARE SIGNATURES
# ============================================================
EDIT_SOFTWARE = [
    "photoshop", "gimp", "lightroom", "snapseed", "picsart", "canva", "meitu",
    "facetune", "pixlr", "affinity photo", "capcut", "vsco", "paint.net", "photoscape",
]


def is_editing_software(s: str) -> bool:
    s = s.lower()
    return any(k in s for k in EDIT_SOFTWARE)


# ============================================================
# EXIF
# ============================================================
def parse_exif(img: Image.Image):
    try:
        exif = img.getexif()
        if not exif:
            return None
        data = {TAGS.get(k, k): v for k, v in exif.items()}
        try:
            sub = exif.get_ifd(0x8769)
            for k, v in sub.items():
                data[TAGS.get(k, k)] = v
        except Exception:
            pass
        result = {
            "make": data.get("Make"),
            "model": data.get("Model"),
            "software": data.get("Software"),
            "date_time": data.get("DateTimeOriginal") or data.get("DateTime"),
            "exposure_time": data.get("ExposureTime"),
            "f_number": data.get("FNumber"),
            "gps": 0x8825 in exif,
        }
        if not any(v not in (None, False) for v in result.values()):
            return None
        return result
    except Exception:
        return None


# ============================================================
# ERROR LEVEL ANALYSIS
# ============================================================
def compute_ela(img: Image.Image, quality=90, amplify=12):
    max_dim = 1100
    w, h = img.size
    scale = min(1.0, max_dim / max(w, h))
    if scale < 1.0:
        img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))))

    rgb = img.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    diff = ImageChops.difference(rgb, resaved)
    arr = np.array(diff).astype(float)
    mag = arr.mean(axis=2)
    amp = np.clip(mag * amplify, 0, 255).astype("uint8")
    ela_img = Image.fromarray(amp).convert("L")

    grid_n = 8
    hh, ww = mag.shape
    bh, bw = max(1, hh // grid_n), max(1, ww // grid_n)
    block_means = []
    for by in range(grid_n):
        for bx in range(grid_n):
            y0, y1 = by * bh, min(hh, (by + 1) * bh)
            x0, x1 = bx * bw, min(ww, (bx + 1) * bw)
            block = mag[y0:y1, x0:x1]
            if block.size > 0:
                block_means.append(block.mean())
    block_means = np.array(block_means) if block_means else np.array([0.0])
    overall_mean = float(block_means.mean())
    stdev = float(block_means.std())
    cv = stdev / overall_mean if overall_mean > 0.6 else 0.0
    return ela_img, rgb, overall_mean, stdev, cv


# ============================================================
# SCORING — GAMBAR
# ============================================================
def score_image(exif, mean, stdev, cv, is_jpeg):
    score = 55
    data_signals = 0
    findings = []

    if exif:
        data_signals += 1
        device = " ".join(str(x) for x in [exif.get("make"), exif.get("model")] if x) or "—"
        findings.append(f'Metadata EXIF ditemukan pada berkas ({device}).')
        score += 12
        if exif.get("exposure_time") or exif.get("f_number"):
            data_signals += 1
            score += 8
            findings.append(
                "Parameter kamera (exposure/aperture) tercatat — konsisten dengan foto asli "
                "langsung dari perangkat, bukan hasil unduhan/tangkapan layar."
            )
        if exif.get("software"):
            findings.append(f'Software tercatat dalam metadata: "{exif["software"]}".')
            if is_editing_software(str(exif["software"])):
                score -= 28
                findings.append("PERHATIAN: software yang tercatat dikenal sebagai alat penyunting gambar.")
        if exif.get("gps"):
            findings.append("Data lokasi GPS tersemat dalam metadata.")
    else:
        findings.append(
            "Metadata EXIF tidak ditemukan pada berkas ini — umum terjadi pada tangkapan layar, "
            "gambar hasil unduhan medsos/WhatsApp, atau berkas yang metadatanya sengaja dihapus."
        )

    data_signals += 1
    if is_jpeg:
        if cv > 0.85:
            score -= 22
            findings.append(
                f"Error Level Analysis (ELA) menunjukkan variasi kompresi tidak merata antar-area "
                f"gambar (indeks variansi {cv:.2f}) — indikasi kemungkinan ada area yang disunting/"
                f"ditempel dari sumber lain."
            )
        elif mean < 0.6:
            findings.append(
                "Perbedaan kompresi pada ELA sangat kecil secara keseluruhan — kurang cukup sinyal "
                "untuk menilai riwayat kompresi gambar ini."
            )
        else:
            score += 10
            findings.append(
                f"Pola ELA relatif merata di seluruh gambar (indeks variansi {cv:.2f}) — tidak ada "
                f"indikasi kuat area sunting lokal."
            )
    else:
        findings.append(
            "Format berkas bukan JPEG — hasil ELA kurang definitif untuk format ini dan hanya "
            "bersifat indikasi tambahan."
        )

    score = max(0, min(100, score))
    if data_signals <= 1:
        status = "TIDAK DAPAT DIVERIFIKASI"
        findings.append("Sinyal forensik yang tersedia terlalu sedikit pada berkas ini untuk memberikan vonis yang pasti.")
    elif score >= 68:
        status = "AMAN"
    elif score >= 40:
        status = "MENCURIGAKAN"
    else:
        status = "PALSU"

    confidence = min(score, 50) if data_signals <= 1 else score
    return status, confidence, findings


# ============================================================
# SCORING — TEKS
# ============================================================
def find_repeated_phrases(words):
    n = 5
    counts = Counter()
    for i in range(len(words) - n + 1):
        gram = " ".join(words[i:i + n]).lower()
        cleaned = re.sub(r"[^a-z0-9à-ÿ ]", "", gram)
        if len(cleaned) < 10:
            continue
        counts[gram] += 1
    return [g for g, c in counts.items() if c >= 3]


def paragraph_stats(text):
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    stats = []
    for p in paras:
        sents = [s.strip() for s in re.split(r"[.!?]+", p) if s.strip()]
        lens = [len(s.split()) for s in sents]
        avg = sum(lens) / len(lens) if lens else 0
        stats.append({"avg": avg, "sent_count": len(sents)})
    return stats


def extract_dates(text):
    results = set()
    results.update(re.findall(r"\b\d{4}-\d{2}-\d{2}\b", text))
    results.update(re.findall(
        r"\b\d{1,2}\s(?:Januari|Februari|Maret|April|Mei|Juni|Juli|Agustus|September|Oktober|November|Desember)\s\d{2,4}\b",
        text, re.IGNORECASE))
    results.update(re.findall(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", text))
    return list(results)


def extract_numbers(text):
    results = set()
    results.update(m.strip() for m in re.findall(r"\bRp\s?[\d.,]+\b", text, re.IGNORECASE))
    results.update(m.strip() for m in re.findall(r"\$\s?[\d.,]+\b", text))
    results.update(m.strip() for m in re.findall(r"\b\d+(?:[.,]\d+)?\s?%", text))
    return list(results)


def score_text(text):
    words = text.split()
    if len(words) < 40:
        return "TIDAK DAPAT DIVERIFIKASI", 35, [
            f"Teks yang dimasukkan terlalu pendek ({len(words)} kata) untuk analisis pola yang bermakna.",
            "Minimal disarankan beberapa paragraf agar variasi kalimat dan gaya bahasa dapat dinilai.",
        ]

    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
    sent_lens = [len(s.split()) for s in sentences]
    mean_len = sum(sent_lens) / len(sent_lens) if sent_lens else 0
    variance = sum((l - mean_len) ** 2 for l in sent_lens) / len(sent_lens) if sent_lens else 0
    stdev_len = variance ** 0.5
    cv = stdev_len / mean_len if mean_len > 0 else 0

    unique_words = {re.sub(r"[^a-z0-9à-ÿ]", "", w.lower()) for w in words}
    unique_words.discard("")
    ttr = len(unique_words) / len(words) if words else 0

    repeated = find_repeated_phrases(words)
    paras = paragraph_stats(text)
    valid_paras = [p for p in paras if p["sent_count"] >= 1]
    doc_avg = sum(p["avg"] for p in valid_paras) / len(valid_paras) if valid_paras else 0
    style_shift = [i for i, p in enumerate(valid_paras)
                   if p["sent_count"] >= 2 and doc_avg > 0 and abs(p["avg"] - doc_avg) / doc_avg > 0.5]

    dates = extract_dates(text)
    numbers = extract_numbers(text)

    score = 60
    findings = []

    if len(sent_lens) >= 6:
        if cv < 0.30:
            score -= 15
            findings.append(
                f"Variasi panjang kalimat sangat rendah (indeks={cv:.2f}) — pola ini kerap ditemukan "
                f"pada teks yang dihasilkan otomatis/AI atau template, meski tidak konklusif dengan sendirinya."
            )
        else:
            score += 8
            findings.append(f"Variasi panjang kalimat berada dalam rentang yang wajar untuk tulisan manusia (indeks={cv:.2f}).")

    if len(words) > 150:
        if ttr < 0.35:
            score -= 8
            findings.append(f"Rasio kosakata unik terhadap total kata cukup rendah ({ttr*100:.0f}%) — indikasi pengulangan/templating.")
        else:
            findings.append(f"Rasio kosakata unik terhadap total kata dalam rentang wajar ({ttr*100:.0f}%).")

    if repeated:
        score -= 15
        findings.append('Ditemukan frasa berulang signifikan (5 kata berturut-turut muncul ≥3×): "' + '" · "'.join(repeated[:3]) + '".')

    if style_shift:
        score -= 12
        for i in style_shift[:2]:
            findings.append(
                f"Paragraf ke-{i+1} menunjukkan panjang kalimat yang menyimpang signifikan dari "
                f"rata-rata dokumen — indikasi kemungkinan teks disisipkan dari sumber berbeda."
            )

    if dates:
        findings.append("Tanggal terdeteksi dalam teks: " + ", ".join(dates[:8]) + ". Periksa konsistensi tanggal ini secara manual terhadap konteks dokumen.")
    if numbers:
        findings.append("Angka/nilai penting terdeteksi: " + ", ".join(numbers[:8]) + ". Disarankan verifikasi silang dengan sumber asli.")

    if not findings:
        findings.append("Tidak ditemukan pola anomali yang jelas pada pemeriksaan heuristik ini.")

    score = max(0, min(100, score))
    if score >= 68:
        status = "AMAN"
    elif score >= 40:
        status = "MENCURIGAKAN"
    else:
        status = "PALSU"

    if status == "PALSU" and not repeated and not style_shift:
        status = "MENCURIGAKAN"

    return status, score, findings


# ============================================================
# SCORING — DOKUMEN PDF
# ============================================================
PDF_EDIT_TOOLS = [
    "ilovepdf", "smallpdf", "pdf24", "sejda", "pdfescape", "soda pdf", "nitro",
    "foxit", "pdf-xchange", "pdfelement", "wondershare", "sodapdf", "pdfsimpli",
    "canva", "docupub", "pdfcandy",
]


def is_pdf_edit_tool(s: str) -> bool:
    s = s.lower()
    return any(k in s for k in PDF_EDIT_TOOLS)


def analyze_pdf(raw_bytes: bytes):
    reader = PdfReader(io.BytesIO(raw_bytes))
    meta = reader.metadata or {}
    n_pages = len(reader.pages)
    eof_count = raw_bytes.count(b"%%EOF")
    has_signature = b"/Sig" in raw_bytes and b"/ByteRange" in raw_bytes
    fonts = set(re.findall(rb"/BaseFont\s*/([A-Za-z0-9+\-,._]+)", raw_bytes))

    def g(key):
        try:
            return meta.get(key)
        except Exception:
            return None

    info = {
        "producer": g("/Producer"),
        "creator": g("/Creator"),
        "author": g("/Author"),
        "creation_date": g("/CreationDate"),
        "mod_date": g("/ModDate"),
        "n_pages": n_pages,
        "eof_count": eof_count,
        "has_signature": has_signature,
        "n_fonts": len(fonts),
    }
    return info


def score_pdf(info):
    score = 60
    data_signals = 0
    findings = []

    has_meta = any([info["producer"], info["creator"], info["author"], info["creation_date"]])
    if has_meta:
        data_signals += 1
        producer_creator = " / ".join(str(x) for x in [info["producer"], info["creator"]] if x)
        if producer_creator:
            findings.append(f'Metadata pembuat dokumen: "{producer_creator}".')
            if is_pdf_edit_tool(producer_creator):
                score -= 15
                findings.append("Tercatat menggunakan layanan/editor PDF pihak ketiga yang umum dipakai untuk menyunting ulang dokumen.")
        if info["creation_date"] and info["mod_date"] and info["creation_date"] != info["mod_date"]:
            findings.append(f'Dokumen tercatat pernah dimodifikasi — dibuat: {info["creation_date"]}, terakhir diubah: {info["mod_date"]}.')
    else:
        findings.append("Metadata pembuat dokumen (Producer/Creator/Author) tidak ditemukan.")

    data_signals += 1
    if info["eof_count"] > 1:
        score -= 25
        findings.append(
            f'Ditemukan {info["eof_count"]} penanda %%EOF dalam struktur berkas — mengindikasikan '
            f'dokumen telah disimpan ulang beberapa kali (incremental update). Ini bisa berarti dokumen '
            f'diedit setelah revisi/tanda tangan awal.'
        )
    else:
        score += 10
        findings.append("Hanya ditemukan satu penanda %%EOF — tidak ada indikasi penyimpanan ulang/revisi tambahan pada struktur berkas.")

    if info["has_signature"]:
        findings.append(
            "Berkas mengandung objek tanda tangan digital. Alat ini TIDAK melakukan validasi kriptografis "
            "— gunakan Adobe Acrobat Reader atau layanan validasi sertifikat resmi untuk memastikan keabsahannya."
        )
    else:
        findings.append("Tidak ditemukan tanda tangan digital tersemat pada berkas ini.")

    if info["n_fonts"] > 0:
        findings.append(f'{info["n_fonts"]} jenis font unik terdeteksi dalam {info["n_pages"]} halaman.')
        if info["n_fonts"] > 6 and info["n_pages"] <= 3:
            score -= 8
            findings.append("Jumlah font relatif banyak untuk dokumen sependek ini — bisa mengindikasikan konten yang digabung dari beberapa sumber berbeda.")

    score = max(0, min(100, score))
    if data_signals <= 1:
        status = "TIDAK DAPAT DIVERIFIKASI"
        findings.append("Sinyal forensik yang tersedia terlalu sedikit pada berkas ini untuk memberikan vonis yang pasti.")
    elif score >= 68:
        status = "AMAN"
    elif score >= 40:
        status = "MENCURIGAKAN"
    else:
        status = "PALSU"

    confidence = min(score, 50) if data_signals <= 1 else score
    return status, confidence, findings


# ============================================================
# REPORT RENDERING
# ============================================================
def get_recommendation(status):
    return {
        "AMAN": "Tidak ditemukan indikasi kuat manipulasi pada pemeriksaan ini. Tetap disarankan verifikasi silang dengan sumber asli/pihak terkait untuk kasus yang penting.",
        "MENCURIGAKAN": "Lakukan verifikasi manual lanjutan: bandingkan dengan sumber asli, gunakan tools forensik profesional (mis. ExifTool, FotoForensics) untuk analisis lebih dalam, dan konfirmasi langsung ke pihak/pembuat dokumen.",
        "PALSU": "Indikasi manipulasi cukup kuat. Jangan gunakan sebagai bukti tanpa verifikasi forensik profesional lebih lanjut. Simpan berkas asli beserta metadatanya untuk keperluan investigasi lanjutan.",
    }.get(status, "Sinyal/data forensik yang tersedia tidak cukup untuk kesimpulan yang meyakinkan. Sediakan berkas asli beresolusi penuh atau gunakan alat forensik digital profesional untuk analisis lebih lanjut.")


STATUS_COLOR = {
    "AMAN": "#3FAE63",
    "MENCURIGAKAN": "#D3A24B",
    "PALSU": "#C1594F",
    "TIDAK DAPAT DIVERIFIKASI": "#9C9C94",
}


def render_report(status, confidence, findings, recommendation):
    color = STATUS_COLOR.get(status, "#9C9C94")
    findings_html = "".join(f"<li>{f}</li>" for f in findings)
    html = f"""
    <div class="report">
      <div class="stamp" style="color:{color};">{status}</div>
      <h3 style="margin:0 0 4px;font-size:11px;letter-spacing:1.5px;color:#8B8B84;">LAPORAN ANALISIS FORENSIK</h3>
      <div class="field">
        <div class="field-label">STATUS KEASLIAN</div>
        <div style="font-family:'JetBrains Mono',monospace;font-weight:800;font-size:17px;color:{color};">{status}</div>
      </div>
      <div class="field">
        <div class="field-label">TINGKAT KEYAKINAN</div>
        <div class="conf-bar-track"><div class="conf-bar-fill" style="width:{confidence}%;background:{color};"></div></div>
        <div class="conf-num">{round(confidence)}% &middot; indikatif berdasarkan heuristik, bukan probabilitas statistik formal</div>
      </div>
      <div class="field">
        <div class="field-label">TEMUAN UTAMA</div>
        <ul class="findings">{findings_html}</ul>
      </div>
      <div class="field">
        <div class="field-label">REKOMENDASI TINDAKAN</div>
        <p class="recommend">{recommendation}</p>
      </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


# ============================================================
# TAB: BUKTI GAMBAR
# ============================================================
with tab_img:
    col1, col2 = st.columns([1.1, 1])
    with col1:
        uploaded = st.file_uploader("Seret bukti gambar ke sini atau klik untuk memilih file", type=["jpg", "jpeg", "png"])
        if uploaded:
            raw_bytes = uploaded.getvalue()
            img = Image.open(io.BytesIO(raw_bytes))
            exif = parse_exif(img)
            is_jpeg = uploaded.type in ("image/jpeg", "image/jpg")

            view = st.radio("Tampilan", ["Asli", "Analisis ELA"], horizontal=True, label_visibility="collapsed")
            ela_img, rgb_preview, mean, stdev, cv = compute_ela(img)
            if view == "Asli":
                st.image(rgb_preview, use_container_width=True)
            else:
                st.image(ela_img, use_container_width=True)
            st.caption("Error Level Analysis (ELA) menyorot area dengan riwayat kompresi berbeda dari sekitarnya — area terang berpotensi menandakan bagian yang disunting/ditempel.")

    with col2:
        st.markdown("<div class='readout'><h4>PEMBACAAN METADATA</h4>", unsafe_allow_html=True)
        if uploaded:
            rows = ""
            rows += f"<div class='meta-row'><span class='meta-k'>Nama Berkas</span><span class='meta-v'>{uploaded.name}</span></div>"
            rows += f"<div class='meta-row'><span class='meta-k'>Ukuran</span><span class='meta-v'>{len(raw_bytes)/1024:.1f} KB</span></div>"
            rows += f"<div class='meta-row'><span class='meta-k'>Dimensi</span><span class='meta-v'>{img.width} × {img.height} px</span></div>"
            if exif:
                rows += "<div class='meta-row'><span class='meta-k'>Metadata EXIF</span><span class='meta-v'>Ditemukan</span></div>"
                if exif.get("make") or exif.get("model"):
                    device = " ".join(str(x) for x in [exif.get("make"), exif.get("model")] if x)
                    rows += f"<div class='meta-row'><span class='meta-k'>Perangkat</span><span class='meta-v'>{device}</span></div>"
                if exif.get("software"):
                    flag = "flag" if is_editing_software(str(exif["software"])) else ""
                    rows += f"<div class='meta-row'><span class='meta-k'>Software</span><span class='meta-v {flag}'>{exif['software']}</span></div>"
                rows += f"<div class='meta-row'><span class='meta-k'>Data GPS</span><span class='meta-v'>{'Tersemat' if exif.get('gps') else 'Tidak ada'}</span></div>"
            else:
                rows += "<div class='meta-row'><span class='meta-k'>Metadata EXIF</span><span class='meta-v flag'>Tidak ditemukan</span></div>"
            st.markdown(rows + "</div>", unsafe_allow_html=True)
        else:
            st.markdown("<p style='color:#5C5D58;font-size:12.5px;'>Unggah gambar untuk memulai pembacaan metadata EXIF &amp; analisis ELA.</p></div>", unsafe_allow_html=True)

        if uploaded and st.button("JALANKAN ANALISIS FORENSIK", key="run_img"):
            status, confidence, findings = score_image(exif, mean, stdev, cv, is_jpeg)
            next_case_number()
            st.session_state.img_report = (status, confidence, findings, get_recommendation(status))
            st.rerun()

    if uploaded and "img_report" in st.session_state:
        render_report(*st.session_state.img_report)

# ============================================================
# TAB: BUKTI TEKS
# ============================================================
with tab_text:
    text_input = st.text_area("Tempel teks yang ingin diperiksa", height=220,
                               placeholder="Tempel teks/dokumen yang ingin diperiksa di sini...")
    if st.button("JALANKAN ANALISIS FORENSIK", key="run_text"):
        if not text_input.strip():
            st.warning("Masukkan teks terlebih dahulu.")
        else:
            status, confidence, findings = score_text(text_input)
            next_case_number()
            st.session_state.text_report = (status, confidence, findings, get_recommendation(status))

    if "text_report" in st.session_state:
        render_report(*st.session_state.text_report)

# ============================================================
# TAB: BUKTI DOKUMEN (PDF)
# ============================================================
with tab_pdf:
    col1, col2 = st.columns([1, 1])
    with col1:
        pdf_file = st.file_uploader("Seret berkas PDF ke sini atau klik untuk memilih file", type=["pdf"])
        pdf_info = None
        if pdf_file:
            pdf_bytes = pdf_file.getvalue()
            try:
                pdf_info = analyze_pdf(pdf_bytes)
            except Exception as e:
                st.error(f"Gagal membaca struktur PDF: {e}")

    with col2:
        st.markdown("<div class='readout'><h4>PEMBACAAN STRUKTUR &amp; METADATA</h4>", unsafe_allow_html=True)
        if pdf_info:
            rows = ""
            rows += f"<div class='meta-row'><span class='meta-k'>Nama Berkas</span><span class='meta-v'>{pdf_file.name}</span></div>"
            rows += f"<div class='meta-row'><span class='meta-k'>Ukuran</span><span class='meta-v'>{len(pdf_bytes)/1024:.1f} KB</span></div>"
            rows += f"<div class='meta-row'><span class='meta-k'>Jumlah Halaman</span><span class='meta-v'>{pdf_info['n_pages']}</span></div>"
            if pdf_info["producer"]:
                rows += f"<div class='meta-row'><span class='meta-k'>Producer</span><span class='meta-v'>{pdf_info['producer']}</span></div>"
            if pdf_info["creator"]:
                rows += f"<div class='meta-row'><span class='meta-k'>Creator</span><span class='meta-v'>{pdf_info['creator']}</span></div>"
            if pdf_info["author"]:
                rows += f"<div class='meta-row'><span class='meta-k'>Author</span><span class='meta-v'>{pdf_info['author']}</span></div>"
            flag = "flag" if pdf_info["eof_count"] > 1 else ""
            rows += f"<div class='meta-row'><span class='meta-k'>Penanda %%EOF</span><span class='meta-v {flag}'>{pdf_info['eof_count']}</span></div>"
            rows += f"<div class='meta-row'><span class='meta-k'>Tanda Tangan Digital</span><span class='meta-v'>{'Terdeteksi' if pdf_info['has_signature'] else 'Tidak ada'}</span></div>"
            st.markdown(rows + "</div>", unsafe_allow_html=True)
        else:
            st.markdown("<p style='color:#5C5D58;font-size:12.5px;'>Unggah berkas PDF untuk memulai pembacaan metadata &amp; struktur revisi.</p></div>", unsafe_allow_html=True)

        if pdf_info and st.button("JALANKAN ANALISIS FORENSIK", key="run_pdf"):
            status, confidence, findings = score_pdf(pdf_info)
            next_case_number()
            st.session_state.pdf_report = (status, confidence, findings, get_recommendation(status))
            st.rerun()

    if pdf_file and "pdf_report" in st.session_state:
        render_report(*st.session_state.pdf_report)

st.markdown(
    "<p style='text-align:center;color:#5C5D58;font-size:11.5px;margin-top:24px;'>"
    "⚠ Alat ini menghasilkan sinyal indikatif berbasis heuristik lokal — seluruh pemrosesan berjalan "
    "di mesin Anda, tidak ada file yang diunggah ke server manapun. Ini BUKAN pengganti laboratorium "
    "forensik digital bersertifikat untuk kebutuhan hukum/formal.</p>",
    unsafe_allow_html=True,
)
