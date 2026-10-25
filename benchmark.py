"""
Benchmark komparatif cipher di Nestiefy: AES-GCM, DES-CBC+HMAC, RC4+HMAC.

APA YANG DIUKUR
1. Waktu enkripsi & dekripsi end-to-end lewat crypto.encrypt_file / decrypt_file.
   Ini SAMA dengan yang dijalankan aplikasi saat upload/download, yaitu:
     - generate data key acak per file
     - enkripsi/dekripsi isi file
     - tag integritas (GCM tag untuk AES, HMAC-SHA256 untuk DES & RC4)
     - SHA-256 plaintext (verifikasi kedua)
     - wrap/unwrap data key dengan master key
   I/O disk & jaringan TIDAK diukur (supaya yang terbandingkan murni kriptografinya).
2. Throughput (MB/s) = ukuran plaintext / median waktu.
3. Overhead penyimpanan:
     - ciphertext : selisih ukuran file .enc vs file asli (padding)
     - metadata   : IV/nonce + tag + wrapped key + IV wrap yang disimpan di database
4. Deteksi manipulasi: 1 bit ciphertext dibalik -> dekripsi HARUS ditolak.
5. Breakdown komponen (ukuran 10 MB): cipher murni vs HMAC-SHA256 vs SHA-256,
   untuk menjelaskan DARI MANA waktu berasal.

METODOLOGI
- Data uji acak (os.urandom) -> tidak bisa dikompresi, mewakili PDF/JPG/MP4.
- Warm-up dulu (hasil dibuang) untuk menghindari efek cold start.
- Garbage collector dimatikan saat pengukuran supaya tidak muncul jeda acak.
- Median dari N repetisi (tahan outlier) + IQR (P25-P75) sebagai ukuran sebaran.
- Ukuran 100 MB mewakili video; repetisinya lebih sedikit supaya waktu total wajar.
- Spesifikasi mesin disimpan di benchmark_env.txt -> wajib dicantumkan di laporan.

CARA PAKAI
    python benchmark.py            # lengkap (beberapa menit, sampai 100 MB)
    python benchmark.py --quick    # cepat, untuk cek skrip jalan (tanpa 100 MB)

OUTPUT
    benchmark_results.csv   hasil per cipher x ukuran
    benchmark_env.txt       spesifikasi mesin & versi library
"""

import argparse
import csv
import gc
import hashlib
import hmac
import os
import platform
import secrets
import statistics
import sys
import time
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path

# Benchmark tidak butuh .env asli. Kalau master key belum ada, pakai key acak
# sementara (hanya hidup selama skrip berjalan, tidak disimpan ke mana pun).
os.environ.setdefault("MASTER_KEY_AES", secrets.token_hex(32))

import crypto  # noqa: E402  (harus setelah master key diset)
from Crypto.Cipher import AES, DES, ARC4  # noqa: E402
from Crypto.Util.Padding import pad  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent
CIPHERS = ["AES", "DES", "RC4"]
CIPHER_LABEL = {"AES": "AES-256-GCM", "DES": "DES-CBC+HMAC", "RC4": "RC4+HMAC"}

MB = 1024 * 1024

# (label, ukuran byte, jumlah repetisi)
SIZES_FULL = [
    ("1 KB", 1024, 50),
    ("10 KB", 10 * 1024, 50),
    ("100 KB", 100 * 1024, 30),
    ("1 MB", 1 * MB, 20),
    ("10 MB", 10 * MB, 10),
    ("100 MB", 100 * MB, 3),     # mewakili video
]
SIZES_QUICK = [
    ("1 KB", 1024, 10),
    ("100 KB", 100 * 1024, 5),
    ("10 MB", 10 * MB, 3),
]
WARMUP_ROUNDS = 2

# Ukuran video untuk estimasi di bagian interpretasi
VIDEO_ESTIMATE_MB = 200


# ----------------------------------------------------------------------------
# Helper statistik & format
# ----------------------------------------------------------------------------
def percentile(values, p):
    """Persentil sederhana (interpolasi linear), p dalam 0..100."""
    data = sorted(values)
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(data) - 1)
    return data[lo] + (data[hi] - data[lo]) * (k - lo)


def timed(fn):
    """Jalankan fn() dan kembalikan (hasil, durasi_ms)."""
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1000


def fmt_ms(ms):
    return f"{ms / 1000:.2f} s" if ms >= 1000 else f"{ms:.2f} ms"


# ----------------------------------------------------------------------------
# 1. Benchmark end-to-end (sama dengan alur upload/download aplikasi)
# ----------------------------------------------------------------------------
def benchmark_one(cipher, plaintext, repetitions):
    for _ in range(WARMUP_ROUNDS):
        crypto.decrypt_file(crypto.encrypt_file(plaintext, cipher), cipher)

    enc_times, dec_times = [], []
    gc.disable()
    try:
        for _ in range(repetitions):
            blob, t_enc = timed(lambda: crypto.encrypt_file(plaintext, cipher))
            recovered, t_dec = timed(lambda: crypto.decrypt_file(blob, cipher))
            if recovered != plaintext:
                raise RuntimeError(f"{cipher}: hasil dekripsi tidak sama dengan plaintext!")
            enc_times.append(t_enc)
            dec_times.append(t_dec)
    finally:
        gc.enable()

    size_mb = len(plaintext) / MB
    enc_med = statistics.median(enc_times)
    dec_med = statistics.median(dec_times)
    ct_overhead = len(blob["ciphertext"]) - len(plaintext)
    meta_bytes = (len(blob["iv_or_nonce"]) + len(blob["auth_tag"])
                  + len(blob["wrapped_key"]) + len(blob["key_wrap_iv"]))

    return {
        "cipher": cipher,
        "plaintext_bytes": len(plaintext),
        "repetitions": repetitions,
        "enc_ms_median": enc_med,
        "enc_ms_p25": percentile(enc_times, 25),
        "enc_ms_p75": percentile(enc_times, 75),
        "dec_ms_median": dec_med,
        "dec_ms_p25": percentile(dec_times, 25),
        "dec_ms_p75": percentile(dec_times, 75),
        "enc_mb_per_s": size_mb / (enc_med / 1000),
        "dec_mb_per_s": size_mb / (dec_med / 1000),
        "ciphertext_overhead_bytes": ct_overhead,
        "metadata_bytes": meta_bytes,
    }


# ----------------------------------------------------------------------------
# 2. Deteksi manipulasi: balik 1 bit ciphertext -> harus ditolak
# ----------------------------------------------------------------------------
def tamper_test(cipher):
    plaintext = os.urandom(4096)
    blob = crypto.encrypt_file(plaintext, cipher)
    corrupted = bytearray(blob["ciphertext"])
    corrupted[len(corrupted) // 2] ^= 0x01
    blob["ciphertext"] = bytes(corrupted)
    try:
        crypto.decrypt_file(blob, cipher)
    except Exception as exc:
        return True, type(exc).__name__
    return False, "-"


# ----------------------------------------------------------------------------
# 3. Breakdown komponen pada 10 MB (cipher murni vs biaya integritas)
# ----------------------------------------------------------------------------
def component_breakdown(size=10 * MB, repetitions=5):
    data = os.urandom(size)
    k32, k8 = os.urandom(32), os.urandom(8)
    tasks = {
        "AES-256-GCM (enkripsi + tag)": lambda: AES.new(k32, AES.MODE_GCM, nonce=os.urandom(12)).encrypt_and_digest(data),
        "DES-CBC (enkripsi saja)": lambda: DES.new(k8, DES.MODE_CBC, iv=os.urandom(8)).encrypt(pad(data, 8)),
        "RC4 (enkripsi saja)": lambda: ARC4.new(k32).encrypt(data),
        "HMAC-SHA256 (untuk DES & RC4)": lambda: hmac.new(k32, data, hashlib.sha256).digest(),
        "SHA-256 plaintext (semua cipher)": lambda: hashlib.sha256(data).digest(),
    }
    results = {}
    for name, fn in tasks.items():
        fn()  # warm-up
        gc.disable()
        try:
            times = [timed(fn)[1] for _ in range(repetitions)]
        finally:
            gc.enable()
        results[name] = (size / MB) / (statistics.median(times) / 1000)
    return results


# ----------------------------------------------------------------------------
# Info mesin (wajib dicantumkan di laporan)
# ----------------------------------------------------------------------------
def environment_info():
    def pkg(name):
        try:
            return version(name)
        except PackageNotFoundError:
            return "tidak terdeteksi"

    return {
        "OS": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "CPU": platform.processor() or "tidak terdeteksi (isi manual)",
        "Python": sys.version.split()[0],
        "pycryptodome": pkg("pycryptodome"),
        "Waktu": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
def print_table(results):
    print("\n" + "=" * 118)
    print("HASIL BENCHMARK END-TO-END (median; IQR = rentang P25-P75)")
    print("=" * 118)
    print(f"{'Cipher':<14}{'Ukuran':<9}{'Rep':>4}  {'Enkripsi':>10} {'IQR enc':>19}  "
          f"{'Dekripsi':>10}  {'Enc MB/s':>9} {'Dec MB/s':>9}  {'+CT':>4} {'+Meta':>6}")
    print("-" * 118)
    for r in results:
        iqr = f"{r['enc_ms_p25']:.2f}-{r['enc_ms_p75']:.2f} ms"
        print(f"{CIPHER_LABEL[r['cipher']]:<14}{r['size_label']:<9}{r['repetitions']:>4}  "
              f"{fmt_ms(r['enc_ms_median']):>10} {iqr:>19}  {fmt_ms(r['dec_ms_median']):>10}  "
              f"{r['enc_mb_per_s']:>9.1f} {r['dec_mb_per_s']:>9.1f}  "
              f"{r['ciphertext_overhead_bytes']:>3}B {r['metadata_bytes']:>5}B")
    print("-" * 118)
    print("+CT   = tambahan ukuran file .enc dibanding file asli (padding)")
    print("+Meta = IV/nonce + tag + wrapped key + IV wrap yang disimpan di database per file")


def write_csv(results, path):
    fields = ["cipher", "size_label", "plaintext_bytes", "repetitions",
              "enc_ms_median", "enc_ms_p25", "enc_ms_p75",
              "dec_ms_median", "dec_ms_p25", "dec_ms_p75",
              "enc_mb_per_s", "dec_mb_per_s",
              "ciphertext_overhead_bytes", "metadata_bytes"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r[k] for k in fields})


def print_interpretation(results, sizes, tamper, breakdown):
    print("\n" + "=" * 118)
    print("INTERPRETASI (bahan laporan - tetap periksa & tulis ulang dengan kata-kata sendiri)")
    print("=" * 118)

    get = {(r["cipher"], r["size_label"]): r for r in results}
    labels = [s[0] for s in sizes]

    # a. Cipher tercepat per ukuran
    print("\n[a] Cipher tercepat (enkripsi) per ukuran file:")
    for label in labels:
        ranking = sorted(CIPHERS, key=lambda c: get[(c, label)]["enc_ms_median"])
        best, second = ranking[0], ranking[1]
        ratio = get[(second, label)]["enc_ms_median"] / get[(best, label)]["enc_ms_median"]
        order = " < ".join(f"{c} {fmt_ms(get[(c, label)]['enc_ms_median'])}" for c in ranking)
        print(f"    {label:<7}: {order}   ({best} {ratio:.1f}x lebih cepat dari {second})")

    # b. Perbandingan di ukuran terbesar (rasio dihitung dengan arah yang benar)
    largest = labels[-1]
    tp = {c: get[(c, largest)]["enc_mb_per_s"] for c in CIPHERS}
    fastest = max(tp, key=tp.get)
    print(f"\n[b] Throughput enkripsi pada {largest}:")
    for c in sorted(CIPHERS, key=tp.get, reverse=True):
        note = "tercepat" if c == fastest else f"{tp[fastest] / tp[c]:.1f}x lebih lambat dari {fastest}"
        print(f"    {CIPHER_LABEL[c]:<14}: {tp[c]:>8.1f} MB/s  ({note})")

    # c. Estimasi untuk skenario (dokumen kecil vs video)
    print(f"\n[c] Estimasi waktu enkripsi untuk skenario Nestiefy (dari throughput {largest}):")
    for name, size_mb in [("Scan KTP / PDF ~500 KB", 0.5), (f"Video kamar ~{VIDEO_ESTIMATE_MB} MB", VIDEO_ESTIMATE_MB)]:
        parts = ", ".join(f"{c} {fmt_ms(size_mb / tp[c] * 1000)}" for c in CIPHERS)
        print(f"    {name:<26}: {parts}")

    # d. Breakdown komponen
    print("\n[d] Breakdown komponen pada 10 MB (MB/s, makin besar makin cepat):")
    for name, mbps in breakdown.items():
        print(f"    {name:<34}: {mbps:>8.1f} MB/s")
    print("    -> DES & RC4 perlu 2 lintasan tambahan (HMAC + SHA-256) di atas cipher-nya;")
    print("       AES-GCM sudah menghasilkan tag integritas dalam satu lintasan.")

    # e. Overhead penyimpanan
    print("\n[e] Overhead penyimpanan per file:")
    for c in CIPHERS:
        r = get[(c, largest)]
        print(f"    {CIPHER_LABEL[c]:<14}: file .enc +{r['ciphertext_overhead_bytes']} B, "
              f"metadata DB {r['metadata_bytes']} B")

    # f. Deteksi manipulasi
    print("\n[f] Deteksi manipulasi (1 bit ciphertext dibalik):")
    for c in CIPHERS:
        ok, err = tamper[c]
        print(f"    {CIPHER_LABEL[c]:<14}: {'DITOLAK (benar)' if ok else 'TIDAK TERDETEKSI (masalah!)'}  [{err}]")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Benchmark cipher Nestiefy")
    parser.add_argument("--quick", action="store_true", help="mode cepat untuk uji skrip")
    args = parser.parse_args()
    sizes = SIZES_QUICK if args.quick else SIZES_FULL

    env = environment_info()
    print("Spesifikasi mesin:")
    for k, v in env.items():
        print(f"  {k:<13}: {v}")
    print("\nTutup aplikasi berat lain & colok charger laptop supaya hasil stabil.")

    results = []
    for label, size, reps in sizes:
        plaintext = os.urandom(size)
        print(f"\n[{label}] {reps} repetisi per cipher")
        for cipher in CIPHERS:
            print(f"  {CIPHER_LABEL[cipher]:<14} ...", end=" ", flush=True)
            row = benchmark_one(cipher, plaintext, reps)
            row["size_label"] = label
            results.append(row)
            print(f"enc {fmt_ms(row['enc_ms_median'])}, dec {fmt_ms(row['dec_ms_median'])}")

    print("\nMengukur komponen & deteksi manipulasi ...")
    breakdown = component_breakdown()
    tamper = {c: tamper_test(c) for c in CIPHERS}

    print_table(results)
    print_interpretation(results, sizes, tamper, breakdown)

    csv_path = BASE_DIR / "benchmark_results.csv"
    write_csv(results, csv_path)
    env_path = BASE_DIR / "benchmark_env.txt"
    env_path.write_text("\n".join(f"{k}: {v}" for k, v in env.items()) + "\n", encoding="utf-8")
    print(f"\n[OK] Hasil   : {csv_path.name}")
    print(f"[OK] Mesin   : {env_path.name}  (cantumkan di laporan)")


if __name__ == "__main__":
    main()