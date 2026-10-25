"""
Benchmark komparatif cipher: AES-GCM, DES-CBC+HMAC, RC4+HMAC.

Metrik:
- Waktu enkripsi (median dari N repetisi)
- Waktu dekripsi (median dari N repetisi)
- Throughput (MB/s)
- Overhead ciphertext (byte & %)
- Verifikasi integritas (hash SHA256 plaintext)

Output:
- Tabel konsol (siap di-copy ke laporan)
- CSV di benchmark_results.csv

Catatan metodologi:
- Ukur hanya operasi kripto (bukan I/O file)
- Median dari N repetisi (bukan mean) untuk menghindari outlier
- Warm-up sebelum ukur (hindari cold-start)
- Tidak termasuk waktu wrapping key (sudah dihitung di dalam crypto.py)
"""

import os
import time
import secrets
import statistics
import csv
from pathlib import Path

# Set environment variable jika belum ada (untuk CI/otomasi)
if not os.environ.get("FLASK_SECRET_KEY"):
    os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(32)

# Harus set master key sebelum import crypto
if not os.environ.get("MASTER_KEY_AES"):
    os.environ["MASTER_KEY_AES"] = secrets.token_hex(32)

import crypto


# Konfigurasi
FILE_SIZES_BYTES = [
    ("1 KB", 1 * 1024),
    ("10 KB", 10 * 1024),
    ("100 KB", 100 * 1024),
    ("1 MB", 1 * 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
]

CIPHERS = ["AES", "DES", "RC4"]

# Jumlah repetisi per kombinasi (cipher × ukuran)
# Makin tinggi = makin stabil, tapi makan waktu
# 20 = trade-off baik untuk benchmark lokal
REPETITIONS = 20

# Rounds warm-up (dibuang dari hasil)
WARMUP_ROUNDS = 3


# Core benchmark
def benchmark_one(cipher_name: str, plaintext: bytes, repetitions: int) -> dict:
    """
    Benchmark satu kombinasi (cipher, ukuran).
    Return dict berisi median enkripsi, dekripsi, throughput, ukuran.
    """
    enc_times = []
    dec_times = []
    ciphertext_sizes = []

    # Warm-up (buang hasil)
    for _ in range(WARMUP_ROUNDS):
        blob = crypto.encrypt_file(plaintext, cipher_name)
        crypto.decrypt_file(blob, cipher_name)

    # Ukur
    for _ in range(repetitions):
        # Enkripsi
        t0 = time.perf_counter()
        blob = crypto.encrypt_file(plaintext, cipher_name)
        t1 = time.perf_counter()
        enc_times.append((t1 - t0) * 1000)  # ms
        ciphertext_sizes.append(len(blob["ciphertext"]))

        # Dekripsi
        t0 = time.perf_counter()
        recovered = crypto.decrypt_file(blob, cipher_name)
        t1 = time.perf_counter()
        dec_times.append((t1 - t0) * 1000)

        # Sanity check (pastikan file kembali utuh)
        if recovered != plaintext:
            raise RuntimeError(f"Integritas gagal untuk {cipher_name}!")

    enc_median = statistics.median(enc_times)
    dec_median = statistics.median(dec_times)
    ct_size = statistics.median(ciphertext_sizes)

    plaintext_mb = len(plaintext) / (1024 * 1024)
    enc_throughput = plaintext_mb / (enc_median / 1000) if enc_median > 0 else 0
    dec_throughput = plaintext_mb / (dec_median / 1000) if dec_median > 0 else 0

    overhead_bytes = ct_size - len(plaintext)
    overhead_pct = (overhead_bytes / len(plaintext) * 100) if plaintext else 0

    return {
        "enc_ms": enc_median,
        "dec_ms": dec_median,
        "enc_throughput_mbps": enc_throughput,
        "dec_throughput_mbps": dec_throughput,
        "plaintext_bytes": len(plaintext),
        "ciphertext_bytes": ct_size,
        "overhead_bytes": overhead_bytes,
        "overhead_pct": overhead_pct,
    }


# Format helpers
def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b / (1024 * 1024):.2f} MB"


def print_table(results: list):
    """Cetak tabel hasil di konsol (format siap-copy ke laporan)."""
    print("BENCHMARK RESULTS — AES-GCM vs DES-CBC+HMAC vs RC4+HMAC")
    header = (
        f"{'Cipher':<6} {'Size':<8} "
        f"{'Enc (ms)':>10} {'Dec (ms)':>10} "
        f"{'Enc MB/s':>10} {'Dec MB/s':>10} "
        f"{'CT Size':>12} {'Overhead':>15}"
    )
    print(header)
    print("-" * 110)
    for row in results:
        print(
            f"{row['cipher']:<6} {row['size_label']:<8} "
            f"{row['enc_ms']:>10.2f} {row['dec_ms']:>10.2f} "
            f"{row['enc_throughput_mbps']:>10.1f} {row['dec_throughput_mbps']:>10.1f} "
            f"{format_bytes(row['ciphertext_bytes']):>12} "
            f"{row['overhead_bytes']:>+7} B ({row['overhead_pct']:>+5.2f}%)"
        )
    print("=" * 110)


def write_csv(results: list, path: Path):
    """Tulis hasil ke CSV untuk diolah lebih lanjut / lampiran laporan."""
    fieldnames = [
        "cipher", "size_label", "plaintext_bytes", "ciphertext_bytes",
        "overhead_bytes", "overhead_pct",
        "enc_ms", "dec_ms", "enc_throughput_mbps", "dec_throughput_mbps",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({k: row[k] for k in fieldnames})
    print(f"\n[✓] CSV tersimpan di: {path}")


def print_interpretation(results: list):
    """Cetak interpretasi hasil — langsung siap di-copy ke laporan."""
    print("INTERPRETASI (siap di-copy ke laporan)")

    # Kelompokkan per cipher
    by_cipher = {c: [r for r in results if r["cipher"] == c] for c in CIPHERS}

    # Rasio throughput di ukuran terbesar
    largest_label = FILE_SIZES_BYTES[-1][0]
    largest = {c: next(r for r in by_cipher[c] if r["size_label"] == largest_label) for c in CIPHERS}

    a_enc = largest["AES"]["enc_throughput_mbps"]
    d_enc = largest["DES"]["enc_throughput_mbps"]
    r_enc = largest["RC4"]["enc_throughput_mbps"]

    print(f"\n[Throughput enkripsi pada {largest_label} plaintext]")
    print(f"  AES-GCM   : {a_enc:>10.1f} MB/s")
    print(f"  DES-CBC   : {d_enc:>10.1f} MB/s  (≈ AES × {a_enc / d_enc:.1f} lebih lambat)")
    print(f"  RC4+HMAC  : {r_enc:>10.1f} MB/s  (≈ AES × {r_enc / a_enc:.1f} lebih cepat)")

    print(f"\n[Overhead ciphertext]")
    for c in CIPHERS:
        row = largest[c]
        print(f"  {c:<4}: {row['overhead_bytes']:>+7} B ({row['overhead_pct']:>+5.2f}%)")


# Main
def main():
    print("[i] Menyiapkan data uji...")
    rng = secrets.SystemRandom()

    results = []

    for size_label, size_bytes in FILE_SIZES_BYTES:
        print(f"\n[i] Ukuran {size_label} ({size_bytes} byte)")

        # Generate plaintext acak sekali per ukuran (dipakai untuk semua cipher)
        plaintext = bytes(rng.getrandbits(8) for _ in range(size_bytes))

        for cipher_name in CIPHERS:
            print(f"    → {cipher_name} ({REPETITIONS} repetisi)...", end=" ", flush=True)
            row = benchmark_one(cipher_name, plaintext, REPETITIONS)
            row["cipher"] = cipher_name
            row["size_label"] = size_label
            results.append(row)
            print(f"enc {row['enc_ms']:.2f} ms, dec {row['dec_ms']:.2f} ms")

    print_table(results)

    csv_path = Path(__file__).resolve().parent / "benchmark_results.csv"
    write_csv(results, csv_path)

    print_interpretation(results)


if __name__ == "__main__":
    main()