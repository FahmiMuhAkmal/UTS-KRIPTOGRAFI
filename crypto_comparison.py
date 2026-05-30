"""
SOAL NO URUT 16-SELESAI (GENAP)
Perbandingan Kriptografi Simetris (AES/Fernet) vs Asimetris (RSA)
"""

import time
import base64
from cryptography.fernet import Fernet  # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import hashes, serialization

# ─────────────────────────────────────────────
# BAGIAN 1: SYMMETRIC CRYPTOGRAPHY (AES/Fernet)
# ─────────────────────────────────────────────

print("=" * 60)
print("       KRIPTOGRAFI SIMETRIS vs ASIMETRIS")
print("=" * 60)

# --- Generate Fernet (AES-128 CBC) key ---
fernet_key = Fernet.generate_key()
fernet_cipher = Fernet(fernet_key)

plaintext = b"Halo, ini adalah pesan rahasia untuk pengujian kriptografi!"

# Encrypt (Symmetric)
t0 = time.perf_counter()
sym_ciphertext = fernet_cipher.encrypt(plaintext)
sym_enc_time = (time.perf_counter() - t0) * 1000

# Decrypt (Symmetric)
t0 = time.perf_counter()
sym_decrypted = fernet_cipher.decrypt(sym_ciphertext)
sym_dec_time = (time.perf_counter() - t0) * 1000

print("\n[SIMETRIS - AES/Fernet]")
print(f"  Plaintext       : {plaintext.decode()}")
print(f"  Kunci           : {fernet_key.decode()[:40]}...")
print(f"  Ciphertext      : {sym_ciphertext.decode()[:60]}...")
print(f"  Hasil Dekripsi  : {sym_decrypted.decode()}")
print(f"  Waktu Enkripsi  : {sym_enc_time:.4f} ms")
print(f"  Waktu Dekripsi  : {sym_dec_time:.4f} ms")
print(f"  Ukuran Ciphertext: {len(sym_ciphertext)} bytes")

# ─────────────────────────────────────────────
# BAGIAN 2: ASYMMETRIC CRYPTOGRAPHY (RSA)
# ─────────────────────────────────────────────

# Generate RSA key pair (2048-bit)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Encrypt (Asymmetric) — RSA/OAEP hanya bisa enkripsi data kecil
t0 = time.perf_counter()
asym_ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
asym_enc_time = (time.perf_counter() - t0) * 1000

# Decrypt (Asymmetric)
t0 = time.perf_counter()
asym_decrypted = private_key.decrypt(
    asym_ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
asym_dec_time = (time.perf_counter() - t0) * 1000

# Serialize keys for display
pub_pem = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n[ASIMETRIS - RSA 2048-bit]")
print(f"  Plaintext         : {plaintext.decode()}")
print(f"  Public Key (awal) : {pub_pem.decode().splitlines()[1][:40]}...")
print(f"  Ciphertext (hex)  : {asym_ciphertext.hex()[:60]}...")
print(f"  Hasil Dekripsi    : {asym_decrypted.decode()}")
print(f"  Waktu Enkripsi    : {asym_enc_time:.4f} ms")
print(f"  Waktu Dekripsi    : {asym_dec_time:.4f} ms")
print(f"  Ukuran Ciphertext : {len(asym_ciphertext)} bytes")

# ─────────────────────────────────────────────
# BAGIAN 3: TABEL PERBANDINGAN
# ─────────────────────────────────────────────

print("\n" + "=" * 60)
print("              TABEL PERBANDINGAN")
print("=" * 60)
print(f"{'Kriteria':<28} {'Simetris (Fernet)':<20} {'Asimetris (RSA)'}")
print("-" * 60)

rows = [
    ("Algoritma",            "AES-128 (Fernet)",    "RSA 2048-bit"),
    ("Jumlah Kunci",         "1 kunci (shared)",    "2 kunci (pub/priv)"),
    (f"Waktu Enkripsi",      f"{sym_enc_time:.4f} ms", f"{asym_enc_time:.4f} ms"),
    (f"Waktu Dekripsi",      f"{sym_dec_time:.4f} ms", f"{asym_dec_time:.4f} ms"),
    ("Ukuran Ciphertext",    f"{len(sym_ciphertext)} bytes", f"{len(asym_ciphertext)} bytes"),
    ("Ukuran Kunci",         "256-bit (32 bytes)",  "2048-bit"),
    ("Keamanan Distribusi",  "Rentan (1 kunci)",    "Aman (kunci publik)"),
    ("Tingkat Keamanan",     "Tinggi (bulk data)",  "Sangat Tinggi"),
    ("Cocok Untuk",          "Data besar/streaming","Key exchange, tanda tangan"),
    ("Kecepatan",            "Sangat Cepat",        "Lambat (operasi besar)"),
]

for row in rows:
    print(f"{row[0]:<28} {row[1]:<20} {row[2]}")

print("=" * 60)
print("\nKesimpulan:")
print("  - Simetris (AES/Fernet) jauh lebih cepat, cocok untuk")
print("    enkripsi data bervolume besar.")
print("  - Asimetris (RSA) lebih aman dalam distribusi kunci,")
print("    ideal untuk pertukaran kunci & autentikasi.")
print("  - Praktik terbaik: gabungkan keduanya (hybrid encryption).")
print("=" * 60)
