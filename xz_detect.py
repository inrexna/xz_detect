import os
import subprocess
import sys
import time

try:
    import yara
except ImportError:
    print("[!] Modul 'yara' tidak ditemukan. Jalankan: pip install yara-python")
    sys.exit(1)

# ==========================================
# DEFINISI YARA RULES (Florian Roth)
# ==========================================
YARA_RULES = r"""
rule BKDR_XZUtil_Binary_CVE_2024_3094_Mar24_1 {
   meta:
      description = "Detects injected code used by the backdoored XZ library (xzutil) CVE-2024-3094."
   strings:
      $op1 = { 48 8d 7c 24 08 f3 ab 48 8d 44 24 08 48 89 d1 4c 89 c7 48 89 c2 e8 ?? ?? ?? ?? 89 c2 }
      $op2 = { 31 c0 49 89 ff b9 16 00 00 00 4d 89 c5 48 8d 7c 24 48 4d 89 ce f3 ab 48 8d 44 24 48 }
      $op3 = { 4d 8b 6c 24 08 45 8b 3c 24 4c 8b 63 10 89 85 78 f1 ff ff 31 c0 83 bd 78 f1 ff ff 00 f3 ab 79 07 }
      $xc1 = { F3 0F 1E FA 55 48 89 F5 4C 89 CE 53 89 FB 81 E7 00 00 00 80 48 83 EC 28 48 89 54 24 18 48 89 4C 24 10 }
   condition:
      uint16(0) == 0x457f and (all of ($op*) or $xc1)
}
"""

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True).strip()
    except Exception:
        return ""

def check_native_hex(file_path):
    if not os.path.exists(file_path):
        return False
    # Signature hex yang LEBIH PANJANG & SPESIFIK (Milik Backdoor XZ)
    malicious_bytes = b"\xf3\x0f\x1e\xfa\x55\x48\x89\xf5\x4c\x89\xce\x53\x89\xfb\x81\xe7\x00\x00\x00\x80\x48\x83\xec\x28\x48\x89\x54\x24\x18\x48\x89\x4c\x24\x10"
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            if malicious_bytes in content:
                return True
    except Exception:
        pass
    return False

def check_ssh_latency():
    start_time = time.time()
    # Tambahkan -o BatchMode=yes agar tidak tersangkut di prompt password
    run_cmd("ssh -o BatchMode=yes -o ConnectTimeout=1 -o StrictHostKeyChecking=no invalid_user@localhost 'exit' 2>/dev/null")
    elapsed = time.time() - start_time
    return elapsed

def main():
    print("\n" + "="*65)
    print(" XZ Backdoor Scanner (CVE-2024-3094)")
    print("="*65)

    threat_score = 0
    liblzma_target = ""

    # 1. VERSION CHECK
    print("\n[*] Tahap 1: Pengecekan Versi xz-utils")
    xz_version = run_cmd("xz --version | head -n 1")
    print(f"    -> Terdeteksi: {xz_version}")
    if "5.6.0" in xz_version or "5.6.1" in xz_version:
        print("    [!] Peringatan: Versi masuk dalam rentang rentan.")
        threat_score += 10
    else:
        print("    [+] Aman: Versi berada di luar rentang infeksi utama.")

    # 2. DEPENDENCY CHECK
    print("\n[*] Tahap 2: Analisis Dependensi SSHD (Runtime Linking)")
    ldd_out = run_cmd("ldd $(which sshd) | grep liblzma")
    if ldd_out:
        print(f"    [!] Terhubung: sshd memuat liblzma -> {ldd_out.strip()}")
        threat_score += 10
        liblzma_target = ldd_out.split("=>")[1].split()[0].strip() if "=>" in ldd_out else ldd_out.split()[0].strip()
    else:
        print("    [+] Aman: sshd tidak memuat liblzma secara langsung.")

    # Jika LDD gagal, gunakan path fallback untuk melanjutkan pengecekan
    if not liblzma_target:
        liblzma_target = "/lib/x86_64-linux-gnu/liblzma.so.5"
    
    # 3. NATIVE HEX SIGNATURE CHECK
    print(f"\n[*] Tahap 3: Pemindaian Byte Level pada {liblzma_target}")
    if os.path.exists(liblzma_target):
        is_infected = check_native_hex(liblzma_target)
        if is_infected:
            print("    [!] KRITIKAL: Ditemukan malicious byte signature (f3 0f 1e fa...)!")
            threat_score += 30
        else:
            print("    [+] Bersih: Tidak ditemukan pola byte backdoor.")
    else:
        print(f"    [-] File {liblzma_target} tidak ditemukan, melewati tahap ini.")

    # 4. YARA RULE MATCHING
    print("\n[*] Tahap 4: Pemindaian Instruksi Assembly via YARA")
    if os.path.exists(liblzma_target):
        rules = yara.compile(source=YARA_RULES)
        matches = rules.match(liblzma_target)
        if matches:
            print(f"    [!] KRITIKAL: YARA Rule '{matches[0].rule}' cocok!")
            threat_score += 40
        else:
            print("    [+] Bersih: Lolos evaluasi YARA.")

    # 5. BEHAVIORAL TIMING CHECK
    print("\n[*] Tahap 5: Analisis Behavioral (SSH Handshake Latency)")
    latency = check_ssh_latency()
    print(f"    -> Waktu respons: {latency:.3f} detik")
    if latency > 0.4:
        print("    [!] Anomali: Terjadi perlambatan mencurigakan pada proses SSH.")
        threat_score += 10
    else:
         print("    [+] Normal: Tidak ada overhead CPU yang tidak wajar.")

    # ==========================================
    # KESIMPULAN / VERDICT
    # ==========================================
    print("\n" + "="*65)
    print(f" TOTAL THREAT SCORE : {threat_score} / 100")
    
    if threat_score >= 80:
        print(" STATUS             : 🔴 SYSTEM COMPROMISED (VULNERABLE)")
        print(" TINDAKAN           : Isolasi jaringan segera dan lakukan forensik!")
    elif threat_score >= 20:
        print(" STATUS             : 🟡 SUSPICIOUS (BUT UH LIKELY PATCHED/SAFE)")
        print(" TINDAKAN           : Terdapat jejak dependensi/versi rentan, namun tidak ada malware aktif. Verifikasi manual disarankan.")
    else:
        print(" STATUS             : 🟢 CLEAN (SECURE)")
        print(" TINDAKAN           : Sistem aman dari CVE-2024-3094.")
    print("="*65 + "\n")

if __name__ == "__main__":
    main()
