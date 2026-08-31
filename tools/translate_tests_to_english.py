from __future__ import annotations

from pathlib import Path
import re
import unicodedata


ROOT = Path(__file__).resolve().parents[1]
TEST_DIR = ROOT / "tests"


PHRASE_REPLACEMENTS = [
    ("Tarayıcı Güvenlik Test Çerçevesi", "Browser Security Test Framework"),
    ("Merkezi test utilities ve helper fonksiyonları", "Central test utilities and helper functions"),
    ("Test durumları", "Test statuses"),
    ("Yapılandırılmış kanıt öğesi", "Structured evidence item"),
    ("Test sırasında oluşan adım/zaman olayı", "Step/timeline event produced during test execution"),
    ("Ana testi destekleyen ikincil doğrulama sonucu", "Secondary validation result supporting the primary test"),
    ("Mevcut test sonucunun baseline ile karşılaştırma özeti", "Summary comparing the current test result with baseline"),
    ("Tek bir test sonucu", "Single test result"),
    ("Test paketi sonucu", "Test package result"),
    ("Tam güvenlik denetim raporu", "Complete security audit report"),
    ("Genel skoru hesapla", "Calculate overall score"),
    ("Risk özeti hesapla", "Calculate risk summary"),
    ("Test logging sistemi", "Test logging system"),
    ("Test sonucunu kaydet", "Log test result"),
    ("Sonuçları JSON olarak kaydet", "Save results as JSON"),
    ("Sonuçlar kaydedildi", "Results saved"),
    ("Test özeti", "Test summary"),
    ("Çözüm rehberi", "Remediation guide"),
    ("Test için çözüm rehberi yok", "No remediation guidance available for this test"),
    ("Security team ile iletişime geçiniz", "Contact the security team"),
    ("Risk hesaplayıcı", "Risk calculator"),
    ("Toplam risk skorunu hesapla (0-100)", "Calculate total risk score (0-100)"),
    ("Risk skorundan risk seviyesini belirle", "Determine risk level from risk score"),
    ("Policy bypass testleri", "Policy bypass tests"),
    ("Veri sızıntısı testleri", "Data exfiltration tests"),
    ("Ağ ve görünürlük testleri", "Network and visibility tests"),
    ("Extension güvenlik testleri", "Extension security tests"),
    ("Uyum ve veri egemenliği testleri", "Compliance and data sovereignty tests"),
    ("Yama ve sürüm hijyeni testleri", "Patch and version hygiene tests"),
    ("Tüm testleri çalıştır", "Run all tests"),
    ("testlerini çalıştır", "run tests"),
    ("Çalışıyor...", "Running..."),
    ("Özeti", "Summary"),
    ("Toplam Test", "Total Tests"),
    ("Başarılı", "Passed"),
    ("Başarısız", "Failed"),
    ("Uyarı", "Warning"),
    ("Cross-Border Upload Kontrolü", "Cross-Border Upload Control"),
    ("Compliance Politikası Hizalaması", "Compliance Policy Alignment"),
    ("InPrivate Mode Açabilirlik", "InPrivate Mode Accessibility"),
    ("Developer Tools Kısıtı", "Developer Tools Restriction"),
    ("Download Policy Uygulanması", "Download Policy Enforcement"),
    ("Password Manager Kontrolleri", "Password Manager Controls"),
    ("Extension Kurulumu (Herhangi bir Store Extension)", "Extension Installation (Any Store Extension)"),
    ("Kurumsal Dosya → Kişisel Mail (Gmail, Outlook.com)", "Enterprise File -> Personal Email (Gmail, Outlook.com)"),
    ("Kurumsal Dosya → Public AI Tools", "Enterprise File -> Public AI Tools"),
    ("Browser Sync: Şifre/Bookmark/History → Kişisel Hesap", "Browser Sync: Password/Bookmark/History -> Personal Account"),
    ("Unmanaged Browser ile M365 Erişimi", "M365 Access with Unmanaged Browser"),
    ("Conditional Access Politikaları Uygulanması", "Conditional Access Policy Enforcement"),
    ("Session Persistence Logout Sonrası", "Session Persistence After Logout"),
    ("Token Depolama Güvenliği", "Token Storage Security"),
    ("Work/Personal Profile Ayrımı", "Work/Personal Profile Separation"),
    ("Public AI Tool Dosya Yükleme", "Public AI Tool File Upload"),
    ("Prompt / Clipboard Sızıntısı", "Prompt / Clipboard Leakage"),
    ("Shadow SaaS Kullanımı", "Shadow SaaS Usage"),
    ("Cloud Discovery Görünürlüğü", "Cloud Discovery Visibility"),
    ("DoH / DNS Değişikliği", "DoH / DNS Modification"),
    ("Tarayıcı Sürüm Güncelliği", "Browser Version Currency"),
    ("Auto-Update Politikası", "Auto-Update Policy"),
    ("Component / Extension Sürüm Hijyeni", "Component / Extension Version Hygiene"),
    ("Log Retention Süresi", "Log Retention Duration"),
    ("Audit Trail Bütünlüğü", "Audit Trail Integrity"),
    ("Tarayc Security Test Paketi", "Browser Security Test Package"),
    ("Tarayc Security Test ercevesi", "Browser Security Test Framework"),
    ("Tum testleri caltr", "Run all tests"),
    ("testlerini caltr", "run tests"),
    ("Testleri alyor...", "Tests running..."),
    ("Kimlik ve oturum testleri", "Identity and session tests"),
    ("Yonetilmeyen taraycda M365 eriiminde ek restriction var m?", "Are additional restrictions enforced for M365 access from unmanaged browsers?"),
    ("Logout sonras cookie/session kalyor mu?", "Do cookies/sessions persist after logout?"),
    ("Compliance ve veri egemenlii testleri", "Compliance and data sovereignty tests"),
    ("A ve gorunurluk testleri", "Network and visibility tests"),
    ("Shadow AI ve SaaS testleri", "Shadow AI and SaaS tests"),
    ("Sertifika, proxy ve inspection testleri", "Certificate, proxy, and inspection tests"),
    ("Adli inceleme ve audit testleri", "Forensic analysis and audit tests"),
    ("Proxy bypass trafii detection et", "Detect proxy-bypass traffic"),
    ("Security team ile iletiime geciniz", "Contact the security team"),
    ("Enterprise files are uploaded to personal email", "Enterprise files can be uploaded to personal email"),
    ("Can enterprise files be uploaded to personal email services?", "Can enterprise files be uploaded to personal email services?"),
    ("Enterprise File to Public AI Tool", "Enterprise File to Public AI Tool"),
    ("SSL inspection zinciri calyor mu?", "Is the SSL inspection chain working?"),
    ("Hassas dosya snfn sec", "Select the sensitive file class"),
    ("Tarayc telemetrisi ve a loglarnda dosya ckn kontrol et", "Check browser telemetry and network logs for file egress"),
]


WORD_REPLACEMENTS = {
    "Kurumsal": "Enterprise",
    "kurumsal": "enterprise",
    "Kullanıcı": "User",
    "kullanıcı": "user",
    "kısıt": "restriction",
    "Kısıt": "Restriction",
    "uyum": "compliance",
    "Uyum": "Compliance",
    "güvenlik": "security",
    "Güvenlik": "Security",
    "doğrulama": "verification",
    "Doğrulama": "Verification",
    "şifre": "password",
    "Şifre": "Password",
    "açılabiliyor": "can be opened",
    "yüklenebiliyor": "can be uploaded",
    "yükleyebiliyor": "can install",
    "çalışıyor": "is running",
    "özelliği": "feature",
    "politikası": "policy",
    "politikaları": "policies",
    "politika": "policy",
    "tespit": "detection",
    "görünür": "visible",
    "görünürlüğü": "visibility",
    "başarılı": "passed",
    "başarısız": "failed",
    "policylar": "policies",
    "kiisel": "personal",
    "dosya": "file",
    "eriim": "access",
    "guncelleme": "update",
    "yukleme": "upload",
    "mumkun": "possible",
    "calyor": "running",
    "gercekten": "truly",
    "senkronize": "synchronized",
}


def repair_mojibake(text: str) -> str:
    if "Ã" not in text and "Å" not in text and "Ä" not in text:
        return text
    try:
        return text.encode("latin1", errors="ignore").decode("utf-8", errors="ignore")
    except Exception:
        return text


def ascii_fold(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", errors="ignore").decode("ascii")


def title_from_test_function(func_name: str) -> str:
    base = func_name.strip()
    if base.startswith("test_"):
        base = base[5:]
    base = re.sub(r"^p\d+_\d+_", "", base)
    base = base.replace("_", " ").strip()
    if not base:
        return "Control Validation"
    return " ".join(word.capitalize() for word in base.split())


def normalize_package_file(text: str) -> str:
    out = ascii_fold(repair_mojibake(text))
    lines = out.splitlines()
    normalized = []
    current_test_func = ""

    for line in lines:
        stripped = line.strip()
        indent = re.match(r"^\s*", line).group(0)

        m_def = re.match(r"^\s*def\s+(test_[a-zA-Z0-9_]+)\s*\(", line)
        if m_def:
            current_test_func = m_def.group(1)

        if re.search(r"\btest_name\s*=\s*\"", line):
            title = title_from_test_function(current_test_func)
            normalized.append(f'{indent}test_name = "{title}",')
            continue

        if re.search(r"\bmessage\s*=\s*\"", line):
            normalized.append(f'{indent}message="Control gap detected in this scenario.",')
            continue

        if re.search(r"\bremediation\s*=\s*\"", line):
            normalized.append(f'{indent}remediation="Apply enterprise policy controls and retest.",')
            continue

        if "print(f\"" in line and "Testleri" in line:
            normalized.append(f'{indent}print(f"{title_from_test_function(current_test_func)} tests running...")')
            continue

        if "print(f\"Package" in line and "Summary" in line:
            normalized.append(f'{indent}print(f"Package Summary:")')
            continue

        line = line.replace("Baarili", "Passed")
        line = line.replace("Baarisiz", "Failed")
        line = line.replace("Toplam Test", "Total Tests")
        line = line.replace("Uyari", "Warning")
        line = line.replace("Tum testleri calistir", "Run all tests")

        normalized.append(line)

    return "\n".join(normalized) + "\n"


def translate_text(text: str) -> str:
    out = repair_mojibake(text)
    for src, dst in PHRASE_REPLACEMENTS:
        out = out.replace(src, dst)

    for src, dst in WORD_REPLACEMENTS.items():
        out = re.sub(rf"\b{re.escape(src)}\b", dst, out)

    out = out.replace("✓", "[OK]")
    out = out.replace("→", "->")
    out = out.replace("“", '"').replace("”", '"')
    out = out.replace("’", "'")
    return out


def main() -> None:
    py_files = sorted(TEST_DIR.glob("*.py"))
    for file_path in py_files:
        original = file_path.read_text(encoding="utf-8")
        translated = translate_text(original)
        if file_path.name.startswith("test_package_"):
            translated = normalize_package_file(translated)
        elif file_path.name in {"test_framework.py", "__init__.py"}:
            translated = ascii_fold(repair_mojibake(translated))
        if translated != original:
            file_path.write_text(translated, encoding="utf-8")
            print(f"Updated: {file_path.name}")


if __name__ == "__main__":
    main()
