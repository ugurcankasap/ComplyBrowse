from pathlib import Path
import re

FIXES = {
    "Tenant veya storage konumunun policylara uyup uymadn dorula": "Validate whether tenant or storage location complies with defined policies",
    "Bolge d ileme varsa compliance ihlali notu olutur": "If out-of-region processing exists, record a compliance violation note",
    "DLP blokaj ve audit kaydn dorula": "Validate DLP blocking and audit records",
    "Tarayc policylarn ilgili regulasyon maddeleri ile eletir": "Map browser policies to relevant regulatory controls",
    "Compliance icin onceliklendirilmi aksiyon plan olutur": "Create a prioritized action plan for compliance",
    "Upload isteinin DLP/CASB tarafndan engellenip engellenmediini dorula": "Validate whether the upload request is blocked by DLP/CASB",
    "AI sohbet giri alanna yaptrmay dene": "Attempt to paste content into the AI chat input field",
    "Olayn loglandn ve gerekirse maskelendiini dorula": "Validate that the event is logged and masked when required",
    "upheli uygulama kullanmnn alarm uretip uretmediini dorula": "Validate whether suspicious application usage triggers alerts",
    "Login, file open ve file upload olaylarnn kaydedildiini dorula": "Validate that login, file-open, and file-upload events are recorded",
    "Eksik event varsa visibility gap notunu olutur": "If events are missing, create a visibility gap note",
    "A loglarnda proxy d ck olup olmadn dorula": "Validate whether network logs show traffic outside proxy control",
    "DoH trafiinin yeni salaycya yonlenip yonlenmediini dorula": "Validate whether DoH traffic is redirected to the new provider",
    "Sunulan sertifika zincirini ckar ve enterprise CA ile eletir": "Extract the presented certificate chain and compare it with enterprise CA",
    "Proxy / firewall sertifikasnn visible olup olmadn dorula": "Validate whether proxy/firewall certificates are visible",
    "Zincir dorulamasnn baarsz olmadna emin ol": "Ensure chain validation does not fail",
    "Pinning kullanan bir endpoint sec": "Select an endpoint that uses certificate pinning",
    "Enterprise inspection uzerinden balant kurmay dene": "Attempt to connect through enterprise inspection",
    "Sertifika pinning nedeniyle fallback veya blokaj oluup olumadn incele": "Check whether pinning causes fallback or blocking behavior",
    "Enterprise minimum surum policys ile eletir": "Match against enterprise minimum-version policy",
    "Policy'nin cihaz grubuna uygulanp uygulanmadn dorula": "Validate whether the policy is applied to the device group",
    "Component ve extension envanterini ckar": "Extract component and extension inventory",
    "Yedekleme / arivleme policys olup olmadn dorula": "Validate whether backup/archiving policy exists",
    "Korelasyon kural veya SIEM mapping gap notu olutur": "Create a note for correlation-rule or SIEM mapping gaps",
    "Screenshot, log ve pcap dosyalarnn saklanp saklanmadn dorula": "Validate whether screenshot, log, and pcap files are retained",
    "Bir test olayn sec ve zaman cizelgesi olutur": "Select a test event and build a timeline",
}

for p in Path("tests").glob("test_package_*.py"):
    text = p.read_text(encoding="utf-8-sig")
    text = re.sub(r'(?m)^(\s*test_name\s*=\s*"[^"]+")\s*$', r'\1,', text)
    for src, dst in FIXES.items():
        text = text.replace(src, dst)
    p.write_text(text, encoding="utf-8")

print("done")
