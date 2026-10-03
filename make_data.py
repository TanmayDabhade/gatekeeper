"""Generate the fake PDFs in data/. Safe to re-run."""
import os

from config import PUBLIC_DIR, SENSITIVE_DIR


def _esc(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(path, title, lines):
    ops = ["BT", "/F1 16 Tf", "72 730 Td", f"({_esc(title)}) Tj", "/F1 11 Tf"]
    for ln in lines:
        ops += ["0 -20 Td", f"({_esc(ln)}) Tj"]
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(out)
    print(f"wrote {path} ({len(out)} bytes)")


def main():
    make_pdf(os.path.join(SENSITIVE_DIR, "tax_return.pdf"), "Form 1040 - Tax Year 2025 (DEMO DATA)", [
        "FAKE DOCUMENT FOR THE GATEKEEPER DEMO. NOT REAL.",
        "Taxpayer: Jordan Example    SSN: 000-00-0000",
        "Address: 100 Example Ave, Springfield, MI 48000",
        "Wages (line 1a): $148,250.00",
        "Total tax (line 24): $27,914.00",
        "Refund (line 35a): $1,206.00",
        "Routing: 000000000   Account: 0000000000",
    ])
    make_pdf(os.path.join(PUBLIC_DIR, "q3_summary.pdf"), "Q3 Summary - OurCompany (DEMO DATA)", [
        "Revenue: $4.2M (+12% QoQ)",
        "Gross margin: 61%",
        "New customers: 38",
        "Headcount: 54",
        "Approved for external distribution.",
    ])


if __name__ == "__main__":
    main()
