import zipfile

from tgviewer import dlp, links
from tgviewer.feeds import store
from tgviewer.urls import extract, host_candidates, normalize


def test_extract_trims_punctuation():
    found = [u for _, _, u in extract("See https://example.com/a. And (www.test.org/x), ok")]
    assert found == ["https://example.com/a", "www.test.org/x"]
    assert [u for _, _, u in extract("wiki https://en.wikipedia.org/wiki/Foo_(bar)!")] == [
        "https://en.wikipedia.org/wiki/Foo_(bar)"]


def test_normalize():
    assert normalize("HTTPS://Example.COM:443") == "https://example.com/"
    assert normalize("www.example.com/x?y=1#frag") == "http://www.example.com/x?y=1"
    assert normalize("javascript:alert(1)") is None
    assert normalize("http://exa mple.com") is None
    assert normalize("https://пример.рф/").startswith("https://xn--")


def test_host_candidates():
    assert host_candidates("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]


def test_link_verdicts():
    store.bad_hosts = frozenset({"evil.example"})
    store.tranco = {"google.com": 1}
    assert links.local_verdict("https://login.evil.example/")[0] == "malicious"
    assert links.local_verdict("https://mail.google.com/")[0] == "clean"
    assert links.local_verdict("http://192.168.1.5/x")[0] == "suspicious"
    assert links.local_verdict("https://xn--80ak6aa92e.com/")[0] == "suspicious"
    assert links.local_verdict("https://bit.ly/abc")[0] == "unknown"
    assert links.local_verdict("https://random-unknown-site.net/")[0] == "unknown"
    assert links.local_verdict("https://google.com/", raw="https://google.com@evil2.net/")[0] == "suspicious"


def test_dlp_rules():
    assert dlp.scan_text("-----BEGIN RSA PRIVATE KEY-----\nabc").action == "block"
    fake_aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"  # split so secret scanners don't flag this test
    assert dlp.scan_text(f"key {fake_aws_key} here").action == "block"
    assert dlp.scan_text("card 4111 1111 1111 1111").action == "warn"
    assert dlp.scan_text("card 4111 1111 1111 1112").action == "allow"  # fails Luhn
    assert dlp.scan_text("Документ: конфіденційно").action == "warn"
    assert dlp.scan_text("hello world").action == "allow"


def test_dlp_docx_label(tmp_path):
    p = tmp_path / "d.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("word/document.xml", "<w:document><w:t>Quarterly plan</w:t></w:document>")
        z.writestr("docProps/custom.xml",
                   '<Properties><property name="MSIP_Label_1234-abcd_Name" fmtid="x" pid="2">'
                   "<vt:lpwstr>Highly Confidential</vt:lpwstr></property></Properties>")
    r = dlp.scan(p, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "d.docx")
    assert r.action == "block" and "Highly Confidential" in r.findings[0]
