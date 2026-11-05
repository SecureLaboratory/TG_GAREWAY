"""ZIP inspection with zip-bomb limits. Every member goes through the static
engines, so a blocked type can't hide inside an archive. ClamAV also scans
archives natively; this adds the type policy and document checks."""
import tempfile
import zipfile
from pathlib import Path

from . import filetype, office, pdf, yara_engine
from .result import RANK, EngineResult

MAX_MEMBERS = 500
MAX_TOTAL = 300 * 1024 * 1024
MAX_RATIO = 150
MAX_DEPTH = 3
OOXML_EXT = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam",
             ".pptx", ".pptm", ".ppsx", ".ppsm", ".potx", ".odt", ".ods", ".odp"}
OTHER_ARCHIVES = {"application/x-rar", "application/vnd.rar", "application/x-rar-compressed",
                  "application/x-7z-compressed", "application/x-tar", "application/gzip",
                  "application/x-bzip2", "application/x-xz", "application/x-lzh-compressed",
                  "application/x-cab", "application/vnd.ms-cab-compressed"}


def is_zip(path: Path, mime: str, name: str) -> bool:
    if Path(name).suffix.lower() in OOXML_EXT or "officedocument" in mime:
        return False
    return mime in ("application/zip", "application/x-zip-compressed") and zipfile.is_zipfile(path)


def _sus(detail: str) -> EngineResult:
    return EngineResult("archive", "suspicious", detail)


def scan_zip(path: Path, depth: int = 0) -> list[EngineResult]:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        return [_sus(f"corrupt zip ({e})")]
    out: list[EngineResult] = []
    with zf, tempfile.TemporaryDirectory(prefix="tgv-zip-") as tmp:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            return [_sus(f"too many files in archive ({len(infos)})")]
        if sum(i.file_size for i in infos) > MAX_TOTAL:
            return [_sus(f"archive expands to more than {MAX_TOTAL // 2**20} MB")]
        for i in infos:
            if i.file_size > 10 * 2**20 and i.compress_size and i.file_size / i.compress_size > MAX_RATIO:
                return [_sus("compression ratio looks like a zip bomb")]

        encrypted = False
        for idx, info in enumerate(infos):
            if info.flag_bits & 0x1:
                encrypted = True
                continue
            target = Path(tmp) / f"m{idx}{Path(info.filename).suffix[:16]}"
            try:
                _extract(zf, info, target)
            except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError) as e:
                out.append(_sus(f"{info.filename}: could not unpack ({e.__class__.__name__})"))
                continue
            for r in scan_member(target, info.filename, depth):
                if RANK.get(r.verdict, 1) > 0:
                    out.append(EngineResult(f"archive/{r.engine}", r.verdict, f"{info.filename}: {r.detail}"))
            target.unlink(missing_ok=True)
        if encrypted:
            out.append(_sus("password-protected archive: content can't be inspected"))
    out.insert(0, EngineResult("archive", "clean", f"{len(infos)} files inspected"))
    return out


def _extract(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> None:
    written = 0
    with zf.open(info) as src, open(target, "wb") as dst:
        while chunk := src.read(1 << 16):
            written += len(chunk)
            if written > info.file_size + 1024:
                raise ValueError("member larger than declared")
            dst.write(chunk)


def scan_member(path: Path, name: str, depth: int) -> list[EngineResult]:
    res, mime, _ = filetype.check(path, name)
    results = [res]
    if is_zip(path, mime, name):
        if depth + 1 < MAX_DEPTH:
            results += scan_zip(path, depth + 1)
        else:
            results.append(_sus("archives nested too deeply"))
    elif mime in OTHER_ARCHIVES:
        results.append(_sus(f"nested {mime} not unpacked"))
    results.append(yara_engine.scan(path, name))
    if office.applies(mime, Path(name).suffix.lower()):
        results.append(office.scan(path))
    if mime == "application/pdf":
        results.append(pdf.scan(path))
    return results
