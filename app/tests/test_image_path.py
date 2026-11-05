"""Image fast path (IMAGE_FAST_PATH) and photos-on-view (AUTO_SCAN_PHOTOS), against the real pipeline."""
import asyncio
from types import SimpleNamespace as NS

import pytest
from PIL import Image

from tgviewer import autoscan
from tgviewer.db import engine, init_db
from tgviewer.feeds import store
from tgviewer.scanning import clamav, pipeline


def _ready() -> bool:
    async def probe():
        try:
            await init_db(attempts=1)
            return await clamav.version() is not None
        except Exception:
            return False
        finally:
            await engine.dispose()
    return asyncio.run(probe())


def engines(res) -> dict:
    return {r["engine"]: r["verdict"] for r in res.results}


@pytest.mark.skipif(not _ready(), reason="needs postgres + clamav")
def test_fast_path_only_for_verified_inbound_pictures(tmp_path):
    photo = tmp_path / "photo.jpg"
    Image.new("RGB", (40, 40), (10, 200, 10)).save(photo)
    disguised = tmp_path / "holiday.jpg"
    disguised.write_bytes(b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 200)  # an .exe named .jpg
    svg = tmp_path / "logo.svg"
    svg.write_text('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')

    async def run():
        store.load_all()
        try:
            inbound = await pipeline.scan_file(photo, "photo.jpg", use_cache=False, will_reencode=True)
            outbound = await pipeline.scan_file(photo, "photo.jpg", use_cache=False, will_reencode=False)
            fake = await pipeline.scan_file(disguised, "holiday.jpg", use_cache=False, will_reencode=True)
            vector = await pipeline.scan_file(svg, "logo.svg", use_cache=False, will_reencode=True)
        finally:
            await engine.dispose()
        return inbound, outbound, fake, vector
    inbound, outbound, fake, vector = asyncio.run(run())

    # Real inbound picture: light path (type check + hash lookup), antivirus skipped.
    assert inbound.verdict == "clean"
    assert engines(inbound)["clamav"] == "skipped" and engines(inbound)["yara"] == "skipped"
    assert "type-policy" in engines(inbound) and "local-feeds" in engines(inbound)
    # Same picture going out (sent as the original file): full scan.
    assert engines(outbound)["clamav"] == "clean"
    # An executable named .jpg is not a picture: full scan, blocked.
    assert fake.verdict == "blocked" and engines(fake)["clamav"] != "skipped"
    # SVG can carry scripts: never the light path.
    assert engines(vector)["clamav"] != "skipped" and vector.verdict != "clean"


def test_photos_are_not_downloaded_on_arrival_by_default():
    mb = 2**20
    assert not autoscan.should_scan_file("private", 1 * mb, False, picture=True)[0]
    assert autoscan.should_scan_file("private", 1 * mb, False, picture=False)[0]  # documents still are
    photo_msg = NS(photo=True, sticker=None, file=NS(mime_type="image/jpeg"))
    doc_msg = NS(photo=None, sticker=None, file=NS(mime_type="application/pdf"))
    svg_msg = NS(photo=None, sticker=None, file=NS(mime_type="image/svg+xml"))
    assert autoscan.is_picture(photo_msg) and not autoscan.is_picture(doc_msg) and not autoscan.is_picture(svg_msg)
