"""Image re-encoding: the browser only ever gets a freshly encoded copy,
which strips exploit payloads and metadata (EXIF, GPS)."""
import io
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError

from ..util import safe_name

Image.MAX_IMAGE_PIXELS = 40_000_000
REENCODABLE = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/x-ms-bmp", "image/tiff"}


def reencode(src: Path, dst_dir: Path, stem: str) -> tuple[Path, str] | None:
    try:
        with Image.open(src) as im:
            source_format = im.format
            im.load()
            im = ImageOps.exif_transpose(im)
            if source_format == "JPEG" and im.mode not in ("RGBA", "LA", "P"):
                im, fmt, ext, mime = im.convert("RGB"), "JPEG", ".jpg", "image/jpeg"
            else:
                im, fmt, ext, mime = im.convert("RGBA"), "PNG", ".png", "image/png"
            out = dst_dir / f"{safe_name(stem, 'image')}{ext}"
            im.save(out, fmt, **({"quality": 90} if fmt == "JPEG" else {"optimize": True}))
            return out, mime
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return None


def avatar_png(raw: bytes, size: int = 96) -> bytes | None:
    """Chat icon: decode, shrink and re-encode to PNG (no original bytes reach the browser)."""
    try:
        with Image.open(io.BytesIO(raw)) as im:
            im.load()
            im = ImageOps.exif_transpose(im).convert("RGB")
            im.thumbnail((size, size))
            out = io.BytesIO()
            im.save(out, "PNG", optimize=True)
            return out.getvalue()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return None
