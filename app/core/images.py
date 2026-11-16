"""Image type detection for the no-JS upload path.

The browser controls Content-Type, so the bytes decide what a file is. SVG is not accepted.
"""

JPEG = b"\xff\xd8\xff"
PNG = b"\x89PNG\r\n\x1a\n"
GIF87 = b"GIF87a"
GIF89 = b"GIF89a"


def sniff_image_mime(data: bytes) -> str | None:
    """Return the image MIME type from the magic bytes, or None if it is not an image."""
    if data.startswith(PNG):
        return "image/png"
    if data.startswith(JPEG):
        return "image/jpeg"
    if data.startswith(GIF87) or data.startswith(GIF89):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None
