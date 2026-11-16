from app.core.images import sniff_image_mime


def test_sniff_image_mime_accepts_known_magic_bytes():
    assert sniff_image_mime(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8) == "image/png"
    assert sniff_image_mime(b"\xff\xd8\xff\xe0" + b"\x00" * 8) == "image/jpeg"
    assert sniff_image_mime(b"GIF89a" + b"\x00" * 8) == "image/gif"
    assert sniff_image_mime(b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 4) == "image/webp"


def test_sniff_image_mime_rejects_spoofed_files():
    assert sniff_image_mime(b"<html>not an image</html>") is None
    assert sniff_image_mime(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>") is None
    assert sniff_image_mime(b"") is None
