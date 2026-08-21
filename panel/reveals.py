from __future__ import annotations

import base64
import io
import json
from urllib.parse import urlencode

import qrcode
import qrcode.image.svg


def qr_data(link: str) -> str:
    output = io.BytesIO()
    qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage).save(output)
    return "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()


def karing_client(config: dict, *, name: str, filename: str) -> dict:
    content = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    import_url = "karing://install-config?" + urlencode(
        {"url": content, "name": name}
    )
    return {
        "label": "Karing",
        "type": "link",
        "import_url": import_url,
        "config": config,
        "filename": filename,
        "qr": {"payload": import_url, "image": qr_data(import_url)},
    }
