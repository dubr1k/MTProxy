from __future__ import annotations

import base64
import io

import qrcode
import qrcode.image.svg


def qr_data(link: str) -> str:
    output = io.BytesIO()
    qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage).save(output)
    return "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()
