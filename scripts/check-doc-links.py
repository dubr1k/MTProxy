#!/usr/bin/env python3
"""Validate repository-local Markdown link targets."""

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")
errors: list[str] = []

for document in sorted(ROOT.rglob("*.md")):
    if any(part in document.parts for part in (".git", ".venv")):
        continue
    for raw in LINK.findall(document.read_text(encoding="utf-8")):
        target = raw.strip().split(maxsplit=1)[0].strip("<>")
        parsed = urlsplit(target)
        if (
            parsed.scheme in {"http", "https", "mailto"}
            or target.startswith("#")
            or not parsed.path
        ):
            continue
        resolved = (document.parent / unquote(parsed.path)).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            errors.append(
                f"{document.relative_to(ROOT)}: link escapes repository: {target}"
            )
            continue
        if not resolved.exists():
            errors.append(
                f"{document.relative_to(ROOT)}: missing link target: {target}"
            )

if errors:
    raise SystemExit("\n".join(errors))
print("Markdown relative links: OK")
