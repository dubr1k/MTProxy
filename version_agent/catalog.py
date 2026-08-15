from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_COMPONENTS = ("telemt", "naive", "mita")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_VERSION = re.compile(r"^[^\r\n]{1,160}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]*@sha256:[0-9a-f]{64}$")


class CatalogError(ValueError):
    """The trusted local catalog is malformed or contains an unsafe artifact."""


@dataclass(frozen=True)
class CatalogEntry:
    component: str
    version: str
    kind: str
    image: str | None = None
    url: str | None = None
    sha256: str | None = None
    runtime_version: str | None = None
    def public(self) -> dict[str, str]:
        result = {"version": self.version, "kind": self.kind}
        if self.image:
            result["image"] = self.image
        if self.url:
            # The URL is intentionally visible: it is an operator-approved source,
            # not a secret. The panel never accepts a URL from the browser.
            result["url"] = self.url
        if self.sha256:
            result["sha256"] = self.sha256
        return result


@dataclass(frozen=True)
class Catalog:
    components: dict[str, tuple[CatalogEntry, ...]]

    def entry(self, component: str, version: str) -> CatalogEntry:
        for item in self.components.get(component, ()):
            if item.version == version:
                return item
        raise CatalogError(f"version is not approved for {component}")


def _reject_unknown(mapping: dict, allowed: set[str], label: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise CatalogError(f"unknown {label} field: {sorted(unknown)[0]}")


def _entry(component: str, raw: object) -> CatalogEntry:
    if not isinstance(raw, dict):
        raise CatalogError(f"{component} catalog entry must be an object")
    _reject_unknown(raw, {"version", "kind", "image", "url", "sha256", "runtime_version"}, "catalog")
    version = raw.get("version")
    kind = raw.get("kind")
    if type(version) is not str or not _VERSION.fullmatch(version):
        raise CatalogError(f"invalid version for {component}")
    runtime_version = raw.get("runtime_version")
    if runtime_version is not None and (
        type(runtime_version) is not str or not _RUNTIME_VERSION.fullmatch(runtime_version)
    ):
        raise CatalogError(f"invalid runtime_version for {component}")
    if kind == "image":
        _reject_unknown(raw, {"version", "kind", "image", "runtime_version"}, "image")
        image = raw.get("image")
        if type(image) is not str or not _IMAGE.fullmatch(image):
            raise CatalogError("telemt image must use an immutable image digest")
        return CatalogEntry(component, version, kind, image=image, runtime_version=runtime_version)
    if kind == "binary":
        _reject_unknown(raw, {"version", "kind", "url", "sha256", "runtime_version"}, "binary")
        url = raw.get("url")
        digest = raw.get("sha256")
        parsed = urlsplit(url) if isinstance(url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise CatalogError("binary artifact URL must be HTTPS without credentials or query")
        if type(digest) is not str or not _SHA256.fullmatch(digest):
            raise CatalogError("binary artifact must have a lowercase SHA-256")
        return CatalogEntry(
            component, version, kind, url=url, sha256=digest, runtime_version=runtime_version
        )
    raise CatalogError(f"unsupported artifact kind for {component}")


def load_catalog(path: Path) -> Catalog:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError("version catalog unavailable") from exc
    if not isinstance(raw, dict):
        raise CatalogError("version catalog must be an object")
    _reject_unknown(raw, {"schema", "components"}, "catalog root")
    if raw.get("schema") != 1 or not isinstance(raw.get("components"), dict):
        raise CatalogError("unsupported version catalog schema")
    if set(raw["components"]) - set(_COMPONENTS):
        raise CatalogError("unknown version catalog component")
    result: dict[str, tuple[CatalogEntry, ...]] = {}
    for component in _COMPONENTS:
        values = raw["components"].get(component, [])
        if not isinstance(values, list):
            raise CatalogError(f"{component} catalog must be a list")
        entries = tuple(_entry(component, value) for value in values)
        versions = [item.version for item in entries]
        if len(set(versions)) != len(versions):
            raise CatalogError(f"duplicate {component} version")
        result[component] = entries
    return Catalog(result)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
