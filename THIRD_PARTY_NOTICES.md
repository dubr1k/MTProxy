# Third-party notices

Proxy Control repository code is distributed under the repository [MIT license](LICENSE). External software keeps its own license; this file is a boundary summary, not a replacement for upstream license texts.

- **lingeniare/MTProxy:** historical upstream repository and provenance for legacy installer material. Confirm the applicable upstream notices when redistributing derived artifacts.
- **TelegramMessenger/MTProxy:** legacy official MTProxy runtime referenced by historical/systemd paths; separately licensed upstream.
- **Telemt:** external MTProto runtime/container with its own public license and release artifacts. The repository pins the selected image and does not relicense it.
- **Mieru/mita:** GPLv3+ external runtime. The `mita` binary is downloaded or mounted separately and is not bundled into this MIT repository or its images. The adapter communicates across a process/Unix-socket boundary and does not include copied upstream source or generated GPL stubs.
- **Caddy and external modules/images:** separately licensed upstream components. The CI validation build imports `github.com/caddyserver/forwardproxy@caddy2` from the `github.com/klzgrad/forwardproxy` fork at immutable commit `d62c80d3dd2c706b6b87579844d2397bddd18317` into Caddy v2.11.4; review the exact build checker, image manifests, and upstream notices before redistribution.
- **Python dependencies:** FastAPI, Starlette, Pydantic, HTTPX, Uvicorn, Argon2, cryptography, qrcode, pytest, Ruff and their transitive dependencies remain under their respective upstream licenses. Exact direct pins are listed in `panel/requirements*.txt`.

Dependency pins and URLs in tracked configuration are not an assertion that all transitive license obligations are reproduced here. Release engineering must inspect the actual resolved artifacts and include notices required by those versions.
