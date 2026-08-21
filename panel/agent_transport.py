"""Direct mTLS ingress for outbound node agents and manual certificate issuance."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import ssl
import subprocess
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlsplit

from .fleet import CommandConflict, FleetStore, NODE_RE, ProtocolError, TypedCommand

AGENT_URI_PREFIX = "urn:mtproxy-panel:node:"
RESULT_RE = re.compile(r"^/agent/v1/nodes/([^/]+)/commands/([^/]+)/result$")
POLL_RE = re.compile(r"^/agent/v1/nodes/([^/]+)/commands/next$")


class CertificateAuthority:
    """Small OpenSSL-backed v1 offline CA workflow; private keys never leave their host."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.key_path = self.directory / "ca.key"
        self.cert_path = self.directory / "ca.crt"

    @staticmethod
    def _run(args: list[str]) -> str:
        return subprocess.run(args, check=True, text=True, capture_output=True).stdout

    def initialize(self, common_name: str, days: int = 3650) -> None:
        if self.key_path.exists() or self.cert_path.exists():
            raise FileExistsError("CA already exists")
        self.directory.mkdir(parents=True, mode=0o700)
        self._run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
                   "-days", str(days), "-subj", f"/CN={common_name}", "-keyout", str(self.key_path),
                   "-out", str(self.cert_path), "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                   "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        os.chmod(self.key_path, 0o600)
        os.chmod(self.cert_path, 0o644)

    def _issue(self, name: str, san: str, usage: str, days: int, output: Path | None = None):
        output = output or self.directory / name
        output.mkdir(parents=True, mode=0o700, exist_ok=True)
        key, csr, cert = output / f"{name}.key", output / f"{name}.csr", output / f"{name}.crt"
        if key.exists() or cert.exists():
            raise FileExistsError(f"certificate output for {name} already exists")
        self._run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256",
                   "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(csr), "-addext", f"subjectAltName={san}"])
        with tempfile.NamedTemporaryFile("w", delete=False) as ext:
            ext.write(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                      f"extendedKeyUsage={usage}\nsubjectAltName={san}\n")
            ext_path = ext.name
        try:
            self._run(["openssl", "x509", "-req", "-sha256", "-days", str(days), "-in", str(csr),
                       "-CA", str(self.cert_path), "-CAkey", str(self.key_path), "-CAcreateserial",
                       "-extfile", ext_path, "-out", str(cert)])
        finally:
            Path(ext_path).unlink(missing_ok=True)
            csr.unlink(missing_ok=True)
        os.chmod(key, 0o600)
        os.chmod(cert, 0o644)
        return key, cert, self.certificate_metadata(cert)

    def issue_node(self, node_id: str, days: int = 90, output: Path | None = None):
        if not NODE_RE.fullmatch(node_id):
            raise ProtocolError("node_id is invalid")
        return self._issue(node_id, f"URI:{AGENT_URI_PREFIX}{node_id}", "clientAuth", days, output)

    def sign_node_csr(self, node_id: str, csr: Path, cert: Path, days: int = 90) -> dict:
        """Sign a CSR whose private key was generated on the node; identity is CA-controlled."""
        if not NODE_RE.fullmatch(node_id):
            raise ProtocolError("node_id is invalid")
        self._run(["openssl", "req", "-in", str(csr), "-noout", "-verify"])
        cert.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if cert.exists():
            raise FileExistsError(cert)
        with tempfile.NamedTemporaryFile("w", delete=False) as ext:
            ext.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                      f"extendedKeyUsage=clientAuth\nsubjectAltName=URI:{AGENT_URI_PREFIX}{node_id}\n")
            ext_path = ext.name
        try:
            self._run(["openssl", "x509", "-req", "-sha256", "-days", str(days), "-in", str(csr),
                       "-CA", str(self.cert_path), "-CAkey", str(self.key_path), "-CAcreateserial",
                       "-extfile", ext_path, "-out", str(cert)])
        finally:
            Path(ext_path).unlink(missing_ok=True)
        os.chmod(cert, 0o644)
        return self.certificate_metadata(cert)

    def issue_server(self, common_name: str, names: list[str], days: int = 90, output: Path | None = None):
        sans = []
        for value in names:
            try:
                import ipaddress
                ipaddress.ip_address(value)
                sans.append(f"IP:{value}")
            except ValueError:
                sans.append(f"DNS:{value}")
        key, cert, _ = self._issue(common_name, ",".join(sans), "serverAuth", days, output)
        return key, cert

    @classmethod
    def certificate_metadata(cls, cert: Path) -> dict:
        pem = cert.read_text()
        der = ssl.PEM_cert_to_DER_cert(pem)
        decoded = ssl._ssl._test_decode_cert(str(cert))  # standard-library parser used by ssl itself
        serial = cls._run(["openssl", "x509", "-in", str(cert), "-noout", "-serial"]).strip().split("=", 1)[1]
        return {
            "serial": serial.upper(),
            "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
            "not_before": int(ssl.cert_time_to_seconds(decoded["notBefore"])),
            "not_after": int(ssl.cert_time_to_seconds(decoded["notAfter"])),
        }


class AgentTransportServer:
    def __init__(self, store: FleetStore, *, host: str, port: int, server_cert: Path, server_key: Path,
                 client_ca: Path, poll_seconds: float = 20, request_timeout: float = 10,
                 body_limit: int = 16_384, requests_per_minute: int = 120):
        self.store, self.host, self.port = store, host, port
        self.poll_seconds, self.request_timeout = min(poll_seconds, 30), request_timeout
        self.body_limit, self.requests_per_minute = min(body_limit, 65_536), requests_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(server_cert), str(server_key))
        context.load_verify_locations(cafile=str(client_ca))
        context.verify_mode = ssl.CERT_REQUIRED
        context.options |= ssl.OP_NO_COMPRESSION
        self.ssl_context = context
        self._server = None

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port, ssl=self.ssl_context,
                                                  ssl_handshake_timeout=self.request_timeout)
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    def _identity(self, writer) -> tuple[str, str, str] | None:
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert()
        der = ssl_object.getpeercert(binary_form=True)
        identities = [value[len(AGENT_URI_PREFIX):] for kind, value in cert.get("subjectAltName", ())
                      if kind == "URI" and value.startswith(AGENT_URI_PREFIX)]
        if len(identities) != 1 or not NODE_RE.fullmatch(identities[0]):
            return None
        return identities[0], cert.get("serialNumber", "").upper(), hashlib.sha256(der).hexdigest()

    def _rate_ok(self, node_id: str) -> bool:
        now = time.monotonic()
        window = self._requests[node_id]
        while window and window[0] < now - 60:
            window.popleft()
        if len(window) >= self.requests_per_minute:
            return False
        window.append(now)
        return True

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await asyncio.wait_for(self._request(reader, writer), self.request_timeout + self.poll_seconds)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        except Exception:
            await self._respond(writer, 500, {"detail": "internal error"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    async def _request(self, reader, writer):
        line = await reader.readline()
        if len(line) > 4096:
            return await self._respond(writer, 414, {"detail": "request target too long"})
        try:
            method, target, version = line.decode("ascii").rstrip("\r\n").split(" ")
        except ValueError:
            return await self._respond(writer, 400, {"detail": "bad request"})
        if version != "HTTP/1.1":
            return await self._respond(writer, 505, {"detail": "HTTP version unsupported"})
        headers = {}
        total = 0
        while True:
            raw = await reader.readline()
            total += len(raw)
            if total > 8192:
                return await self._respond(writer, 431, {"detail": "headers too large"})
            if raw == b"\r\n":
                break
            try:
                key, value = raw.decode("ascii").rstrip("\r\n").split(":", 1)
            except ValueError:
                return await self._respond(writer, 400, {"detail": "bad request"})
            headers[key.lower()] = value.strip()
        if "transfer-encoding" in headers:
            return await self._respond(writer, 400, {"detail": "transfer encoding unsupported"})
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            return await self._respond(writer, 400, {"detail": "invalid content length"})
        if length < 0 or length > self.body_limit:
            return await self._respond(writer, 413, {"detail": "request body too large"})
        body = await reader.readexactly(length) if length else b""
        path = urlsplit(target).path
        match = POLL_RE.fullmatch(path) if method == "GET" else RESULT_RE.fullmatch(path) if method == "PUT" else None
        if not match:
            return await self._respond(writer, 404, {"detail": "not found"})
        node_id = match.group(1)
        identity = self._identity(writer)
        if not identity:
            return await self._respond(writer, 403, {"detail": "certificate not authorized"})
        if not self._rate_ok(identity[0]):
            return await self._respond(writer, 429, {"detail": "rate limit exceeded"})
        authenticated = await asyncio.to_thread(
            self.store.authenticate_certificate,
            node_id,
            identity[1],
            identity[2],
            identity[0],
        )
        if not authenticated:
            return await self._respond(writer, 403, {"detail": "certificate not authorized"})
        if method == "GET":
            deadline = time.monotonic() + self.poll_seconds
            command = await asyncio.to_thread(self.store.poll_next, node_id)
            while command is None and time.monotonic() < deadline:
                await asyncio.sleep(min(0.1, self.poll_seconds))
                command = await asyncio.to_thread(self.store.poll_next, node_id)
            envelope = None if command is None else TypedCommand.parse({key: command[key] for key in (
                "protocol_version", "command_id", "node_id", "sequence", "idempotency_key", "operation",
                "expected_telemt_revision", "actor", "expires_at", "payload_sha256", "payload")}).as_dict()
            return await self._respond(writer, 200, {"command": envelope})
        if headers.get("content-type", "").split(";", 1)[0] != "application/json":
            return await self._respond(writer, 415, {"detail": "application/json required"})
        try:
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {"sequence", "status", "result"}:
                raise ValueError
            result = await asyncio.to_thread(
                self.store.record_result,
                node_id,
                match.group(2),
                value["sequence"],
                value["status"],
                value["result"],
            )
        except (ValueError, ProtocolError):
            return await self._respond(writer, 422, {"detail": "invalid result"})
        except KeyError:
            return await self._respond(writer, 404, {"detail": "command not found"})
        except CommandConflict:
            return await self._respond(writer, 409, {"detail": "result conflict"})
        return await self._respond(writer, 200, {"command_id": result["command_id"], "status": result["status"]})

    @staticmethod
    async def _respond(writer, status: int, value: dict):
        reason = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 409: "Conflict",
                  413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
                  422: "Unprocessable Entity", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
                  500: "Internal Server Error", 505: "HTTP Version Not Supported"}.get(status, "Error")
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                     "Cache-Control: no-store\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()
