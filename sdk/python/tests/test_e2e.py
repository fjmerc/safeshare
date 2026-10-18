"""
End-to-end encryption tests: interop vectors generated from the web app's
crypto.js (sdk/testdata/e2e-vectors.json, see tests/js/e2e-vectors.test.js),
plus upload/download round trips against a mocked server.
"""

import json
from pathlib import Path

import httpx
import pytest
from pytest_httpx import HTTPXMock

from safeshare import SafeShareClient, e2e
from safeshare.e2e import (
    ClientEncryptionRequiredError,
    DecryptionError,
    InvalidPayloadError,
    MetadataNotRemovedError,
    PayloadTooLargeError,
)
from safeshare.exceptions import DownloadError, ValidationError

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "testdata" / "e2e-vectors.json").read_text())
KEY = e2e.decode_key(VECTORS["key"])
IV = bytes.fromhex(VECTORS["iv"])
BASE = "https://share.example.com"


class TestVectorsFromWebApp:
    def test_constants(self):
        assert VECTORS["constants"] == {"pad_min_bytes": e2e.PAD_MIN_BYTES, "ciphertext_overhead": e2e.CIPHERTEXT_OVERHEAD}

    @pytest.mark.parametrize("case", VECTORS["padme"], ids=lambda c: str(c["n"]))
    def test_padme(self, case):
        assert e2e.padme_length(case["n"]) == case["padded"]

    @pytest.mark.parametrize("case", VECTORS["padded_length"], ids=lambda c: f'{c["n"]}-{c["max_stored"]}')
    def test_padded_length(self, case):
        if "error" in case:
            with pytest.raises(PayloadTooLargeError):
                e2e.padded_payload_length(case["n"], case["max_stored"])
        else:
            assert e2e.padded_payload_length(case["n"], case["max_stored"]) == case["padded"]

    @pytest.mark.parametrize("case", VECTORS["wrap"], ids=lambda c: c["id"])
    def test_wrap(self, case):
        data = bytes.fromhex(case["data"])
        pad = case["format"] == "SF02"
        if "error" in case:
            with pytest.raises(PayloadTooLargeError):
                e2e.wrap_payload(case["name"], data, pad, case.get("max_stored", 0))
            return
        assert e2e.wrap_payload(case["name"], data, pad, case.get("max_stored", 0)).hex() == case["payload"]

    @pytest.mark.parametrize("case", VECTORS["unwrap"], ids=lambda c: c["id"])
    def test_unwrap(self, case):
        payload = bytes.fromhex(case["payload"])
        if case.get("error"):
            with pytest.raises(InvalidPayloadError):
                e2e.unwrap_payload(payload)
            return
        got = e2e.unwrap_payload(payload)
        assert (got.filename, got.data.hex(), got.version) == (case["filename"], case["data"], case["version"])

    @pytest.mark.parametrize("case", VECTORS["encrypt"], ids=lambda c: c["id"])
    def test_encrypt_and_decrypt(self, case):
        payload = bytes.fromhex(case["payload"])
        assert e2e.encrypt_blob(KEY, payload, IV).hex() == case["blob"]
        assert e2e.decrypt_blob(KEY, bytes.fromhex(case["blob"])) == payload

    @pytest.mark.parametrize("case", VECTORS["decrypt_fails"], ids=lambda c: c["id"])
    def test_decrypt_fails(self, case):
        with pytest.raises(DecryptionError):
            e2e.decrypt_blob(KEY, bytes.fromhex(case["blob"]))

    @pytest.mark.parametrize("case", VECTORS["share_url"], ids=lambda c: c["base"])
    def test_share_url(self, case):
        assert e2e.build_share_url(case["base"], case["claim_code"], case["key"]) == case["url"]
        link = e2e.parse_share_url(case["url"])
        assert (link.claim_code, link.key) == (case["claim_code"], case["key"])
        assert e2e.build_share_url(link.base_url, link.claim_code, link.key) == case["url"]


def test_padme_dense_reference():
    def ref(n):
        if n < 2:
            return n
        e = n.bit_length() - 1
        z = e - e.bit_length()
        if z <= 0:
            return n
        u = 1 << z
        return -(-n // u) * u

    for n in range(0, 70000):
        assert e2e.padme_length(n) == ref(n)


@pytest.mark.parametrize(
    "link",
    [
        "",
        "ftp://h.example/#/claim/abcdefgh/key/" + VECTORS["key"],
        "https://h.example/#/claim/abcdefgh",
        "https://h.example/#/claim/abc/key/" + VECTORS["key"],
        "https://h.example/#/claim/abcdefgh/key/short",
        "https://h.example/#/claim/abcdefgh/key/" + VECTORS["key"] + "AA",
        "https:///#/claim/abcdefgh/key/" + VECTORS["key"],
    ],
)
def test_parse_share_url_rejects(link):
    with pytest.raises(ValidationError):
        e2e.parse_share_url(link)


def test_parse_share_url_drops_userinfo_and_query():
    link = e2e.parse_share_url("https://share.example.com@evil.example:8443/p/?x=1#/claim/abcdefgh/key/" + VECTORS["key"])
    assert link.base_url == "https://evil.example:8443/p"


@pytest.mark.parametrize(
    "name,want",
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("..\\..\\boot.ini", "boot.ini"),
        ("..", "fallback"),
        ("", "fallback"),
        (".bash_profile", "bash_profile"),
        ("CON", "_CON"),
        ("nul.txt", "_nul.txt"),
        ("a.txt:evil", "a.txt_evil"),
        ("trail. ", "trail"),
        ("invoice\u202etxt.exe", "invoicetxt.exe"),
        ("bell\x07\nname.txt", "bellname.txt"),
        ("naïve 日本語.txt", "naïve 日本語.txt"),
        ("é" * 200 + ".txt", "é" * 125 + ".txt"),
    ],
)
def test_safe_filename(name, want):
    assert e2e.safe_filename(name, "fallback") == want


def test_metadata_file_type():
    assert e2e.metadata_file_type(b"\xff\xd8\xff\xe0..") == "JPEG image"
    assert e2e.metadata_file_type(b"\x89PNG\r\n\x1a\n..") == "PNG image"
    assert e2e.metadata_file_type(b"PK\x03\x04...[Content_Types].XML") == "Office document"
    assert e2e.metadata_file_type(b"PK\x03\x04 plain zip") is None
    assert e2e.metadata_file_type(b" " * 5000 + b"%PDF-1.7") == "PDF"
    assert e2e.metadata_file_type(b"hello") is None


def test_unwrap_download_matches_web_app():
    sf02 = e2e.wrap_payload("inner.txt", b"body")
    sf01 = e2e.wrap_payload("inner.txt", b"body", pad=False)
    bad = sf02[:-1] + b"\x01"
    assert e2e.unwrap_download(sf02, "encrypted.bin") == e2e.DecryptedFile("inner.txt", b"body")
    assert e2e.unwrap_download(sf01, "encrypted.bin") == e2e.DecryptedFile("inner.txt", b"body")
    with pytest.raises(InvalidPayloadError):
        e2e.unwrap_download(bad, "encrypted.bin")
    assert e2e.unwrap_download(sf02, "visible.txt") == e2e.DecryptedFile("visible.txt", b"body")
    assert e2e.unwrap_download(bad, "visible.txt") == e2e.DecryptedFile("visible.txt", bad)
    assert e2e.unwrap_download(sf01, "visible.txt") == e2e.DecryptedFile("visible.txt", sf01)


# ---- client round trips ----

GHOST = {
    "version": "1.16.0",
    "max_file_size": 1 << 20,
    "max_expiration_hours": 168,
    "chunked_upload_enabled": True,
    "chunked_upload_threshold": 1 << 20,
    "chunk_size": 1 << 20,
    "require_auth_for_upload": False,
    "anonymous_mode": True,
    "client_encryption_required": True,
    "strip_metadata": True,
}
PLAIN = {**GHOST, "anonymous_mode": False, "client_encryption_required": False, "strip_metadata": False}


class FakeServer:
    """Stores what is uploaded and serves it back."""

    def __init__(self, httpx_mock: HTTPXMock, config: dict):
        self.stored = b""
        self.name = ""
        self.requests = []
        httpx_mock.add_callback(self._handle, is_reusable=True, is_optional=True)
        self.config = config

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api/config":
            return httpx.Response(200, json=self.config)
        if path == "/api/upload":
            body = request.read()
            boundary = request.headers["content-type"].split("boundary=")[1].encode()
            for part in body.split(b"--" + boundary):
                if b'name="file"' in part:
                    head, _, content = part.partition(b"\r\n\r\n")
                    self.stored = content[:-2]
                    self.name = head.split(b'filename="')[1].split(b'"')[0].decode()
            return httpx.Response(200, json={
                "claim_code": "Claim1234", "download_url": f"{BASE}/api/claim/Claim1234",
                "file_size": len(self.stored), "original_filename": self.name,
            })
        if path == "/api/claim/Claim1234/info":
            return httpx.Response(200, json={
                "claim_code": "Claim1234", "original_filename": self.name, "file_size": len(self.stored),
                "created_at": "2026-10-18T10:00:00Z", "client_encrypted": True,
            })
        if path == "/api/claim/Claim1234":
            return httpx.Response(200, content=self.stored)
        return httpx.Response(404, json={"error": "not found"})


@pytest.fixture
def ghost(httpx_mock):
    return FakeServer(httpx_mock, GHOST)


def test_ghost_upload_is_encrypted_padded_and_round_trips(ghost, tmp_path):
    src = tmp_path / "notes.txt"
    src.write_bytes(b"secret notes")
    with SafeShareClient(BASE) as c:
        res = c.upload(src)
        assert res.encrypted and res.original_filename == "notes.txt"
        assert res.share_url == e2e.build_share_url(BASE, "Claim1234", res.encryption_key)
        assert "encryption_key" not in res.model_dump() and "share_url" not in res.model_dump_json()
        assert ghost.name == "encrypted.bin"
        assert b"secret notes" not in ghost.stored and b"notes.txt" not in ghost.stored
        assert len(ghost.stored) == e2e.PAD_MIN_BYTES + e2e.CIPHERTEXT_OVERHEAD
        upload_req = [r for r in ghost.requests if r.url.path == "/api/upload"][0]
        assert upload_req.headers["x-safeshare-client-encrypted"] == "true"
        assert b'name="client_encrypted"\r\n\r\ntrue' in upload_req.content

        f = c.download_decrypted("Claim1234", res.encryption_key)
        assert (f.filename, f.data) == ("notes.txt", b"secret notes")

        dest = tmp_path / "out.txt"
        c.download("Claim1234", dest, decryption_key=res.encryption_key, overwrite=False)
        assert dest.read_bytes() == b"secret notes" and (dest.stat().st_mode & 0o777) == 0o600
        before = len(ghost.requests)
        with pytest.raises(DownloadError):
            c.download("Claim1234", dest, decryption_key=res.encryption_key, overwrite=False)
        assert len(ghost.requests) == before, "checked the destination only after downloading"

        with pytest.raises(DecryptionError):
            c.download_decrypted("Claim1234", e2e.generate_key())


def test_ghost_refuses_metadata_files(ghost, tmp_path):
    jpg = tmp_path / "photo.jpg"
    jpg.write_bytes(b"\xff\xd8\xff\xe1Exif")
    with SafeShareClient(BASE) as c:
        with pytest.raises(MetadataNotRemovedError):
            c.upload(jpg)
        assert not ghost.stored
        res = c.upload(jpg, keep_metadata=True)
        assert res.metadata_kept == "JPEG image"


def test_never_on_required_server(ghost, tmp_path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"x")
    with SafeShareClient(BASE) as c:
        with pytest.raises(ClientEncryptionRequiredError):
            c.upload(src, encrypt="never")


def test_plain_server_auto_unencrypted_always_encrypts(httpx_mock, tmp_path):
    srv = FakeServer(httpx_mock, PLAIN)
    src = tmp_path / "a.txt"
    src.write_bytes(b"do not reveal")
    with SafeShareClient(BASE) as c:
        res = c.upload(src)
        assert not res.encrypted and srv.stored == b"do not reveal"
        res = c.upload(src, encrypt="always", show_filename=True)
        assert res.encrypted and srv.name == "a.txt" and b"do not reveal" not in srv.stored
        assert len(srv.stored) == e2e.PAD_MIN_BYTES + e2e.CIPHERTEXT_OVERHEAD


def test_download_refuses_huge_reported_size(httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/api/claim/Claim1234/info", json={
        "claim_code": "Claim1234", "original_filename": "encrypted.bin", "file_size": 1 << 62,
        "created_at": "2026-10-18T10:00:00Z",
    })
    with SafeShareClient(BASE) as c:
        with pytest.raises(DownloadError):
            c.download_decrypted("Claim1234", e2e.generate_key())


def test_get_config_accepts_current_server_response(httpx_mock):
    httpx_mock.add_response(url=f"{BASE}/api/config", json=GHOST)
    with SafeShareClient(BASE) as c:
        cfg = c.get_config()
        assert cfg.anonymous_mode and cfg.client_encryption_required and cfg.default_expiration_hours is None


def test_proxy_options(monkeypatch):
    from safeshare.client import _proxy_options

    for n in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(n, raising=False)
    assert _proxy_options(None, False) == {}
    assert _proxy_options("socks5h://127.0.0.1:9050", False) == {"proxy": "socks5h://127.0.0.1:9050", "trust_env": False}
    monkeypatch.setenv("HTTPS_PROXY", "socks5://127.0.0.1:9050")
    assert _proxy_options(None, False) == {"proxy": "socks5://127.0.0.1:9050"}  # covers http:// too
    monkeypatch.setenv("HTTP_PROXY", "http://proxy:3128")
    assert _proxy_options(None, False) == {}
    assert _proxy_options(None, True) == {"trust_env": False}
    with pytest.raises(ValidationError):
        _proxy_options("ftp://x", False)


@pytest.mark.parametrize("scheme", ["socks5", "socks5h"])
def test_socks_proxy_gets_unresolved_hostname(scheme, monkeypatch):
    """Requests go through the SOCKS proxy with the host name unresolved,
    so a Tor user's DNS doesn't leak (and .onion names work)."""
    import socket
    import struct
    import threading

    for n in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(n, raising=False)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(10)
    seen = {}

    def serve():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        with conn:
            ver, nmethods = conn.recv(2)
            conn.recv(nmethods)
            conn.sendall(b"\x05\x00")
            head = conn.recv(4)
            seen["atyp"] = head[3]
            if head[3] == 3:
                (n,) = conn.recv(1)
                seen["host"] = conn.recv(n).decode()
                (seen["port"],) = struct.unpack(">H", conn.recv(2))
            conn.sendall(b"\x05\x01\x00\x01" + bytes(6))  # general failure

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    port = srv.getsockname()[1]
    with SafeShareClient("http://exampleonionaddressxyz.onion", proxy=f"{scheme}://127.0.0.1:{port}") as c:
        with pytest.raises(Exception):
            c.get_config()
    t.join(5)
    srv.close()
    assert seen == {"atyp": 3, "host": "exampleonionaddressxyz.onion", "port": 80}
