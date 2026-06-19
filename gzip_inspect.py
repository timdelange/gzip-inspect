#!/usr/bin/env python3
"""
gzip_inspect.py — fetch an HTTP endpoint, capture the raw gzip bytes,
validate the header magic, attempt to decompress, and report on the
trailer (CRC32 + size) to diagnose malformed gzip responses.

Usage:
  gzip_inspect.py <url> [-H "Header: value"] [-o raw_response.gz]
"""
import sys
import gzip
import socket
import ssl
import argparse
from urllib.parse import urlparse


# gzip header: bytes 0-1 must be 0x1f 0x8b
GZIP_MAGIC = b"\x1f\x8b"
# gzip trailer: last 8 bytes = CRC32 (4) + ISIZE (4, raw mod-32 size)
TRAILER_LEN = 8


def parse_http_headers(header_block: bytes) -> dict[str, str]:
    """Parse an HTTP response header block into lowercase name -> value."""
    lines = header_block.decode("latin-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        val = value.strip()
        if key in headers:
            headers[key] += ", " + val
        else:
            headers[key] = val
    return headers


def is_chunked(headers: dict[str, str]) -> bool:
    te = headers.get("transfer-encoding", "")
    return "chunked" in (part.strip().lower() for part in te.split(","))


def decode_chunked(data: bytes) -> bytes:
    """Decode an HTTP/1.1 chunked transfer-encoded body."""
    pos = 0
    out = bytearray()
    while True:
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            raise RuntimeError("malformed chunked body: missing chunk-size line")
        size_line = data[pos:crlf]
        size_part = size_line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_part, 16)
        except ValueError as e:
            raise RuntimeError(
                f"malformed chunked body: invalid chunk size {size_part!r}"
            ) from e

        pos = crlf + 2
        if chunk_size == 0:
            if data.startswith(b"\r\n", pos):
                return bytes(out)
            trailer_end = data.find(b"\r\n\r\n", pos)
            if trailer_end == -1:
                raise RuntimeError(
                    "malformed chunked body: missing terminator after final chunk"
                )
            return bytes(out)

        end = pos + chunk_size
        if len(data) < end + 2:
            raise RuntimeError("malformed chunked body: truncated chunk data")
        out.extend(data[pos:end])
        if data[end : end + 2] != b"\r\n":
            raise RuntimeError("malformed chunked body: missing chunk data terminator")
        pos = end + 2


def extract_body(raw: bytes) -> bytes:
    """Split HTTP headers from body and decode transfer encodings."""
    sep = b"\r\n\r\n"
    if sep not in raw:
        raise RuntimeError("malformed HTTP response: no header/body separator")
    header_block, body = raw.split(sep, 1)
    headers = parse_http_headers(header_block)

    if is_chunked(headers):
        return decode_chunked(body)

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length.strip())
        except ValueError as e:
            raise RuntimeError(
                f"malformed HTTP response: invalid Content-Length {content_length!r}"
            ) from e
        if len(body) < length:
            raise RuntimeError(
                "malformed HTTP response: body shorter than Content-Length "
                f"({len(body)} < {length})"
            )
        return body[:length]

    return body


def parse_header_arg(header: str) -> str:
    """Validate a curl-style 'Name: value' header string."""
    if ":" not in header:
        raise ValueError(f"invalid header (expected 'Name: value'): {header!r}")
    name, value = header.split(":", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise ValueError(f"invalid header (empty name): {header!r}")
    return f"{name}: {value}"


def fetch_raw(url: str, extra_headers: list[str] | None = None, timeout: int = 30) -> bytes:
    """Fetch URL with no automatic gzip decoding — return the raw bytes."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme!r}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # Tell the server we are willing to accept gzip, but do NOT advertise
    # that we want it decoded (so we receive the raw stream back).
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: gzip_inspect/1.0",
        "Accept-Encoding: gzip",  # request gzip so server actually sends it
        "Connection: close",
    ]
    if extra_headers:
        headers.extend(extra_headers)
    request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")

    raw = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(request)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        raise RuntimeError(f"network error fetching {url}: {e}") from e

    # Split headers from body and decode chunked transfer-encoding when present.
    try:
        return extract_body(raw)
    except RuntimeError as e:
        raise RuntimeError(f"malformed HTTP response fetching {url}: {e}") from e


def inspect(body: bytes) -> dict:
    info = {
        "size_bytes": len(body),
        "magic_ok": None,
        "magic_hex": None,
        "crc32_in_trailer": None,
        "isize_in_trailer": None,
        "last8_hex": None,
        "decompressed_ok": None,
        "error": None,
    }

    if len(body) >= 2:
        info["magic_hex"] = body[:2].hex()
        info["magic_ok"] = body[:2] == GZIP_MAGIC

    if len(body) < TRAILER_LEN:
        info["error"] = f"response too short to have a trailer ({len(body)} < {TRAILER_LEN})"
        return info

    last8 = body[-TRAILER_LEN:]
    info["last8_hex"] = last8.hex()
    # CRC32 (little-endian) + ISIZE (little-endian) are the last 8 bytes
    info["crc32_in_trailer"] = int.from_bytes(last8[0:4], "little")
    info["isize_in_trailer"] = int.from_bytes(last8[4:8], "little")

    try:
        gzip.decompress(body)
        info["decompressed_ok"] = True
    except gzip.BadGzipFile as e:
        info["decompressed_ok"] = False
        info["error"] = f"gzip.BadGzipFile: {e}"
    except OSError as e:
        # OSError("CRC check failed ...") is the canonical "truncated trailer"
        # symptom; OSError("Compressed data ended prematurely") also common.
        info["decompressed_ok"] = False
        if "CRC check failed" in str(e) or "truncated" in str(e).lower():
            info["error"] = (
                f"decompression FAILED — endpoint is sending malformed gzip "
                f"({e}). Last 8 bytes: {last8.hex()}"
            )
        else:
            info["error"] = f"OSError during decompress: {e}"
    return info


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("url", help="HTTP(S) URL to fetch")
    ap.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help='extra HTTP header, curl-style (e.g. -H "Authorization: Bearer token")',
    )
    ap.add_argument("-o", "--output", help="write raw body to this file")
    args = ap.parse_args()

    extra_headers: list[str] = []
    if args.headers:
        try:
            extra_headers = [parse_header_arg(h) for h in args.headers]
        except ValueError as e:
            print(f"HEADER ERROR: {e}", file=sys.stderr)
            return 2

    print(f"Fetching {args.url} (Accept-Encoding: gzip) ...")
    try:
        body = fetch_raw(args.url, extra_headers=extra_headers or None)
    except RuntimeError as e:
        print(f"NETWORK ERROR: {e}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "wb") as f:
            f.write(body)
        print(f"Wrote raw response to {args.output} ({len(body)} bytes)")

    info = inspect(body)

    print(f"\n=== Gzip inspection ===")
    print(f"Total bytes:        {info['size_bytes']}")
    print(f"Magic bytes (hex):  {info['magic_hex']}  (expected 1f8b)")
    print(f"Magic OK:           {info['magic_ok']}")
    print(f"Last 8 bytes (hex): {info['last8_hex']}")
    print(f"  trailer CRC32:    {info['crc32_in_trailer']:#010x}")
    print(f"  trailer ISIZE:    {info['isize_in_trailer']} (raw mod-32 size)")

    if info["decompressed_ok"] is True:
        print("\n[OK] gzip.decompress() succeeded — response is well-formed.")
        return 0
    else:
        print(f"\n[FAIL] {info['error']}")
        if info["decompressed_ok"] is False and info["magic_ok"]:
            print("Diagnosis: endpoint is sending malformed gzip.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
