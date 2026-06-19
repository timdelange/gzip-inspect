# gzip-inspect

A small Python CLI that fetches an HTTP(S) endpoint **without** automatic
decompression, captures the raw gzip stream, validates the gzip magic bytes,
and tries to decompress it. Designed to diagnose endpoints that send
malformed or truncated gzip bodies (e.g. missing CRC32 / ISIZE trailer).

## Why

Some servers (broken proxies, misconfigured CDNs, half-baked middleware)
advertise `Content-Encoding: gzip` but ship a body that is either:

- not actually gzipped (wrong magic)
- truncated mid-stream (no trailer)
- has a wrong/missing CRC32

Most HTTP clients will silently swallow the error and pass you garbage.
`gzip-inspect` shows you exactly what came over the wire.

## Install

Just clone and run — no dependencies, stdlib only:

```bash
git clone https://github.com/timdelange/gzip-inspect.git
cd gzip-inspect
chmod +x gzip_inspect.py
./gzip_inspect.py --help
```

Requires Python 3.7+.

## Usage

```bash
gzip_inspect.py <url> [-o raw_response.gz]
```

- `url` — the HTTP(S) endpoint to fetch
- `-o, --output` — optionally write the raw bytes to a file for further
  inspection (e.g. `xxd raw_response.gz` or `zcat raw_response.gz`)

The script sends `Accept-Encoding: gzip` so the server will actually
return a gzip stream, but uses a raw socket to **prevent** the standard
library from transparently decoding it.

### Example

```bash
$ ./gzip_inspect.py https://httpbin.org/gzip
Fetching https://httpbin.org/gzip (Accept-Encoding: gzip) ...

=== Gzip inspection ===
Total bytes:        421
Magic bytes (hex):  1f8b  (expected 1f8b)
Magic OK:           True
Last 8 bytes (hex): 23ce5e1300000000
  trailer CRC32:    0x135ece23
  trailer ISIZE:    0 (raw mod-32 size)

[OK] gzip.decompress() succeeded — response is well-formed.
```

### Diagnosing a broken endpoint

```bash
$ ./gzip_inspect.py https://broken.example.com/data
Fetching https://broken.example.com/data (Accept-Encoding: gzip) ...

=== Gzip inspection ===
Total bytes:        8192
Magic bytes (hex):  1f8b  (expected 1f8b)
Magic OK:           True
Last 8 bytes (hex): 8a5d2f47ffffffff
  trailer CRC32:    0x472f5d8a
  trailer ISIZE:    4294967295 (raw mod-32 size)

[FAIL] decompression FAILED — endpoint is sending malformed gzip
       (CRC check failed ...).
       Last 8 bytes: 8a5d2f47ffffffff
Diagnosis: endpoint is sending malformed gzip.
```

The `ffffffff` ISIZE and the CRC check failure are the classic signs of a
truncated body — the server sent headers promising N bytes of compressed
data, but the connection closed after fewer bytes (or a proxy cut the
stream early).

## Exit codes

- `0` — gzip was well-formed
- `1` — response is malformed / failed decompression
- `2` — network error (DNS, refused, timeout, malformed HTTP response)

## How it works

1. Open a raw `socket` (or `ssl.wrap_socket` for HTTPS) — no `urllib`,
   no `requests`, no implicit decoding.
2. Send a minimal HTTP/1.1 GET with `Accept-Encoding: gzip`.
3. Read until the server closes the connection.
4. Split headers from body on `\r\n\r\n`.
5. Check bytes 0–1 are `1f 8b` (the gzip magic).
6. Inspect the last 8 bytes:
   - bytes 0–3 of the trailer = CRC32 of the uncompressed data
   - bytes 4–7 of the trailer = ISIZE (uncompressed size mod 2³²)
7. Attempt `gzip.decompress()` and report any
   `gzip.BadGzipFile` / `OSError("CRC check failed ...")` / truncation
   errors with a clear diagnosis.

## License

MIT
