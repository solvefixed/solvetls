# solvetls

<a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.12%E2%80%933.13-3776AB.svg?logo=python&amp;logoColor=white" alt="Python 3.12–3.13"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>

A TLS and HTTP fingerprinting server. Each response describes the client's JA3,
JA4 and Akamai fingerprints, TLS extensions, captured HTTP/2 frames, and available
IP/TCP information.

Try <https://tls.solvedev.to/> in a browser or with `curl`.

## Quick start

A TLS certificate and private key are required; see [Certificates](#certificates).

With Python 3.12–3.13:

```shell
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Test the local server from another terminal:

```shell
curl -k https://localhost/
```

Plain HTTP requests redirect to HTTPS (308), preserving the host, path and query.

Or run with Docker:

```shell
docker compose up -d
```

For a direct Python launch, the account needs permission to bind ports 80 and 443.
For local testing, use `SOLVETLS_PORT=8443 SOLVETLS_HTTP_PORT=8080 python main.py`
and `curl -k https://localhost:8443/`.

## Response

<details>
<summary>Example HTTP/2 response (abridged)</summary>

```jsonc
{
  "source": "https://github.com/solvefixed/solvetls",
  "ip": "203.0.113.42:8616",
  "http_version": "HTTP/2.0",
  "method": "GET",
  "user_agent": "curl/8.7.1",

  "tls": {
    "ja3_hash": "375c6162a492dfbf2795909110ce8424",
    "ja4": "t13d4907h2_0d8feac7bc37_7395dae3b2f3",
    "version": { "value": 771, "hex": "0x0303", "name": "TLS_1_2" },
    "cipher_suites": [
      { "value": 4867, "hex": "0x1303", "name": "TLS_CHACHA20_POLY1305_SHA256" },
      { "value": 4866, "hex": "0x1302", "name": "TLS_AES_256_GCM_SHA384" }
      // ...
    ],
    "extensions": [
      // ...
      {
        "value": 10, "hex": "0x000a", "name": "SUPPORTED_GROUPS", "length": 10,
        "decoded": { "groups": [
          { "value": 29, "hex": "0x001d", "name": "X25519" },
          { "value": 23, "hex": "0x0017", "name": "SECP256R1" },
          { "value": 24, "hex": "0x0018", "name": "SECP384R1" },
          { "value": 25, "hex": "0x0019", "name": "SECP521R1" }
        ] },
        "data": "0008001d001700180019"
      }
      // ...
    ]
    // ...
  },

  "http2": {
    "akamai_fingerprint": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
    "akamai_fingerprint_hash": "64a832f547be33249bf4d33e8a46c5dc",
    "settings": [
      { "value": 3, "hex": "0x0003", "name": "MAX_CONCURRENT_STREAMS", "setting": 100 },
      { "value": 4, "hex": "0x0004", "name": "INITIAL_WINDOW_SIZE", "setting": 10485760 },
      { "value": 2, "hex": "0x0002", "name": "ENABLE_PUSH", "setting": 0 }
    ],
    "headers": [
      [":method", "GET"], [":scheme", "https"],
      [":authority", "tls.solvedev.to"], [":path", "/"],
      ["user-agent", "curl/8.7.1"], ["accept", "*/*"]
    ],
    "frames": [
      // ...
      {
        "value": 1, "hex": "0x0001", "name": "HEADERS", "flags": 5,
        "flag_names": ["END_STREAM", "END_HEADERS"],
        "stream_id": 1, "length": 31,
        "payload": {
          "header_block": "8287418b4d085d07a3b9642f75d27f847a8825b650c3cbbab87f53032a2f2a",
          "priority": null
        },
        "raw": "00001f0105000000018287418b4d085d07a3b9642f75d27f847a8825b650c3cbbab87f53032a2f2a"
      }
    ]
  },

  "tcpip": {
    "cap_length": 64,
    "dst_port": 443,
    "src_port": 8616,
    "ip": { "id": 0, "ttl": 49, "ip_version": 4, "src_ip": "203.0.113.42" },
    "tcp": { "ack": 0, "checksum": 6357, "seq": 2902113646, "window": 65535 }
    // ...
  }
}
```

</details>

An HTTP/1.1 client gets an `http1` section instead, with its request line and headers.

Reports preserve header order and casing. TLS extensions include raw hex `data`
and, when supported, `decoded` values. The original HTTP/1.1 request head
(`raw_head`) and HTTP/2 frames (`raw`) are also included as hex.

## Certificates

For local testing, generate a self-signed certificate:

```shell
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout certs/privkey.pem -out certs/fullchain.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

For a public server, use a trusted certificate for your domain, for example from
[Let's Encrypt](https://letsencrypt.org/).

## Configuration

All environment variables are optional.

| Variable | Default | Description |
|---|---|---|
| `SOLVETLS_HOST` | `0.0.0.0` | bind address |
| `SOLVETLS_PORT` | `443` | HTTPS bind port |
| `SOLVETLS_HTTP_PORT` | `80` | HTTP redirect port; empty disables HTTP |
| `SOLVETLS_CERT` | `certs/fullchain.pem` | certificate chain |
| `SOLVETLS_KEY` | `certs/privkey.pem` | private key |
| `SOLVETLS_MONGODB_URL` | *(unset)* | MongoDB connection string including a database name |
| `SOLVETLS_LOG_LEVEL` | `INFO` | `DEBUG` adds the negotiated cipher and ALPN per connection |

Set `SOLVETLS_MONGODB_URL` to save reports in the database's `fingerprints`
collection. When configured, MongoDB must be available at startup.

### Docker configuration

Set `SOLVETLS_*` values in `docker-compose.yml` under `environment`; shell
variables and Compose `.env` files are not forwarded automatically.
Use container paths for certificates, and adjust `ports` and volumes to match.

## Limitations

- Connect directly or use TLS passthrough. A reverse proxy that terminates TLS
  hides the original client's TLS fingerprint from solvetls. TLS passthrough
  preserves it, but `ip` and `tcpip` may describe the TCP proxy.
- The server closes each connection after one fingerprint response.
- Each server instance accepts up to 32 clients and processes up to 4 reports at
  once, including database writes. Excess connections are closed; requests that
  cannot obtain a report slot receive an empty `503` response.
- Detailed TCP/IP data requires Linux kernel support. When unavailable, `tcpip`
  contains socket addresses only. IPv6 extension headers and TCP options are
  not decoded.

## Development

Tests require the OpenSSL command-line tool.

```shell
python -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
python -m unittest discover -v
```

Include the localhost network tests:

```shell
SOLVETLS_NETWORK_TESTS=1 python -m unittest discover -v
```

Run the full suite with a running MongoDB test server. The test URL must omit
the database name; integration tests create and delete their own unique databases.

```shell
SOLVETLS_NETWORK_TESTS=1 SOLVETLS_MONGODB_TESTS=1 \
  SOLVETLS_MONGODB_TEST_URL=mongodb://localhost:27017 \
  python -m unittest discover -v
```

GitHub Actions runs lint checks, tests, and Docker smoke tests on pushes and pull
requests.

## License

[MIT](./LICENSE)
