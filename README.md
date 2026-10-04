# httpd_payloadshield
`mod_payloadshield` is an Apache HTTP Server 2.4 module that decrypts the PayloadShield request envelope before the request reaches the application (or `mod_proxy` upstream) and encrypts the response body before it is returned. It is the Apache counterpart of `ngx_payloadshield` and shares its crypto providers and wire format.

## Wire format

Identical to ngx_payloadshield and ComPyPS/ComPHPPS:

* Body is JSON `{"encrypted":"<Base64>"}` in both directions.
* `aes-gcm-256` / `chacha20-poly1305`: Base64 of `12-byte nonce || ciphertext || 16-byte tag`, shared 32-byte key.
* `rsa-hybrid`: Base64 of a JSON object with Base64 `key` (RSA-OAEP-SHA256 wrapped AES key), `nonce` and `data`.

The algorithm is static server configuration; it is never taken from the request.

## Build

Requires Apache 2.4 development files (`apxs`) and OpenSSL 1.1.1+ headers.

```sh
make                # builds mod_payloadshield.la with apxs
sudo make install   # installs mod_payloadshield.so
make test           # crypto unit tests (no Apache needed)
```

## Configuration

```apache
LoadModule payloadshield_module modules/mod_payloadshield.so

<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm aes-gcm-256
    PayloadShieldKey /etc/payloadshield/server.key
    PayloadShieldMaxBodySize 10485760
</Location>
```

| Directive | Meaning |
|---|---|
| `PayloadShield On\|Off` | Enable processing. Default `Off`. |
| `PayloadShieldAlgorithm name` | `aes-gcm-256`, `chacha20-poly1305` or `rsa-hybrid`. Required when enabled. |
| `PayloadShieldKey file` | Symmetric key file: 32 raw bytes or Base64 of 32 bytes. |
| `PayloadShieldPrivateKey file` | RSA private PEM used to decrypt requests (`rsa-hybrid`). |
| `PayloadShieldPublicKey file` | RSA public PEM used to encrypt responses (`rsa-hybrid`). |
| `PayloadShieldMaxBodySize bytes` | Maximum plaintext request/response size. Default 10 MiB. |
| `PayloadShieldFailOpen On\|Off` | Pass data through unchanged when PayloadShield fails. Default `Off`; can expose plaintext. |

Directives are valid in server, virtual host, directory and location contexts. Unsupported algorithms and unreadable keys fail `apachectl configtest`. Set `LimitRequestBody` high enough for the encrypted JSON request.

## Behaviour

* Requests are fully read and decrypted in the `fixups` phase, so `Content-Length` seen by handlers and `mod_proxy` is the plaintext length. Failures return 400 (bad envelope or authentication failure), 413 (too large) or 500.
* Responses are fully buffered, encrypted and sent as `application/json` with a new `Content-Length`. Upstream responses with a `Content-Encoding` other than `identity` are refused (500) unless fail-open is on.
* Subrequests, internal redirects, HEAD, 1xx, 204 and 304 responses are not processed.

This module is a prototype. Compile and integration-test it against the exact httpd/OpenSSL build used in deployment, and combine it with TLS, replay protection and restrictive key-file permissions.
