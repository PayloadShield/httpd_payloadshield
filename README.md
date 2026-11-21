# httpd_payloadshield
`mod_payloadshield` is an Apache HTTP Server 2.4 module that decrypts the PayloadShield request envelope before the request reaches the application (or `mod_proxy` upstream) and encrypts the response body before it is returned. It is the Apache counterpart of `ngx_payloadshield` and shares its crypto providers and wire format.

## Overview and use case

PayloadShield is primarily intended for **encrypted service-to-service communication behind Apache**. The calling service sends an encrypted PayloadShield JSON envelope to Apache. Apache authenticates and decrypts the request, forwards plaintext to the internal application or `mod_proxy` upstream, and encrypts the complete upstream response before returning it.

```text
Billing Service                       Apache Gateway
  |  TLS + {"encrypted":"..."} request
  | ------------------------------------------> |
  |                         decrypt             |
  |                         mod_proxy          |
  |                                      PHP / Java / Node / Python / Go
  |                         encrypted response |
  | <------------------------------------------ |
```

Use this module when payload encryption must sit at a common Apache gateway, public-facing applications should receive ciphertext only, or upstream applications should remain unchanged while trusted internal traffic is handled as normal HTTP.

Advantages include:

* Centralized request and response encryption for Apache virtual hosts and locations.
* Application-layer protection in addition to TLS.
* Support for existing PHP, Java, Node.js, Python, Go, and other HTTP upstreams.
* AES-256-GCM, ChaCha20-Poly1305, and RSA-Hybrid algorithms.
* Shared PayloadShield wire format across Apache, Nginx, and supported framework integrations.
* No PayloadShield dependency in the upstream application.

PayloadShield does not replace HTTPS, authentication, authorization, replay prevention, input validation, audit logging, key management, or network isolation.

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

## Pre-built module

Pre-built modules for the following Apache HTTP Server versions are available in [`dist/`](dist/) and on the [GitHub Releases page](https://github.com/PayloadShield/httpd_payloadshield/releases/latest):

| Apache version | Download |
|---|---|
| 2.4.62 | [mod_payloadshield_2.4.62.so](https://github.com/PayloadShield/httpd_payloadshield/releases/latest/download/mod_payloadshield_2.4.62.so) |
| 2.4.63 | [mod_payloadshield_2.4.63.so](https://github.com/PayloadShield/httpd_payloadshield/releases/latest/download/mod_payloadshield_2.4.63.so) |
| 2.4.64 | [mod_payloadshield_2.4.64.so](https://github.com/PayloadShield/httpd_payloadshield/releases/latest/download/mod_payloadshield_2.4.64.so) |
| 2.4.71 | [mod_payloadshield_2.4.71.so](https://github.com/PayloadShield/httpd_payloadshield/releases/latest/download/mod_payloadshield_2.4.71.so) |

Download the module that matches the Apache HTTP Server version and platform you are running:

```sh
HTTPD_VERSION=2.4.71
curl -fL -o "mod_payloadshield_${HTTPD_VERSION}.so" \
  "https://github.com/PayloadShield/httpd_payloadshield/releases/latest/download/mod_payloadshield_${HTTPD_VERSION}.so"
sudo install -m 0755 "mod_payloadshield_${HTTPD_VERSION}.so" \
  "$(apxs -q LIBEXECDIR)/mod_payloadshield.so"
```

Then load and validate the module:

```apache
LoadModule payloadshield_module modules/mod_payloadshield.so
```

```sh
apachectl configtest
sudo apachectl restart
```

Pre-built binaries must match your Apache HTTP Server build, CPU architecture, and deployment environment. Test each downloaded module with `apachectl configtest` and integration tests before production use.

## Docker installation

Install Docker Engine or Docker Desktop and make sure the Docker daemon is running. The Docker image builds the Apache module, loads it in Apache, and listens on container port `8080`. PayloadShield processing is disabled until you add directives for the endpoint you want to protect.

Build and start an image locally (replace the version with one from `docker/httpd-versions.json`):

```sh
VERSION=2.4.69
docker build -f docker/Dockerfile --build-arg HTTPD_VERSION="$VERSION" --target final \
  -t "payloadshield-httpd:$VERSION" .
docker run -d --name payloadshield-httpd --restart unless-stopped \
  -p 8080:8080 "payloadshield-httpd:$VERSION"
```

Check that Apache is serving requests:

```sh
curl http://localhost:8080/
```

To enable encryption for an endpoint, copy the image's Apache configuration and add a `<Location>` block. Keep the existing `LoadModule payloadshield_module` line in the copied configuration:

```sh
docker run --rm "payloadshield-httpd:$VERSION" \
  cat /usr/local/apache2/conf/httpd.conf > httpd.conf
```

Add this block to `httpd.conf` and provide a 32-byte symmetric key in `server.key` (or its Base64 encoding):

```apache
<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm aes-gcm-256
    PayloadShieldKey /etc/payloadshield/server.key
    PayloadShieldMaxBodySize 10485760
</Location>
```

Do not commit the key to source control. Validate the configuration, then start the container with the configuration and key mounted read-only:

```sh
docker run --rm \
  -v "$PWD/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
  -v "$PWD/server.key:/etc/payloadshield/server.key:ro" \
  "payloadshield-httpd:$VERSION" httpd -t

docker rm -f payloadshield-httpd
docker run -d --name payloadshield-httpd --restart unless-stopped \
  -p 8080:8080 \
  -v "$PWD/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
  -v "$PWD/server.key:/etc/payloadshield/server.key:ro" \
  "payloadshield-httpd:$VERSION"
```

For a different algorithm, select `chacha20-poly1305` with its 32-byte key, or configure the role-specific PEM files for `rsa-hybrid` as described under [Configuration](#configuration). Use TLS in front of the container; payload encryption does not replace transport security.

To build all listed versions, run the crypto unit tests, and smoke-test the images, use `bash docker/build.sh`. The deployment scripts (`./deploy.sh` on Linux/macOS or `deploy.bat` on Windows) start a container for each listed version on consecutive host ports beginning at `HOST_PORT` (default `8080`). They pull tags from `IMAGE_REPOSITORY` (default `kanduganesh/payloadshield-httpd`); if a tag is missing, they build it and push it to that registry. Set `IMAGE_REPOSITORY`, `CONTAINER_NAME`, and `HOST_PORT` as needed before deployment.

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

### AES-256-GCM

Generate a random 32-byte key and mount or install it with restricted permissions:

```sh
openssl rand 32 > server.key
chmod 600 server.key
```

```apache
<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm aes-gcm-256
    PayloadShieldKey /etc/payloadshield/server.key
    PayloadShieldMaxBodySize 10485760
</Location>
```

AES-256-GCM uses a random 12-byte nonce and 16-byte authentication tag. Distribute the same 32-byte key only to services that are authorized to communicate. Never commit the key to source control.

### ChaCha20-Poly1305

ChaCha20-Poly1305 uses the same 32-byte key size and shared PayloadShield envelope as AES-GCM:

```apache
<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm chacha20-poly1305
    PayloadShieldKey /etc/payloadshield/server.key
    PayloadShieldMaxBodySize 10485760
</Location>
```

Both Apache and the calling client must select the same algorithm and key. Coordinate algorithm and key changes with a deployment of both ends.

### RSA-Hybrid

RSA-Hybrid combines RSA-OAEP-SHA256 key wrapping with AES-256-GCM payload encryption:

```sh
openssl genrsa -out server-private.pem 2048
openssl rsa -in server-private.pem -pubout -out server-public.pem
openssl genrsa -out client-recipient-private.pem 2048
openssl rsa -in client-recipient-private.pem -pubout -out client-recipient-public.pem
chmod 600 server-private.pem client-recipient-private.pem
```

```apache
<Location "/api">
    PayloadShield On
    PayloadShieldAlgorithm rsa-hybrid
    PayloadShieldPrivateKey /etc/payloadshield/server-private.pem
    PayloadShieldPublicKey /etc/payloadshield/client-recipient-public.pem
    PayloadShieldMaxBodySize 10485760
</Location>
```

Clients use `server-public.pem` to encrypt requests. Apache decrypts those requests with `server-private.pem`, while clients use `client-recipient-private.pem` to decrypt responses encrypted with `client-recipient-public.pem`. RSA keys must use PEM format and be at least 2048 bits.

## Behaviour

* Requests are fully read and decrypted in the `fixups` phase, so `Content-Length` seen by handlers and `mod_proxy` is the plaintext length. Failures return 400 (bad envelope or authentication failure), 413 (too large) or 500.
* Responses are fully buffered, encrypted and sent as `application/json` with a new `Content-Length`. Upstream responses with a `Content-Encoding` other than `identity` are refused (500) unless fail-open is on.
* Subrequests, internal redirects, HEAD, 1xx, 204 and 304 responses are not processed.

Compile and integration-test the module against the exact httpd/OpenSSL build used in deployment, and combine it with TLS, replay protection and restrictive key-file permissions.

## Maintainer

PayloadShield is maintained by **Ganesh Kandu**.

* Email: [kanduganesh@gmail.com](mailto:kanduganesh@gmail.com)
* GitHub: [github.com/kanduganesh](https://github.com/kanduganesh)
* Project: [github.com/PayloadShield/httpd_payloadshield](https://github.com/PayloadShield/httpd_payloadshield)
