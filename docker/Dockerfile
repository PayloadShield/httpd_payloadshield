ARG HTTPD_VERSION=2.4.69
ARG HTTPD_IMAGE=httpd:${HTTPD_VERSION}

FROM ${HTTPD_IMAGE} AS builder
ARG HTTPD_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends \
        libapr1-dev libaprutil1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/httpd_payloadshield
COPY . .
RUN make APXS=/usr/local/apache2/bin/apxs \
    && make test

FROM builder AS test

FROM ${HTTPD_IMAGE} AS runtime
ARG HTTPD_VERSION
LABEL org.opencontainers.image.title="payloadshield-httpd" \
      org.opencontainers.image.version="${HTTPD_VERSION}"

COPY --from=builder /src/httpd_payloadshield/.libs/mod_payloadshield.so \
    /usr/local/apache2/modules/mod_payloadshield.so
RUN sed -i 's/^Listen 80$/Listen 8080/' /usr/local/apache2/conf/httpd.conf \
    && printf '\nLoadModule payloadshield_module modules/mod_payloadshield.so\nServerName localhost\n' \
        >> /usr/local/apache2/conf/httpd.conf \
    && printf 'ok\n' > /usr/local/apache2/htdocs/index.html

EXPOSE 8080
CMD ["httpd-foreground"]

FROM runtime AS final
