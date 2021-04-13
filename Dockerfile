FROM alpine:3.12.0

ARG ACM_CERT_HELPER_VERSION=0.41.0

# Dependencies
RUN apk add --update --no-cache \
    curl \
    aws-cli

COPY entrypoint.sh /bin/entrypoint.sh

# Download acm-cert-helper
RUN curl -k -LSs --output /tmp/acm_cert_helper.tar.gz \
    https://github.com/dwp/acm-pca-cert-generator/releases/download/${ACM_CERT_HELPER_VERSION}/acm_cert_helper-${ACM_CERT_HELPER_VERSION}.tar.gz && \
    tar -C /tmp --strip-components=1 -zoxf /tmp/acm_cert_helper.tar.gz && \
    rm -f /tmp/acm_cert_helper.tar.gz && \
    mv /tmp/acm_cert_helper /bin/ && \
    mkdir -p /acm-cert-helper && \
    chmod 0755 /bin/entrypoint.sh && \
    chown -R nobody:nogroup /etc/acm_cert_helper /acm_cert_helper

# Data volume
VOLUME [ "/acm-cert-helper" ]

# Working from data dir
WORKDIR /acm-cert-helper

ENTRYPOINT [ "/bin/entrypoint.sh" ]
