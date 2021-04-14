FROM python:3-alpine3.13

ARG ACM_CERT_HELPER_VERSION=0.41.7

# Upgrade pip

RUN pip install --upgrade pip
ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1
# Python Dependencies

RUN apk add --no-cache \
    libressl-dev \
    musl-dev \
    gcc \
    libffi-dev

# Container Dependencies
RUN apk add --update --no-cache \
    curl \
    aws-cli \
    gcc \
    musl-dev \
    util-linux

# Download acm-cert-helper
RUN curl -k -LSs --output /tmp/acm_cert_helper.tar.gz \
    https://github.com/dwp/acm-pca-cert-generator/releases/download/${ACM_CERT_HELPER_VERSION}/acm_cert_helper-${ACM_CERT_HELPER_VERSION}.tar.gz && \
    pip3 install /tmp/acm_cert_helper.tar.gz && \
    rm -f /tmp/acm_cert_helper.tar.gz

COPY entrypoint.sh /bin/entrypoint.sh

RUN mkdir -p /acm-cert-helper && \
    chmod 0755 /bin/entrypoint.sh

# Data volume
VOLUME [ "/acm-cert-helper" ]

# Working from data dir
WORKDIR /acm-cert-helper

ENTRYPOINT [ "/bin/entrypoint.sh" ]
