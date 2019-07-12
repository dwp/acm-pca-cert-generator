#!/usr/bin/env python

"""Handles keystore and Truststore generation."""

import OpenSSL
import jks
import logging
import os

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


logger = logging.getLogger("truststore")


def generate_keystore(
    keystore_path, keystore_password, priv_key, cert, alias, priv_key_password=None
):
    """Generate a Java KeyStore.

    Args:
        keystore_path (str): The path at which to save the keystore
        keystore_password (str): The password to protect the keystore with
        priv_key (str): The base64 PEM-encoded private key to store
        cert (str): The base64 PEM-encoded certificate signed by ACM PCA
        alias (str): The alias under which to store the key pair
        priv_key_password (str): The password to protect the private key with

    """
    logger.info("Generating Java KeyStore")
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, priv_key)
    dumped_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, pkey)

    x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    dumped_cert = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_ASN1, x509_cert
    )

    pke = jks.PrivateKeyEntry.new(alias, [dumped_cert], dumped_key, "rsa_raw")

    if priv_key_password:
        pke.encrypt(priv_key_password)

    keystore = jks.KeyStore.new("jks", [pke])
    try:
        newdir = os.path.dirname(keystore_path)
        os.makedirs(newdir)
    except OSError:
        # Raise only if the directory doesn't already exist
        if not os.path.isdir(newdir):
            raise
    keystore.save(keystore_path, keystore_password)


def parse_s3_url(url):
    """Extract the S3 bucket name and key from a given S3 URL.

    Args:
        url (str): The S3 URL to parse

    Returns:
        dict: A {"bucket": "string", "key": "string"} dict representing the
              S3 object identified by the given URL

    """
    parsed_url = urlparse(url)
    if parsed_url.scheme != "s3":
        raise ValueError("S3 URLs must start with 's3://'")

    bucket = parsed_url.netloc.split(".")[0]
    key = parsed_url.path.lstrip("/")

    return {"bucket": bucket, "key": key}


def generate_truststore(s3_client, truststore_path, truststore_password, certs):
    """Generate a Java TrustStore.

    Args:
        s3_client (Object): The aws utils to use
        truststore_path (str): The path at which to save the truststore
        truststore_password (str): The password to protect the truststore with
        certs (list): A list of dicts containing aliases and certificate paths
                      for SSL certs to add to the truststore, e.g.:
                      [{"alias": "testcert", "cert": "/tmp/mycert.pem"}]

    """
    logger.info("Generating Java TrustStore")
    trusted_certs = []
    for cert_entry in certs:
        alias = cert_entry["alias"]
        cert = parse_s3_url(cert_entry["cert"])
        pem_cert = s3_client.get_object(Bucket=cert["bucket"], Key=cert["key"])
        x509_cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, pem_cert["Body"].read().decode("utf-8")
        )
        asn_cert = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, x509_cert
        )
        trusted_certs.append(jks.TrustedCertEntry.new(alias, asn_cert))

    try:
        newdir = os.path.dirname(truststore_path)
        os.makedirs(newdir)
    except OSError:
        # Raise only if the directory doesn't already exist
        if not os.path.isdir(newdir):
            raise

    truststore = jks.KeyStore.new("jks", trusted_certs)
    truststore.save(truststore_path, truststore_password)
