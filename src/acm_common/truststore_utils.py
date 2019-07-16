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


def parse_trusted_cert_arg(trusted_cert_aliases, trusted_certs):
    """Split the CLI arguments for trusted cert aliases and paths.

    Args:
        trusted_cert_aliases (str): comma-separated list of certificate aliases
                                    to add to the truststore
        trusted_certs (str): comma-separated list of certificates (paths) to add
                             to the truststore

    Returns:
        list of dicts: A list of {"alias": "string", "cert": "string"} dicts
                       containing a mapping of alias name to certifificate path
                       for trusted certificates

    Raises:
        ValueError: If the number of trusted_cert_aliases and trusted_certs don't match

    """
    aliases = trusted_cert_aliases.split(",")
    cert_paths = trusted_certs.split(",")
    if len(aliases) != len(cert_paths):
        raise ValueError(
            "The number of trusted certificate aliases ({}) and trusted "
            "certificates ({}) don't match".format(len(aliases), len(cert_paths))
        )
    certs = []
    i = 0
    for alias in aliases:
        cert = {"alias": alias, "cert": cert_paths[i]}
        certs.append(cert)
        i += 1
    return certs


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
        new_dir = os.path.dirname(keystore_path)
        os.makedirs(new_dir)
    except OSError:
        # Raise only if the directory doesn't already exist
        if not os.path.isdir(new_dir):
            raise
    keystore.save(keystore_path, keystore_password)
    logger.info("Java KeyStore generated")


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
        new_dir = os.path.dirname(truststore_path)
        os.makedirs(new_dir)
    except OSError:
        # Raise only if the directory doesn't already exist
        if not os.path.isdir(new_dir):
            raise

    truststore = jks.KeyStore.new("jks", trusted_certs)
    truststore.save(truststore_path, truststore_password)
    logger.info("Java TrustStore generated")
