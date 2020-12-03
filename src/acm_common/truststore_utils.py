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
certificate_suffix = "-----END CERTIFICATE-----"


def command_exists(name):
    """Check whether `name` is on PATH and marked as executable.

    Args:
        name (str): Command to check if exists
    """
    from shutil import which

    return which(name) is not None


def get_aws_certificate_chain(all_aws_data):
    """Make a certificate chain in order.

    Args:
        all_aws_data (json): the results of the Retrieve call

    Returns:
        list: A list of base 64 encoded certs in order

    """
    downloaded_cert = all_aws_data["Certificate"]
    cert_chain = [downloaded_cert]

    downloaded_chain = all_aws_data["CertificateChain"].split(certificate_suffix)
    downloaded_chain.pop()

    for index in range(len(downloaded_chain)):
        downloaded_chain[index] = (downloaded_chain[index] + certificate_suffix).strip()

    cert_chain.extend(downloaded_chain)
    return cert_chain


def parse_trusted_cert_arg(trusted_cert_aliases, trusted_certs_s3_urls):
    """Split the CLI arguments for trusted cert aliases and paths.

    Args:
        trusted_cert_aliases (str): comma-separated list of certificate aliases
                                    to add to the truststore
        trusted_certs_s3_urls (str): comma-separated list of certificates (paths) to
                                    add to the truststore

    Returns:
        list of dicts: A list of {"alias": "string", "cert": "string"} dicts
                       containing a mapping of alias name to certificate path
                       for trusted certificates, e.g.
                       [
                        {"alias": "a1", "cert": "c1", "source": "s3"},
                        {"alias": "a2", "cert": "c2", "source": "s3"},
                       ...]

    Raises:
        ValueError: If the number of trusted_cert_aliases and trusted_certs don't match

    """
    aliases = trusted_cert_aliases.split(",")
    cert_paths = trusted_certs_s3_urls.split(",")
    if len(aliases) != len(cert_paths):
        raise ValueError(
            "The number of trusted certificate aliases ({}) and trusted "
            "certificates ({}) don't match".format(len(aliases), len(cert_paths))
        )
    certs = []
    i = 0
    for alias in aliases:
        cert_data = {"alias": alias, "cert": cert_paths[i], "source": "s3"}
        certs.append(cert_data)
        i += 1
    return certs


def generate_keystore(
    keystore_path, keystore_password, priv_key, cert_list, alias, priv_key_password=None
):
    """Generate a Java KeyStore.

    Args:
        keystore_path (str): The path at which to save the keystore
        keystore_password (str): The password to protect the keystore with
        priv_key (str): The base64 PEM-encoded private key to store
        cert_list (List of str): A list of base64 PEM-encoded certificates
            signed by ACM PCA.
            Multiple certificates should represent the chain in the right order.
        alias (str): The alias under which to store the key pair
        priv_key_password (str): The password to protect the private key with

    """
    logger.info("Generating Java KeyStore")
    key_pem = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, priv_key)
    dumped_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, key_pem)

    dumped_cert_list = []
    for cert in cert_list:
        x509_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        dumped_cert = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, x509_cert
        )
        dumped_cert_list.append(dumped_cert)

    number_certs = len(dumped_cert_list)
    logger.info("Adding {} certs to keystore...".format(number_certs))
    pke = jks.PrivateKeyEntry.new(alias, dumped_cert_list, dumped_key, "rsa_raw")

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


def add_cert_and_key(priv_key, cert_list, alias):
    """Add certificate and private key.

    Args:
        priv_key (str): The base64 PEM-encoded private key to store
        cert_list (List of str): A list of base64 PEM-encoded certificates
            signed by ACM PCA.
            Multiple certificates should represent the chain in the right order.
        alias (str): The alias under which to store the key pair

    """
    logger.info("Writing certificate and private key to filesystem")

    # Determine which directory to store certs in
    if command_exists("update-ca-trust"):
        ca_dir = "/etc/pki"
    elif command_exists("update-ca-certificates"):
        ca_dir = "/etc/ssl"
    else:
        logger.error("Cannot determine certs directory")
        raise OSError(
            "OS is missing a required command for CA trust. Either update-ca-trust or "
            "update-ca-certificates is required."
        )

    logger.info("Using cert directory:" + ca_dir)

    with open(ca_dir + "/private/" + alias + ".key", "a") as f:
        f.write(str(priv_key))

    for cert in cert_list:
        with open(ca_dir + "/certs/" + alias + ".crt", "a") as f:
            f.write(cert)


def parse_s3_url(url):
    """Extract the S3 bucket name and key from a given S3 URL.

    Args:
        url (str): The S3 URL to parse e.g. s3://bucket/folder/file.txt

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


def fetch_cert(source, entry, s3_client):
    """Fetch a cert for s3 or use text in memory.

    Args:
        source (String): A valid source, e.g. s3 or memory
        entry (String): The s3 url, or the plain text
        s3_client (Object): The aws utils to use

    Returns:
        pem_cert_body (String): Newline separated pem data

    """
    if source == "s3":
        bucket_and_key = parse_s3_url(entry)
        logger.info("...reading s3 source = {}".format(bucket_and_key))
        pem_cert = s3_client.get_object(
            Bucket=bucket_and_key["bucket"], Key=bucket_and_key["key"]
        )
        pem_cert_body = pem_cert["Body"].read()
    elif source == "memory":
        logger.info("...reading from memory")
        pem_cert_body = entry
    else:
        raise ValueError(
            "Invalid cert entry type {}, " "must be one of s3, memory".format(source)
        )

    # Python3 will return a byte string, Python2 will return a string
    if type(pem_cert_body) == bytes:
        pem_cert_body = pem_cert_body.decode("utf-8")

    return pem_cert_body


def generate_truststore(s3_client, truststore_path, truststore_password, certs):
    """Generate a Java TrustStore.

    Supports certs that are either specified from an s3 url,
    or provided in plain text in memory

    Args:
        s3_client (Object): The aws utils to use
        truststore_path (str): The path at which to save the truststore
        truststore_password (str): The password to protect the truststore with
        certs (list): A list of dicts containing aliases and certificate paths
                      for SSL certs to add to the truststore, e.g.:
                      [{"alias": "testcert", "cert": "/tmp/mycert.pem"}]

    """
    logger.info("Generating Java TrustStore")

    try:
        new_dir = os.path.dirname(truststore_path)
        os.makedirs(new_dir)
    except OSError:
        # Raise only if the directory doesn't already exist
        if not os.path.isdir(new_dir):
            raise

    trusted_certs = []
    for cert_entry in certs:
        alias = cert_entry["alias"]
        entry = cert_entry["cert"]
        source = cert_entry["source"]
        logger.info("...Processing cert with alias = {} from {}".format(alias, source))

        pem_cert_body = fetch_cert(source, entry, s3_client)
        logger.debug("...cert body = {}".format(pem_cert_body))

        x509_cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, pem_cert_body.decode("utf-8")
        )
        asn_cert = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, x509_cert
        )
        trusted_certs.append(jks.TrustedCertEntry.new(alias, asn_cert))

    truststore = jks.KeyStore.new("jks", trusted_certs)
    truststore.save(truststore_path, truststore_password)
    logger.info("Java TrustStore generated")


def add_ca_certs(s3_client, certs):
    """Update CA certificates.

    Supports certs that are either specified from an s3 url,
    or provided in plain text in memory

    Args:
        s3_client (Object): The aws utils to use
        certs (list): A list of dicts containing aliases and certificate paths
                      for SSL certs to add to the CA certificates, e.g.:
                      [{"alias": "testcert", "cert": "/tmp/mycert.pem"}]

    """
    logger.info("Fetching CA certs and writing to filesystem")

    # Determine which update-ca command to use and directory to store CAs in
    if command_exists("update-ca-trust"):
        logger.info("update-ca-trust available")
        update_ca_cmd = "update-ca-trust"
        ca_dir = "/etc/pki/ca-trust/source/anchors/"
    elif command_exists("update-ca-certificates"):
        logger.info("update-ca-certificates available")
        update_ca_cmd = "update-ca-certificates"
        ca_dir = "/usr/local/share/ca-certificates/"
    else:
        logger.error("Environment is missing required CA commands")
        raise OSError(
            "OS is missing a required command for CA trust. Either update-ca-trust or "
            "update-ca-certificates is required."
        )

    for cert_entry in certs:
        alias = cert_entry["alias"]
        entry = cert_entry["cert"]
        source = cert_entry["source"]
        logger.info("...Processing cert with alias = {} from {}".format(alias, source))

        pem_cert_body = fetch_cert(source, entry, s3_client)
        logger.debug("...cert body = {}".format(pem_cert_body))

        with open(ca_dir + alias + ".crt", "a") as f:
            f.write(str(pem_cert_body))

    logger.info("Updating CA trust")
    os.system(update_ca_cmd)
