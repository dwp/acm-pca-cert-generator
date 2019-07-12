#!/usr/bin/env python

"""Certificate Retriever."""
import OpenSSL
import boto3
import configargparse
import logging
import sys
from acm_common import logger_utils, truststore_utils

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


logger = logging.getLogger("retriever")


def parse_args(args):
    """Parse the supplied command line arguments.

    Returns:
        argparse.NameSpace: The parsed and validated command line arguments

    """
    p = configargparse.ArgParser(
        default_config_files=[
            "/etc/acm_cert_helper/acm_cert_retriever.conf",
            "~/.config/acm_cert_helper/acm_cert_retriever.conf",
        ]
    )

    p.add(
        "--acm-key-arn",
        required=True,
        env_var="RETRIEVER_ACM_KEY_ARN",
        help="ARN in AWS ACM to use to fetch the required key",
    )
    p.add(
        "--acm-cert-arn",
        required=True,
        env_var="RETRIEVER_ACM_CERT_ARN",
        help="ARN in AWS ACM to use to fetch the required certificate",
    )
    p.add(
        "--keystore-path",
        required=True,
        env_var="RETRIEVER_KEYSTORE_PATH",
        help="Filename of the keystore to save the signed keypair to",
    )
    p.add(
        "--keystore-password",
        required=True,
        env_var="RETRIEVER_KEYSTORE_PASSWORD",
        help="Password for the Java Keystore",
    )
    p.add(
        "--private-key-alias",
        required=True,
        env_var="RETRIEVER_PRIVATE_KEY_ALIAS",
        help="The alias to store the private key under in the Java KeyStore",
    )
    p.add(
        "--private-key-password",
        env_var="RETRIEVER_PRIVATE_KEY_PASSWORD",
        help="The password used to protect ",
    )
    p.add(
        "--truststore-path",
        required=True,
        env_var="RETRIEVER_TRUSTSTORE_PATH",
        help="Filename of the keystore to save trusted certificates to",
    )
    p.add(
        "--truststore-password",
        required=True,
        env_var="RETRIEVER_TRUSTSTORE_PASSWORD",
        help="Password for the Java TrustStore",
    )
    p.add(
        "--truststore-aliases",
        required=True,
        env_var="RETRIEVER_TRUSTSTORE_ALIASES",
        help="Comma-separated list of aliases to use for entries in the Java TrustStore",
    )
    p.add(
        "--truststore-certs",
        required=True,
        env_var="RETRIEVER_TRUSTSTORE_CERTS",
        help="Comma-separated list of S3 URIs pointing at certificates to be "
        "added to the Java TrustStore",
    )
    p.add(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        default="INFO",
        env_var="RETRIEVER_LOG_LEVEL",
        help="Logging level",
    )

    return p.parse_args(args)


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


def retrieve_acm_data(acm_client, aws_acm_arn):
    """Download the relevant information from ACM.

    See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.get_certificate

    Args:
        acm_client (Object): The ACM utility to call
        aws_acm_arn (str): The ARN that identifies a stored credential in ACM.

    Returns:
        dict: A {"arn": "string", "data": "string"} dict representing the
              S3 object identified by the given URL

    """
    return {
        "arn": "your arn",
        "data": {
            'Certificate': "your cert",
            'CertificateChain': "your cert chain"
            }
        }


def _main(args):
    args = parse_args(args)
    logger_utils.setup_logging(logger, args.log_level)

    acm_client = boto3.client("acm")
    key_data = retrieve_acm_data(acm_client, args.acm_key_arn)
    cert_and_chain = retrieve_acm_data(acm_client, args.acm_cert_arn)

    truststore_utils.generate_keystore(
        args.keystore_path,
        args.keystore_password,
        key_data.data,
        cert_and_chain.data,
        args.private_key_alias,
        args.private_key_password,
    )

    trusted_certs = truststore_utils.parse_trusted_cert_arg(
        args.truststore_aliases, args.truststore_certs
    )

    # When we know whether or not to add the ACM chain, we'd do something like this
    # trusted_certs.add (
    #   {"alias": "aws-cert", "cert": cert_and_chain["CertificateChain"] } )

    s3_client = boto3.client("s3")
    truststore_utils.generate_truststore(
        s3_client, args.truststore_path, args.truststore_password, trusted_certs
    )


def main():
    """Start of CLI script.

    This is called by setuptools entrypoint, so is not able to take any arguments.
    In order to support automated testing of CLI parsing, this just wraps _main()
    which enables args to be passed in.

    """
    _main(sys.argv[1:])


if __name__ == "__main__":
    main()
