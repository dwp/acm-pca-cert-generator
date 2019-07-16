#!/usr/bin/env python

"""Certificate Retriever."""
import boto3
import configargparse
import logging
import sys
from acm_common import logger_utils, truststore_utils


logger = logging.getLogger("retriever")
acm_client = boto3.client("acm")
s3_client = boto3.client("s3")


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


def retrieve_key_and_cert(args, acm_util, s3_util, truststore_util):
    """Download a key and certificate chain form ACM, and puts them in a Keystore.

    Also creates a Truststore with files from S3.

    Args:
        args (Object): The parsed command line arguments
        acm_util (Object): The boto3 utility to use
        s3_util (Object): The boto3 utility to use
        truststore_util (Object): The utility package to pass the data to

    """
    cert_and_key_data = acm_util.get_certificate(CertificateArn=args.acm_key_arn)

    truststore_util.generate_keystore(
        args.keystore_path,
        args.keystore_password,
        cert_and_key_data['PrivateKey'],
        cert_and_key_data['Certificate'],
        args.private_key_alias,
        args.private_key_password,
    )

    trusted_certs = truststore_util.parse_trusted_cert_arg(
        args.truststore_aliases, args.truststore_certs
    )

    # When we know whether or not to add the ACM chain, we'd do something like this
    # trusted_certs.add (
    #   {"alias": "aws-cert", "cert": cert_and_key_data["CertificateChain"] } )

    truststore_util.generate_truststore(
        s3_util, args.truststore_path, args.truststore_password, trusted_certs
    )


def _main(args):
    args = parse_args(args)
    logger_utils.setup_logging(logger, args.log_level)
    retrieve_key_and_cert(args, acm_client, s3_client, truststore_utils)


def main():
    """Start of CLI script.

    This is called by setuptools entrypoint, so is not able to take any arguments.
    In order to support automated testing of CLI parsing, this just wraps _main()
    which enables args to be passed in.

    """
    _main(sys.argv[1:])


if __name__ == "__main__":
    main()
