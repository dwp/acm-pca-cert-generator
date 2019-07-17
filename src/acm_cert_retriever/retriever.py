#!/usr/bin/env python

"""Certificate Retriever."""
import boto3
import configargparse
import logging
import sys
from Cryptodome.PublicKey import RSA
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
        "--acm-cert-arn",
        required=True,
        env_var="RETRIEVER_ACM_CERT_ARN",
        help="ARN in AWS ACM to use to fetch the required cert, cert chain, and key",
    )
    p.add(
        "--acm-key-passphrase",
        required=True,
        env_var="RETRIEVER_ACM_KEY_PASSPHRASE",
        help="Passphrase to use to encrypt the downloaded key",
    )
    p.add(
        "--add-downloaded-chain-to-truststore",
        choices=["true", "false"],
        default="false",
        env_var="RETRIEVER_ADD_DOWNLOADED_CHAIN",
        help="Whether or not to add the downloaded cert chain from the ARN "
             "to the trust store",
    )
    p.add(
        "--keystore-path",
        required=True,
        env_var="RETRIEVER_KEYSTORE_PATH",
        help="Filename to create for the Java Keystore",
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
        help="The alias to use to store the private key in the Java KeyStore",
    )
    p.add(
        "--private-key-password",
        env_var="RETRIEVER_PRIVATE_KEY_PASSWORD",
        help="The password used to protect the private key in the Java KeyStore",
    )
    p.add(
        "--truststore-path",
        required=True,
        env_var="RETRIEVER_TRUSTSTORE_PATH",
        help="Filename to create for the Java TrustStore",
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
        help="Comma-separated list of S3 URIs pointing at certificates to use for "
             "entries in the Java TrustStore",
    )
    p.add(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        default="INFO",
        env_var="RETRIEVER_LOG_LEVEL",
        help="Logging level",
    )

    return p.parse_args(args)


def retrieve_key_and_cert(acm_util, rsa_util, acm_cert_arn, acm_key_passphrase):
    """Download a key and certificate and certificate chain form ACM.

    Args:
        acm_util (Object): The boto3 utility to use
        rsa_util (Object): The Crypto RSA utility to use
        acm_cert_arn (String): ARN of the certificate to export
        acm_key_passphrase (String): temporary password to use for key encryption

    Returns:
        Dict: The json result, with the key decrypted

    Raises:
        Error: If the export request fails

    """
    logger.info("Retrieving cert and key from AWS...")
    try:
        all_data = acm_util.export_certificate(
            CertificateArn=acm_cert_arn, Passphrase=acm_key_passphrase)
    except Exception as e:
        logger.exception("Failed to fetch {}: Error = {}".format(acm_cert_arn, e))
        raise e
    else:
        logger.info("...cert and key exported from AWS")

    encrypted_key = rsa_util.import_key(all_data['PrivateKey'], acm_key_passphrase)
    decrypted_key = encrypted_key.export_key()
    all_data['PrivateKey'] = decrypted_key

    logger.info("Retrieved cert and key from AWS and decrypted the key")
    return all_data


def create_stores(args, cert_and_key_data, s3_util, truststore_util):
    """Create a Keystore and Truststore.

    Also creates a Truststore with files from S3.
    Optionally adds the downloaded cert chain into the TrustStore.

    Args:
        args (Object): The parsed command line arguments
        cert_and_key_data (Dict): A json with the cert, cert chain, and decrypted key
        s3_util (Object): The boto3 utility to use
        truststore_util (Object): The utility package to pass the data to

    Returns:
        Dict: The json result, with the key in plain text

    """
    logger.info("Creating KeyStore and TrustStore")

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

    # When we know whether or not to add our own ACM chain, we'd do something like this:
    if args.add_downloaded_chain_to_truststore == "true":
        trusted_certs.append({
            "alias": "aws-cert-chain",
            "cert": cert_and_key_data["CertificateChain"],
            "source": "memory"})

    truststore_util.generate_truststore(
        s3_util, args.truststore_path, args.truststore_password, trusted_certs
    )
    logger.info("Created KeyStore and TrustStore")


def retrieve_key_and_cert_and_make_stores(acm_util, s3_util, truststore_util,
                                          rsa_util, args):
    """Create a Keystore and Truststore from AWS data.

    Args:
        acm_util (Object): The boto3 utility to use
        s3_util (Object): The boto3 utility to use
        truststore_util (Object): The utility package to pass the data to
        rsa_util (Object): The Crypto RSA utility to use
        args (Object): The parsed command line arguments

    """
    cert_and_key = retrieve_key_and_cert(acm_util,
                                         rsa_util,
                                         args.acm_cert_arn,
                                         args.acm_key_passphrase)
    create_stores(args, cert_and_key, s3_util, truststore_util)


def _main(args):
    args = parse_args(args)
    logger_utils.setup_logging(logger, args.log_level)
    retrieve_key_and_cert_and_make_stores(acm_client,
                                          s3_client,
                                          truststore_utils,
                                          RSA,
                                          args)


def main():
    """Start of CLI script.

    This is called by setuptools entrypoint, so is not able to take any arguments.
    In order to support automated testing of CLI parsing, this just wraps _main()
    which enables args to be passed in.

    """
    _main(sys.argv[1:])


if __name__ == "__main__":
    main()
