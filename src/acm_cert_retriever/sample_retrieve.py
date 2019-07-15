#!/usr/bin/env python

"""Sample Certificate Retriever."""
import boto3
import configargparse
import logging
import sys
from Cryptodome.IO import PKCS8
from acm_common import logger_utils


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
            "/etc/acm_cert_helper/acm_cert_sample_retrieve.conf",
            "~/.config/acm_cert_helper/acm_cert_sample_retrieve.conf",
        ]
    )

    p.add(
        "--acm-cert-arn",
        required=True,
        env_var="RETRIEVER_ACM_CERT_ARN",
        help="ARN in AWS ACM to use to fetch the required cert, key and certificate chain",
    )
    p.add(
        "--acm-cert-passphrase",
        required=True,
        env_var="RETRIEVER_ACM_CERT_PASSPHRASE",
        help="Passphrase to use to encrypt the downloaded key",
    )
    p.add(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        default="INFO",
        env_var="RETRIEVER_LOG_LEVEL",
        help="Logging level",
    )

    return p.parse_args(args)


def retrieve_key_and_cert(args, acm_util):
    """Download a key and certificate and certificate chain form ACM, and print them to the console.

    Also creates a Truststore with files from S3.

    Args:
        args (Object): The parsed command line arguments
        acm_util (Object): The boto3 utility to use

    Returns:
        all_data (Dict): THe json result, with the key encrypted by the passphrase
    """
    all_data = acm_util.export_certificate(CertificateArn=args.acm_cert_arn, Passphrase=args.acm_cert_passphrase)
    print("-------------")
    print("acm_cert_arn={}".format(args.acm_cert_arn))
    print("acm_cert_passphrase={}".format(args.acm_cert_passphrase))
    print("-------------")
    print(all_data['Certificate'])
    print("-------------")
    print(all_data['CertificateChain'])
    print("-------------")
    trimmed_key = all_data['PrivateKey'].trim()
    print(trimmed_key)
    print("-------------")

    # decrypted_key = RSA.importKey(all_data['PrivateKey'], passphrase=args.acm_cert_passphrase)
    # decrypted_key.decrypt(args.acm_cert_passphrase)

    decrypted_key = PKCS8.unwrap(p8_private_key=trimmed_key, passphrase=args.acm_cert_passphrase)

    print(decrypted_key)
    print("-------------")

    return all_data


def _main(args):
    args = parse_args(args)
    logger_utils.setup_logging(logger, args.log_level)
    retrieve_key_and_cert(args, acm_client)


def main():
    """Start of CLI script.

    This is called by setuptools entrypoint, so is not able to take any arguments.
    In order to support automated testing of CLI parsing, this just wraps _main()
    which enables args to be passed in.

    """
    _main(sys.argv[1:])


if __name__ == "__main__":
    main()
