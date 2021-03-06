#!/usr/bin/env python

"""Certificate Generator."""
import OpenSSL
import boto3
import configargparse
import logging
import os
import re
import sys
from acm_common import logger_utils, truststore_utils


logger = logging.getLogger("certgen")
subject_name_parts = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]
pem_type = OpenSSL.crypto.FILETYPE_PEM


def str2bool(v):
    """Parse the supplied command line arguments into a boolean.

    Returns:
        Boolean: The parsed and validated command line arguments. Defaults to False.

    """
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "1"):
        return True
    elif v.lower() in ("no", "false", "0"):
        return False
    else:
        raise configargparse.ArgumentTypeError("Boolean value expected.")


def check_key_length(value):
    """Check that a valid key length has been provided.

    Args:
        value (str): The command line argument provided by the user

    Returns:
        int: The key length

    Raises:
        configargparse.ArgumentError: If the supplied key length was invalid

    """
    valid_key_lengths = [2048, 4096, 8192]
    try:
        new_value = int(value)
    except Exception:
        raise configargparse.ArgumentTypeError(
            "{} is an invalid key length. Must be an integer.".format(value)
        )
    if new_value not in valid_key_lengths:
        raise configargparse.ArgumentTypeError(
            "{} is an invalid key length. Must be either 2048, 4096 or 8192.".format(
                value
            )
        )
    return new_value


def check_validity_period(value):
    """Check that a valid certificate validity period has been provided.

    Args:
        value (str): The command line argument provided by the user

    Returns:
        str: The validated validity period

    Raises:
        configargparse.ArgumentError: If the supplied validity period was invalid.

    """
    pattern = re.compile("[1-9][0-9]*[dmy]$")
    if not pattern.search(value):
        raise configargparse.ArgumentTypeError(
            "{} is an invalid validity period. Must be in the form "
            "<number><unit>, e.g. 1d for 1 day, 1m for 1 month or 1y for 1 "
            "year".format(value)
        )
    return value


def check_subject_cn(value):
    """Check that either the Subject CN was given, or HOSTNAME is set in the environment.

    Args:
        value (str): The command line argument provided by the user

    Returns:
        str: The given Subject CN, or HOSTNAME

    Raises:
        configargpase.ArgumentTypeError: If neither the Subject CN or HOSTNAME is present.

    """
    if not value and "HOSTNAME" not in os.environ:
        raise configargparse.ArgumentTypeError(
            "You must provide either --subject-cn or the HOSTNAME environment variable"
        )
    if not value:
        value = os.environ["HOSTNAME"]
    return value


def parse_args(args):
    """Parse the supplied command line arguments.

    Returns:
        argparse.NameSpace: The parsed and validated command line arguments

    """
    p = configargparse.ArgParser(
        default_config_files=[
            "/etc/acm_cert_helper/acm_pca_cert_generator.conf",
            "~/.config/acm_cert_helper/acm_pca_cert_generator.conf",
        ]
    )

    p.add(
        "--key-type",
        choices=["RSA", "DSA"],
        required=True,
        env_var="CERTGEN_KEY_TYPE",
        help="The key type",
    )
    p.add(
        "--key-length",
        type=check_key_length,
        required=True,
        env_var="CERTGEN_KEY_LENGTH",
        help="The key length in bits",
    )
    p.add(
        "--key-digest-algorithm",
        choices=["sha256", "sha384", "sha512"],
        default="sha384",
        env_var="CERTGEN_KEY_DIGEST",
        help="The key digest algorithm",
    )
    p.add(
        "--subject-c",
        required=True,
        env_var="CERTGEN_SUBJECT_C",
        help="Certificate subject country",
    )
    p.add(
        "--subject-st",
        required=True,
        env_var="CERTGEN_SUBJECT_ST",
        help="Certificate subject state/province/county",
    )
    p.add(
        "--subject-l",
        required=True,
        env_var="CERTGEN_SUBJECT_L",
        help="Certificate subject locality (city/town)",
    )
    p.add(
        "--subject-o",
        required=True,
        env_var="CERTGEN_SUBJECT_O",
        help="Certificate subject organisation",
    )
    p.add(
        "--subject-ou",
        required=True,
        env_var="CERTGEN_SUBJECT_OU",
        help="Certificate subject organisational unit",
    )
    p.add(
        "--subject-cn",
        type=check_subject_cn,
        required=False,
        env_var="CERTGEN_SUBJECT_CN",
        help="Certificate subject common name (defaults to $HOSTNAME)",
    )
    p.add(
        "--subject-emailaddress",
        required=True,
        env_var="CERTGEN_SUBJECT_EMAILADDRESS",
        help="Certificate subject email address",
    )
    p.add("--ca-arn", required=True, env_var="CERTGEN_CA_ARN", help="ACM PCA ARN")
    p.add(
        "--signing-algorithm",
        choices=[
            "SHA256WITHECDSA",
            "SHA384WITHECDSA",
            "SHA512WITHECDSA",
            "SHA256WITHRSA",
            "SHA384WITHRSA",
            "SHA512WITHRSA",
        ],
        required=True,
        env_var="CERTGEN_SIGNING_ALGORITHM",
        help="The algorithm that ACM PCA will use to sign the certificate",
    )
    p.add(
        "--validity-period",
        required=True,
        type=check_validity_period,
        env_var="CERTGEN_VALIDITY_PERIOD",
        help="How long the certificate is valid for, e.g. 1d, 1m, 1y for 1 day, "
        "1 month and 1 year respectively",
    )
    p.add(
        "--keystore-path",
        required=False,
        env_var="CERTGEN_KEYSTORE_PATH",
        help="Filename for the Java Keystore",
    )
    p.add(
        "--keystore-password",
        required=False,
        env_var="CERTGEN_KEYSTORE_PASSWORD",
        help="Password for the Java Keystore",
    )
    p.add(
        "--private-key-alias",
        required=True,
        env_var="CERTGEN_PRIVATE_KEY_ALIAS",
        help="The alias to store the private key under in the Java KeyStore",
    )
    p.add(
        "--private-key-password",
        env_var="CERTGEN_PRIVATE_KEY_PASSWORD",
        help="The password used to protect the private key in the Java KeyStore",
    )
    p.add(
        "--truststore-path",
        required=False,
        env_var="CERTGEN_TRUSTSTORE_PATH",
        help="Filename of the Java TrustStore",
    )
    p.add(
        "--truststore-password",
        required=False,
        env_var="CERTGEN_TRUSTSTORE_PASSWORD",
        help="Password for the Java TrustStore",
    )
    p.add(
        "--truststore-aliases",
        required=True,
        env_var="CERTGEN_TRUSTSTORE_ALIASES",
        help="Comma-separated list of aliases to use for entries in the Java TrustStore",
    )
    p.add(
        "--truststore-certs",
        required=True,
        env_var="CERTGEN_TRUSTSTORE_CERTS",
        help="Comma-separated list of S3 URIs pointing at certificates to use for "
        "entries in the Java TrustStore",
    )
    p.add(
        "--jks-only",
        default=False,
        type=str2bool,
        env_var="CERTGEN_JKS_ONLY",
        help="Only generate the Java KeyStores; don't update the OS trustchains "
        "(which requires this utility to be run as root)",
    )
    p.add(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        default="INFO",
        env_var="CERTGEN_LOG_LEVEL",
        help="Logging level",
    )

    return p.parse_args(args)


def generate_private_key(key_type, key_bits):
    """Generate a private SSL key.

    Args:
        key_type (str): The type of key to generate (RSA, DSA)
        key_bits (int): The length of the key

    Returns:
        bytes: The PEM-encoded private key

    """
    logger.info("Generating private key")
    key = OpenSSL.crypto.PKey()
    if key_type == "RSA":
        openssl_key_type = OpenSSL.crypto.TYPE_RSA
    elif key_type == "DSA":
        openssl_key_type = OpenSSL.crypto.TYPE_DSA
    else:
        raise ValueError(
            "Invalid value for key_type. Only 'RSA' and 'DSA' are supported."
        )
    key.generate_key(openssl_key_type, key_bits)
    private_key = OpenSSL.crypto.dump_privatekey(pem_type, key)
    logger.info("Private key generated")
    return private_key


def generate_csr(key, digest, subject_details):
    """Generate a certificate signing request.

    Args:
        key (bytes): The PEM-encoded private key to sign the CSR with
        digest (str): The name of the message digest to use for the signature
        subject_details (dict): A dict containing all of the certificate subject's
                                details. Must contain keys "C", ST", "L", "O", "OU",
                                "CN", "emailAddress"

    Return:
        bytes: The PEM-encoded CSR

    Raises:
        KeyError: If subject_details doesn't contain all of the required keys

    """
    logger.info("Generating Certificate Signing Request")
    csr = OpenSSL.crypto.X509Req()
    subject = csr.get_subject()

    for name_part in subject_name_parts:
        setattr(subject, name_part, subject_details[name_part])

    pkey = OpenSSL.crypto.load_privatekey(pem_type, key)
    csr.set_pubkey(pkey)
    csr.sign(pkey, digest)

    signing_result = OpenSSL.crypto.dump_certificate_request(pem_type, csr)
    logger.info("Certificate Signing Request done")
    return signing_result


def create_validity_dict(validity_period):
    """Convert a validity period string into a dict for issue_certificate().

    Args:
        validity_period (str): How long the signed certificate should be valid for

    Returns:
        dict: A dict {"Value": number, "Type": "string" } representation of the
              validity period

    """
    validity_suffix = validity_period[-1:]
    if validity_suffix == "d":
        validity_unit = "DAYS"
    elif validity_suffix == "m":
        validity_unit = "MONTHS"
    elif validity_suffix == "y":
        validity_unit = "YEARS"

    return {"Value": int(validity_period[:-1]), "Type": validity_unit}


def sign_cert(acmpca_client, ca_arn, csr, signing_algo, validity_period):
    """Sign a CSR using ACM PCA.

    Args:
        acmpca_client: boto3 ACM PCA client
        ca_arn (str): The ARN of the ACM PCA resource to sign the CSR with
        csr (str): The PEM-encoded CSR
        signing_algo (str): The algorithm to sign the CSR with
        validity_period (str): How long the signed certificate should be valid for

    Returns:
        str: The base64 PEM-encoded certificate and certificate chain of the signed CSR

    """
    logger.info("Requesting cert to be signed by ACM PCA")
    cert_arn = acmpca_client.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm=signing_algo,
        Validity=create_validity_dict(validity_period),
    )["CertificateArn"]

    logger.info("Waiting for cert to be signed by ACM PCA")
    waiter = acmpca_client.get_waiter("certificate_issued")
    waiter.wait(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)

    logger.info("Retrieving signed cert from ACM PCA")
    aws_result = acmpca_client.get_certificate(
        CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn
    )
    logger.info("Cert signing done by ACM PCA")
    return aws_result


def gather_subjects(args):
    """Create a dictionary of the subjects for the CSR.

    Args:
        args (Object): The parsed arguments

    Returns:
        Dict: The gathered subjects

    """
    subject_details = {}
    for name_part in subject_name_parts:
        name = "subject_{}".format(name_part.lower())
        subject_details[name_part] = getattr(args, name)

    return subject_details


def generate_key_and_cert(
    acmpca_util,
    s3_util,
    truststore_util,
    args,
    fn_generate_private_key,
    fn_generate_csr,
    fn_sign_cert,
):
    """Generate a key and cert in ACM PCA.

    Args:
        acmpca_util (Object): The boto3 utility to use
        s3_util (Object): The boto3 utility to use
        truststore_util (Object): The utility package to pass the data to
        args (Object): The parsed command line arguments,
        fn_generate_private_key (Function): Function pointer,
        fn_generate_csr (Function): Function pointer,
        fn_sign_cert (Function): Function pointer
    """
    key = fn_generate_private_key(args.key_type, args.key_length)

    subject_details = gather_subjects(args)
    csr = fn_generate_csr(key, args.key_digest_algorithm, subject_details)

    cert_and_chain = fn_sign_cert(
        acmpca_util, args.ca_arn, csr, args.signing_algorithm, args.validity_period
    )

    if (args.keystore_path is not None) and (args.truststore_path is not None):
        generate_key_and_trust_store(
            s3_util, truststore_util, args, key, cert_and_chain
        )

    if not args.jks_only:
        update_os_ca_trust(s3_util, truststore_util, args, key, cert_and_chain)


def update_os_ca_trust(s3_util, truststore_util, args, key, cert_and_chain):
    """Place generated key and cert in OS CA trust.

    Args:
        s3_util (Object): The boto3 utility to use
        truststore_util (Object): The utility package to pass the data to
        args (Object): The parsed command line arguments
        key (Object): The generated private key
        cert_and_chain (Object): The generated certificate chain
    """
    truststore_util.add_cert_and_key(
        key, [cert_and_chain["Certificate"]], args.private_key_alias
    )

    trusted_certs = truststore_util.parse_trusted_cert_arg(
        args.truststore_aliases, args.truststore_certs
    )

    truststore_util.add_ca_certs(s3_util, trusted_certs)


def generate_key_and_trust_store(s3_util, truststore_util, args, key, cert_and_chain):
    """Place generated key and cert in keystore and truststore.

    Args:
        s3_util (Object): The boto3 utility to use
        truststore_util (Object): The utility package to pass the data to
        args (Object): The parsed command line arguments
        key (Object): The generated private key
        cert_and_chain (Object): The generated certificate chain
    """
    truststore_util.generate_keystore(
        args.keystore_path,
        args.keystore_password,
        key,
        [cert_and_chain["Certificate"]],
        args.private_key_alias,
        args.private_key_password,
    )

    trusted_certs = truststore_util.parse_trusted_cert_arg(
        args.truststore_aliases, args.truststore_certs
    )

    truststore_util.generate_truststore(
        s3_util, args.truststore_path, args.truststore_password, trusted_certs
    )


def _main(args):
    args = parse_args(args)
    logger_utils.setup_logging(logger, args.log_level)

    acmpca_client = boto3.client("acm-pca")
    s3_client = boto3.client("s3")
    generate_key_and_cert(
        acmpca_client,
        s3_client,
        truststore_utils,
        args,
        generate_private_key,
        generate_csr,
        sign_cert,
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
