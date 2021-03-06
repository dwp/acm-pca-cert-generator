import OpenSSL
import botocore.session
import os
import io
import jks
import logging
import pytest
from acm_pca_cert_generator import certgen
from acm_common import truststore_utils
from botocore.stub import Stubber, ANY

try:
    import mock
    from mock import MagicMock
    from mock import call
except ImportError:
    from unittest import mock
    from unittest.mock import MagicMock
    from unittest.mock import call


valid_subject_details = {
    "C": "GB",
    "ST": "MyCounty",
    "L": "MyCity",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


def test_get_aws_certificate_chain_with_no_entries():
    template_downloaded_data = {
        "Certificate": "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----",
        "CertificateChain": "",
        "PrivateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEY\n-----END ENCRYPTED PRIVATE KEY-----",
    }
    actual_chain = truststore_utils.get_aws_certificate_chain(template_downloaded_data)
    assert len(actual_chain) == 1
    assert (
        actual_chain[0]
        == "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----"
    )


def test_get_aws_certificate_chain_with_single_entry():
    template_downloaded_data = {
        "Certificate": "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----",
        "CertificateChain": "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----",
        "PrivateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEY\n-----END ENCRYPTED PRIVATE KEY-----",
    }
    actual_chain = truststore_utils.get_aws_certificate_chain(template_downloaded_data)
    assert len(actual_chain) == 2
    assert (
        actual_chain[0]
        == "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----"
    )
    assert (
        actual_chain[1]
        == "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----"
    )


def test_get_aws_certificate_chain_with_multiple_entries():
    template_downloaded_data = {
        "Certificate": "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----",
        "CertificateChain": "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----\n"
        "-----BEGIN CERTIFICATE-----\nCERT3\n-----END CERTIFICATE-----",
        "PrivateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEY\n-----END ENCRYPTED PRIVATE KEY-----",
    }
    actual_chain = truststore_utils.get_aws_certificate_chain(template_downloaded_data)
    assert len(actual_chain) == 4
    assert (
        actual_chain[0]
        == "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----"
    )
    assert (
        actual_chain[1]
        == "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----"
    )
    assert (
        actual_chain[2]
        == "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----"
    )
    assert (
        actual_chain[3]
        == "-----BEGIN CERTIFICATE-----\nCERT3\n-----END CERTIFICATE-----"
    )


def test_parse_trusted_cert_arg():
    trust_aliases = "myca1,myca2"
    trust_certs = "s3://certbucket/ca1.pem,s3://certbucket/ca2.pem"
    certs = truststore_utils.parse_trusted_cert_arg(trust_aliases, trust_certs)
    assert len(certs) == 2
    assert certs[0]["alias"] == "myca1"
    assert certs[0]["cert"] == "s3://certbucket/ca1.pem"
    assert certs[1]["alias"] == "myca2"
    assert certs[1]["cert"] == "s3://certbucket/ca2.pem"


def test_command_exists_finds_path_that_exists():
    assert truststore_utils.command_exists("pytest") is True


def test_command_exists_does_not_find_path_that_does_not_exist():
    assert (
        truststore_utils.command_exists("definitely_not_likely_to_be_a_command")
        is False
    )


def test_command_exists_does_not_finds_path_that_is_not_executable():
    test_path = "/tmp"
    test_file = "test.txt"
    test_file_and_path = os.path.join(test_path, test_file)
    if os.path.exists(test_file_and_path):
        os.remove(test_file_and_path)

    with open(test_file_and_path, "a") as test_file_write:
        test_file_write.write("Test file contents")

    assert truststore_utils.command_exists(test_file, [test_path]) is False


def test_command_exists_does_not_finds_path_that_is_directory():
    test_path = "/tmp"
    test_directory = "dir"
    test_path_and_directory = os.path.join(test_path, test_directory)
    if not os.path.exists(test_path_and_directory):
        os.mkdir(test_path_and_directory)

    assert truststore_utils.command_exists(test_directory, [test_path]) is False


def test_parse_trusted_cert_arg_mismatched_lengths():
    trust_aliases = "myca1,myca2"
    trust_certs = "s3://certbucket"
    with pytest.raises(ValueError):
        truststore_utils.parse_trusted_cert_arg(trust_aliases, trust_certs)


def test_generate_keystore():
    certgen.logger.setLevel(logging.DEBUG)
    keystore_path = "tests/tmp/keystore.jks"
    keystore_password = "password1"
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    priv_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
    cert_pem = _generate_self_signed_cert(pkey)
    truststore_utils.generate_keystore(
        keystore_path, keystore_password, priv_key, [cert_pem], "testalias"
    )

    ks = jks.KeyStore.load(keystore_path, keystore_password)
    assert len(ks.private_keys.items()) == 1


def test_generate_truststore():
    truststore_path = "tests/tmp/truststore.jks"
    truststore_password = "password1"

    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    trusted_cert_pem = _generate_self_signed_cert(pkey)
    get_object_params = {"Bucket": "certbucket", "Key": ANY}

    certs = [
        {"alias": "myca1", "cert": "s3://certbucket/ca1.pem", "source": "s3"},
        {"alias": "myca2", "cert": trusted_cert_pem, "source": "memory"},
    ]

    s3 = botocore.session.get_session().create_client("s3")
    with Stubber(s3) as stubber:
        stubber.add_response(
            "get_object", {"Body": io.BytesIO(trusted_cert_pem)}, get_object_params
        )
        stubber.add_response(
            "get_object", {"Body": io.BytesIO(trusted_cert_pem)}, get_object_params
        )
        stubber.activate()
        truststore_utils.generate_truststore(
            s3, truststore_path, truststore_password, certs
        )
        ts = jks.KeyStore.load(truststore_path, truststore_password)
        assert len(ts.certs) == 2


def test_retrieve_key_and_cert_retryable_will_call_cert_utils():
    # Given
    acm_client = MagicMock()
    acm_client.export_certificate = MagicMock()
    acm_client.export_certificate.return_value = "data-downloaded"

    # When
    truststore_utils.retrieve_key_and_cert_retryable(
        acm_client, "test-arn", "test-passphrase"
    )

    # Then
    acm_client.export_certificate.assert_called_once_with(
        CertificateArn="test-arn", Passphrase="test-passphrase"
    )


def test_retrieve_key_and_cert_retryable_will_retry():
    # Given
    os.environ["RETRYABLE_EXPORT_MAX_ATTEMPTS"] = "3"
    os.environ["RETRYABLE_EXPORT_BACKOFF_MILLIS"] = "1"
    os.environ["RETRYABLE_EXPORT_MAX_BACKOFF_MILLIS"] = "10"

    acm_client = MagicMock()
    acm_client.export_certificate = MagicMock()
    acm_client.export_certificate.side_effect = [
        Exception("Bad1"),
        Exception("Bad2"),
        "success",
    ]

    # When
    truststore_utils.retrieve_key_and_cert_retryable(
        acm_client, "test-arn", "test-passphrase"
    )

    # Then
    calls = [
        call(CertificateArn="test-arn", Passphrase="test-passphrase"),
        call(CertificateArn="test-arn", Passphrase="test-passphrase"),
        call(CertificateArn="test-arn", Passphrase="test-passphrase"),
    ]
    acm_client.export_certificate.assert_has_calls(calls)

    # Cleanup
    del os.environ["RETRYABLE_EXPORT_MAX_ATTEMPTS"]
    del os.environ["RETRYABLE_EXPORT_BACKOFF_MILLIS"]
    del os.environ["RETRYABLE_EXPORT_MAX_BACKOFF_MILLIS"]


def _generate_self_signed_cert(private_key):
    # Generate CSR
    x509req = OpenSSL.crypto.X509Req()
    subject = x509req.get_subject()
    subject_name_parts = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]
    for name_part in subject_name_parts:
        setattr(subject, name_part, valid_subject_details[name_part])
    x509req.set_pubkey(private_key)
    x509req.sign(private_key, "sha256")

    # Generate signed cert
    cert = OpenSSL.crypto.X509()
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
    cert.set_issuer(x509req.get_subject())
    cert.set_subject(x509req.get_subject())
    cert.set_pubkey(x509req.get_pubkey())
    cert.sign(private_key, "sha256")

    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
