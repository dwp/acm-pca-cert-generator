import OpenSSL
import boto3
import botocore.session
import configargparse
import jks
import logging
import pytest
from acm_pca_cert_generator import certgen
from botocore.stub import Stubber
from collections import Counter


def test_check_key_length_valid():
    assert certgen.check_key_length("2048") == 2048


def test_check_key_length_not_number():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_key_length("test")


def test_check_key_length_invalid_choice():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_key_length("1024")


def test_check_validity_period_valid():
    assert certgen.check_validity_period("365d") == "365d"
    assert certgen.check_validity_period("12m") == "12m"
    assert certgen.check_validity_period("1y") == "1y"


def test_check_validity_period_invalid():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_validity_period("52w")


def test_generate_private_key():
    pkey = certgen.generate_private_key("RSA", 2048)
    assert pkey.type() == OpenSSL.crypto.TYPE_RSA
    assert pkey.bits() == 2048


def test_generate_private_key_invalid_type():
    with pytest.raises(ValueError):
        pkey = certgen.generate_private_key("TSA", 2048)


def test_generate_private_key_invalid_length():
    with pytest.raises(TypeError):
        pkey = certgen.generate_private_key("RSA", "notanint")


valid_subject_details = {
    "C": "GB",
    "ST": "Yorkshire",
    "L": "Leeds",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


def test_generate_csr():
    pkey = certgen.generate_private_key("RSA", 2048)
    csr = certgen.generate_csr(pkey, "sha256", valid_subject_details)
    x509req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    name = x509req.get_subject().get_components()

    # Check that the subject details match
    assert Counter(name) == Counter(valid_subject_details.items())
    # Check that the CSR was signed with the right key
    assert x509req.verify(pkey)


def test_generate_csr_invalid_subject_details():
    invalid_subject_details = dict(valid_subject_details)
    pkey = certgen.generate_private_key("RSA", 2048)
    invalid_subject_details.pop("emailAddress")
    with pytest.raises(KeyError):
        csr = certgen.generate_csr(pkey, "sha256", invalid_subject_details)


def test_sign_cert():
    ca_arn = "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/506a130d-8519-45dc-903d-2a30709d6a33"
    stub_cert_arn = "{}/certificate/286535153982981100925020015808220737245".format(
        ca_arn
    )
    pkey = certgen.generate_private_key("RSA", 2048)
    csr = certgen.generate_csr(pkey, "sha256", valid_subject_details)
    signing_algo = "SHA384WITHRSA"
    validity = certgen.create_validity_dict("1d")

    acmpca = botocore.session.get_session().create_client("acm-pca")
    stubber = Stubber(acmpca)

    issue_cert_params = {
        "CertificateAuthorityArn": ca_arn,
        "Csr": csr,
        "SigningAlgorithm": signing_algo,
        "Validity": validity,
    }

    issue_cert_response = {"CertificateArn": stub_cert_arn}

    get_cert_params = {
        "CertificateArn": stub_cert_arn,
        "CertificateAuthorityArn": ca_arn,
    }

    get_cert_response = {
        "Certificate": "mycertstring",
        "CertificateChain": "mycertchainstring",
    }

    with Stubber(acmpca) as stubber:
        stubber.add_response(
            "issue_certificate", issue_cert_response, issue_cert_params
        )

        # boto3 waiters check HTTP status codes for success or failure but
        # botocore stubbers don't issue HTTP calls. The following mocks the
        # success of the waiter.wait() call by setting a client "error" up with
        # a success return code.
        stubber.add_client_error("get_certificate", http_status_code=200)
        stubber.add_response("get_certificate", get_cert_response, get_cert_params)
        stubber.activate()
        cert_chain = certgen.sign_cert(acmpca, ca_arn, csr, "SHA384WITHRSA", "1d")
        assert cert_chain == get_cert_response["CertificateChain"]


def generate_self_signed_cert(pkey):
    # Generate CSR
    x509req = OpenSSL.crypto.X509Req()
    subject = x509req.get_subject()
    subject_name_parts = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]
    for name_part in subject_name_parts:
        setattr(subject, name_part, valid_subject_details[name_part])
    x509req.set_pubkey(pkey)
    x509req.sign(pkey, "sha256")

    # Generate signed cert
    cert = OpenSSL.crypto.X509()
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
    cert.set_issuer(x509req.get_subject())
    cert.set_subject(x509req.get_subject())
    cert.set_pubkey(x509req.get_pubkey())
    cert.sign(pkey, "sha256")

    return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)


def test_generate_keystore():
    certgen.logger.setLevel(logging.DEBUG)
    keystore_path = "tests/tmp/keystore.jks"
    keystore_password = "password1"
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    priv_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
    cert_pem = generate_self_signed_cert(pkey)
    certgen.generate_keystore(
        keystore_path, keystore_password, priv_key, cert_pem, "testalias"
    )

    ks = jks.KeyStore.load(keystore_path, keystore_password)
    assert len(ks.private_keys.items()) == 1
