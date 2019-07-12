import OpenSSL
import botocore.session
import configargparse
import os
import pytest
from acm_pca_cert_generator import certgen
from botocore.stub import Stubber


valid_subject_details = {
    "C": "GB",
    "ST": "Yorkshire",
    "L": "Leeds",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


def test_parse_args_for_certgen_will_return_valid_args_when_given_correct_list():
    args = """
        --key-type DSA
        --key-length 8192
        --key-digest-algorithm sha512
        --subject-c A
        --subject-st B
        --subject-l C
        --subject-o D
        --subject-ou E
        --subject-emailaddress F
        --ca-arn G
        --signing-algorithm SHA512WITHRSA
        --validity-period 22y
        --keystore-path H
        --keystore-password I
        --private-key-alias J
        --private-key-password K
        --truststore-path L 
        --truststore-password M
        --truststore-aliases N
        --truststore-certs O
        --log-level CRITICAL
    """

    result = certgen.parse_args(args)

    assert result.key_type == "DSA"
    assert result.key_length == 8192
    assert result.key_digest_algorithm == "sha512"
    assert result.subject_c == "A"
    assert result.subject_st == "B"
    assert result.subject_l == "C"
    assert result.subject_o == "D"
    assert result.subject_ou == "E"
    assert result.subject_emailaddress == "F"
    assert result.ca_arn == "G"
    assert result.signing_algorithm == "SHA512WITHRSA"
    assert result.validity_period == "22y"
    assert result.keystore_path == "H"
    assert result.keystore_password == "I"
    assert result.private_key_alias == "J"
    assert result.private_key_password == "K"
    assert result.truststore_path == "L"
    assert result.truststore_password == "M"
    assert result.truststore_aliases == "N"
    assert result.truststore_certs == "O"
    assert result.log_level == "CRITICAL"


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


def test_check_subject_cn_not_found():
    # Tox won't pass HOSTNAME through, so this tests for the case where both the
    # arg and environment variable are missing
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_subject_cn(None)


def test_check_subject_cn_blank_cn():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_subject_cn("")


def test_check_subject_cn_hostname_available():
    os.environ["HOSTNAME"] = "myfqdn.example.com"
    assert certgen.check_subject_cn(None) == "myfqdn.example.com"


def test_generate_private_key():
    key = certgen.generate_private_key("RSA", 2048)
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    assert pkey.type() == OpenSSL.crypto.TYPE_RSA
    assert pkey.bits() == 2048


def test_generate_private_key_invalid_type():
    with pytest.raises(ValueError):
        certgen.generate_private_key("TSA", 2048)


def test_generate_private_key_invalid_length():
    with pytest.raises(TypeError):
        certgen.generate_private_key("RSA", "notanint")


def test_generate_csr():
    key = certgen.generate_private_key("RSA", 2048)
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    csr = certgen.generate_csr(key, "sha256", valid_subject_details)
    x509req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    name = x509req.get_subject().get_components()

    # Check that the subject details match
    assert len(name) == len(valid_subject_details.items())
    # Check that the CSR was signed with the right key
    assert x509req.verify(pkey)


def test_generate_csr_invalid_subject_details():
    invalid_subject_details = dict(valid_subject_details)
    pkey = certgen.generate_private_key("RSA", 2048)
    invalid_subject_details.pop("emailAddress")
    with pytest.raises(KeyError):
        certgen.generate_csr(pkey, "sha256", invalid_subject_details)


def test_sign_cert():
    ca_arn = "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/506a130d-8519-45dc-903d-2a30709d6a33"
    stub_cert_arn = "{}/certificate/286535153982981100925020015808220737245".format(
        ca_arn
    )
    key = certgen.generate_private_key("RSA", 2048)
    csr = certgen.generate_csr(key, "sha256", valid_subject_details)
    signing_algo = "SHA384WITHRSA"
    validity = certgen.create_validity_dict("1d")

    acmpca = botocore.session.get_session().create_client("acm-pca")

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
        assert cert_chain == get_cert_response


def test_end_to_end():
    key = certgen.generate_private_key("RSA", 2048)
    pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)

    csr = certgen.generate_csr(key, "sha256", valid_subject_details)
    x509req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)

    cert = OpenSSL.crypto.X509()
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
    cert.set_issuer(x509req.get_subject())
    cert.set_subject(x509req.get_subject())
    cert.set_pubkey(x509req.get_pubkey())
    cert.sign(pkey, "sha256")
    signed_cert = str(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    )

    ca_arn = "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/506a130d-8519-45dc-903d-2a30709d6a33"
    stub_cert_arn = "{}/certificate/286535153982981100925020015808220737245".format(
        ca_arn
    )

    signing_algo = "SHA384WITHRSA"
    validity = certgen.create_validity_dict("1d")

    acmpca = botocore.session.get_session().create_client("acm-pca")

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

    get_cert_response = {"Certificate": signed_cert, "CertificateChain": signed_cert}

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
        assert cert_chain == get_cert_response
