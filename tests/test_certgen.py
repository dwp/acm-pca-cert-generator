import OpenSSL
import botocore.session
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
