import OpenSSL
import botocore.session
import pytest
import unittest
from collections import namedtuple
from acm_pca_cert_generator import certgen
from botocore.stub import Stubber

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
    "ST": "Yorkshire",
    "L": "Leeds",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


def make_tuple(some_args_dict):
    return namedtuple("DummyParsedArgs", some_args_dict.keys())(*some_args_dict.values())


subject_args = {
    "subject_c": "city",
    "subject_st": "s",
    "subject_l": "l",
    "subject_o": "o",
    "subject_ou": "ou",
    "subject_cn": "cn",
    "subject_emailaddress": "email"
}


class TestRetriever(unittest.TestCase):

    def test_gather_subjects(self):
        sample_args = make_tuple(subject_args)
        result = certgen.gather_subjects(sample_args)
        self.assertEqual(
            result,
            {
                'C': 'city', 'CN': 'cn', 'L': 'l', 'O': 'o', 'OU': 'ou', 'ST': 's',
                'emailAddress': 'email'
            })

    def test_generate_private_key(self):
        key = certgen.generate_private_key("RSA", 2048)
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        self.assertEqual(pkey.type(), OpenSSL.crypto.TYPE_RSA)
        self.assertEqual(pkey.bits(), 2048)

    def test_generate_private_key_invalid_type(self):
        with pytest.raises(ValueError):
            certgen.generate_private_key("TSA", 2048)

    def test_generate_private_key_invalid_length(self):
        with pytest.raises(TypeError):
            certgen.generate_private_key("RSA", "notanint")

    def test_generate_csr(self):
        key = certgen.generate_private_key("RSA", 2048)
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        csr = certgen.generate_csr(key, "sha256", valid_subject_details)
        x509req = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
        name = x509req.get_subject().get_components()

        # Check that the subject details match

        self.assertEqual(len(name), len(valid_subject_details.items()))
        # Check that the CSR was signed with the right key
        self.assertTrue(x509req.verify(pkey))

    def test_generate_csr_invalid_subject_details(self):
        invalid_subject_details = dict(valid_subject_details)
        pkey = certgen.generate_private_key("RSA", 2048)
        invalid_subject_details.pop("emailAddress")
        with pytest.raises(KeyError):
            certgen.generate_csr(pkey, "sha256", invalid_subject_details)

    def test_sign_cert_happy_case(self):
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

        self.assertEqual(cert_chain, get_cert_response)

    def test_sign_cert_end_to_end(self):
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

        self.assertEqual(cert_chain, get_cert_response)

#    @mock.patch('acm_common.truststore_utils.parse_trusted_cert_arg')
#    @mock.patch('acm_common.truststore_utils.generate_keystore')
#    @mock.patch('acm_common.truststore_utils.generate_truststore')
#    @mock.patch('acm_cert_retriever.retriever.logger')
#    def test_generate_key_and_cert_will_use_acmpca_and_make_stores(self):
#
#        # generate_key_and_cert(acmpca_client, s3_client, truststore_utils, args)
#        assert True
#