import OpenSSL
import botocore.session
import io
import jks
import logging
import pytest
from acm_pca_cert_generator import certgen
from acm_common import truststore_utils
from botocore.stub import Stubber, ANY


valid_subject_details = {
    "C": "GB",
    "ST": "MyCounty",
    "L": "MyCity",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


def test_get_aws_certificate_chain():
    template_downloaded_data = {
        'Certificate': '-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----',
        'CertificateChain': '-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----\n'
                            '-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----\n'
                            '-----BEGIN CERTIFICATE-----\nCERT3\n-----END CERTIFICATE-----',
        'PrivateKey': '-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEY\n-----END ENCRYPTED PRIVATE KEY-----'
    }
    actual_chain = truststore_utils.get_aws_certificate_chain(template_downloaded_data)
    assert len(actual_chain) == 4
    assert actual_chain[0] == "-----BEGIN CERTIFICATE-----\nDOWNLOADED\n-----END CERTIFICATE-----"
    assert actual_chain[1] == "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----"
    assert actual_chain[2] == "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----"
    assert actual_chain[3] == "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----"


def test_parse_trusted_cert_arg():
    trust_aliases = "myca1,myca2"
    trust_certs = "s3://certbucket/ca1.pem,s3://certbucket/ca2.pem"
    certs = truststore_utils.parse_trusted_cert_arg(trust_aliases, trust_certs)
    assert len(certs) == 2
    assert certs[0]["alias"] == "myca1"
    assert certs[0]["cert"] == "s3://certbucket/ca1.pem"
    assert certs[1]["alias"] == "myca2"
    assert certs[1]["cert"] == "s3://certbucket/ca2.pem"


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
        keystore_path, keystore_password, priv_key, cert_pem, "testalias"
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
        truststore_utils.generate_truststore(s3, truststore_path, truststore_password, certs)
        ts = jks.KeyStore.load(truststore_path, truststore_password)
        assert len(ts.certs) == 2


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