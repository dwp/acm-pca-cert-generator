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
    "ST": "Yorkshire",
    "L": "Leeds",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


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
    certs = [
        {"alias": "myca1", "cert": "s3://certbucket/ca1.pem"},
        {"alias": "myca2", "cert": "s3://certbucket/ca2.pem"},
    ]

    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    trusted_cert_pem = _generate_self_signed_cert(pkey)
    get_object_params = {"Bucket": "certbucket", "Key": ANY}
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


def _generate_self_signed_cert(pkey):
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