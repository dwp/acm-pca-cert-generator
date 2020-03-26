import unittest
from collections import namedtuple
from acm_pca_cert_generator import certgen

try:
    import mock
    from mock import MagicMock
except ImportError:
    from unittest import mock
    from unittest.mock import MagicMock


valid_subject_details = {
    "C": "GB",
    "ST": "MyCounty",
    "L": "MyCity",
    "O": "MyOrg",
    "OU": "MyOU",
    "CN": "myfqdn.example.com",
    "emailAddress": "joebloggs@example.com",
}


def make_tuple(some_args_dict):
    return namedtuple("DummyParsedArgs", some_args_dict.keys())(*some_args_dict.values())


template_args = {
    "subject_c": "my-country",
    "subject_st": "my-state",
    "subject_l": "my-city",
    "subject_o": "my-organisation",
    "subject_ou": "my-org",
    "subject_cn": "my-host",
    "subject_emailaddress": "my-email",
    "key_type": "my-keytype",
    "key_length": 123,
    "key_digest_algorithm": "my-digest-algorithm",
    "keystore_path": "my-keystore-path",
    "keystore_password": "my-keystore-password",
    "ca_arn": "my-ca-arn",
    "signing_algorithm" : "my-signing-algorithm",
    "validity_period": "my-validity-period",
    "private_key_alias": "my-key-alias",
    "private_key_password": "my-key-password",
    "truststore_path": "my-truststore-path",
    "truststore_password": "my-truststore-password",
    "truststore_aliases": "my-truststore-aliases",
    "truststore_certs": "my-truststore-certs",
    "jks_only": "true",
    "log_level": "ANY"
}

dummy_certs_data = [
    {"alias": "a1", "cert": "c1", "source": "s1"}
]

created_cert_data = {
    'Certificate': 'created-cert',
    'CertificateChain': 'created-chain'
}


class TestCertGen(unittest.TestCase):

    def test_generate_key_and_cert_will_use_acmpca_and_make_stores(self):
        # Given
        sample_args = make_tuple(template_args)

        acmpca_client = MagicMock()
        acmpca_client.create_certificate = MagicMock()

        s3_client = MagicMock()

        mock_truststore_utils = MagicMock()
        mock_truststore_utils.generate_truststore = MagicMock()
        mock_truststore_utils.generate_keystore = MagicMock()
        mock_truststore_utils.parse_trusted_cert_arg = MagicMock()
        mock_truststore_utils.add_cert_and_key = MagicMock()
        mock_truststore_utils.add_ca_certs = MagicMock()
        mock_truststore_utils.parse_trusted_cert_arg.return_value = dummy_certs_data

        mock_generate_private_key = MagicMock()
        mock_private_key = MagicMock()
        mock_generate_private_key.return_value = mock_private_key

        mock_generate_csr = MagicMock()
        mock_csr = MagicMock()
        mock_generate_csr.return_value = mock_csr

        mock_sign_cert = MagicMock()
        mock_sign_cert.return_value = created_cert_data

        # When
        certgen.generate_key_and_cert(
            acmpca_client, s3_client, mock_truststore_utils, sample_args,
            mock_generate_private_key, mock_generate_csr, mock_sign_cert
        )

        # Then
        mock_generate_private_key.assert_called_once_with("my-keytype", 123)

        mock_generate_csr.assert_called_once_with(
            mock_private_key,
            "my-digest-algorithm",
            {
                'C': 'my-country', 'ST': 'my-state', 'L': 'my-city', 'O': 'my-organisation',
                'OU': 'my-org', 'CN': 'my-host', 'emailAddress': 'my-email'
            }
        )

        mock_sign_cert.assert_called_once_with(
            acmpca_client, "my-ca-arn", mock_csr,
            "my-signing-algorithm", "my-validity-period")

        mock_truststore_utils.generate_keystore.assert_called_once_with(
            "my-keystore-path",
            "my-keystore-password",
            mock_private_key,
            ['created-cert'],
            "my-key-alias",
            "my-key-password"
        )

        mock_truststore_utils.generate_truststore.assert_called_once_with(
            s3_client,
            "my-truststore-path",
            "my-truststore-password",
            dummy_certs_data
        )
