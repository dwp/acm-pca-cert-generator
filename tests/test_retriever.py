import unittest
from collections import namedtuple
from acm_common import truststore_utils
from acm_cert_retriever import retriever
try:
    import mock
    from mock import MagicMock
    from mock import call
except ImportError:
    from unittest import mock
    from unittest.mock import MagicMock
    from unittest.mock import call

sample_args = {
    "acm_cert_arn": "my-cert-arn",
    "acm_key_passphrase": "my-key-passphrase",
    "keystore_path": "my-keystore-path",
    "keystore_password": "my-keystore-password",
    "private_key_alias": "my-key-alias",
    "private_key_password": "my-key-password",
    "truststore_path": "my-truststore-path",
    "truststore_password": "my-truststore-password",
    "truststore_aliases": "my-truststore-alias",
    "truststore_certs": "my-truststore-certs",
    "log_level": "ANY"
}
dummy_args = namedtuple("Employee", sample_args.keys())(*sample_args.values())

downloaded_data = {
    'Certificate': 'result-cert',
    'CertificateChain': 'result-chain',
    'PrivateKey': 'encrypted-key'
}

result_data = {
    'Certificate': 'result-cert',
    'CertificateChain': 'result-chain',
    'PrivateKey': 'decrypted-key'
}


class TestRetriever(unittest.TestCase):

    @mock.patch('acm_common.truststore_utils.parse_trusted_cert_arg')
    @mock.patch('acm_common.truststore_utils.generate_keystore')
    @mock.patch('acm_common.truststore_utils.generate_truststore')
    def test_retrieve_key_and_cert_will_generate_keystore_and_truststore_from_acm_data(
            self,
            mocked_generate_truststore,
            mocked_generate_keystore,
            mocked_parse_trusted_cert_arg
    ):

        # Given
        acm_client = MagicMock()
        acm_client.export_certificate = MagicMock()
        acm_client.export_certificate.return_value = downloaded_data

        rsa_util = MagicMock()
        rsa_util.import_key = MagicMock()
        dummy_key_object = MagicMock()
        rsa_util.import_key.return_value = dummy_key_object
        dummy_key_object.export_key = MagicMock()
        dummy_key_object.export_key.return_value = 'decrypted-key'

        s3_client = MagicMock()
        s3_client.get_object = MagicMock()
        s3_client.get_object.return_value = "your-s3-data"

        mocked_parse_trusted_cert_arg.return_value = "result-trusted-certs"

        # When
        retriever.retrieve_key_and_cert_and_make_stores(acm_client,
                                                        s3_client,
                                                        truststore_utils,
                                                        rsa_util,
                                                        dummy_args)

        # Then
        acm_client_call = [call(CertificateArn='my-cert-arn', Passphrase='my-key-passphrase')]
        acm_client.export_certificate.assert_has_calls(acm_client_call)

        mocked_generate_keystore.assert_called_once_with(
            "my-keystore-path",
            "my-keystore-password",
            result_data['PrivateKey'],
            result_data['Certificate'],
            "my-key-alias",
            "my-key-password"
        )

        mocked_parse_trusted_cert_arg.assert_called_once_with(
            "my-truststore-alias",
            "my-truststore-certs"
        )

        mocked_generate_truststore.assert_called_once_with(
            s3_client,
            "my-truststore-path",
            "my-truststore-password",
            "result-trusted-certs"
        )


if __name__ == '__main__':
    unittest.main()
