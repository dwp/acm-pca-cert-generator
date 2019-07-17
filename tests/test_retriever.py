import unittest
import copy
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


def make_tuple(some_args_dict):
    return namedtuple("DummyParsedArgs", some_args_dict.keys())(*some_args_dict.values())


sample_args = {
    "acm_cert_arn": "my-cert-arn",
    "acm_key_passphrase": "my-key-passphrase",
    "add_downloaded_chain_to_truststore": "yes",
    "keystore_path": "my-keystore-path",
    "keystore_password": "my-keystore-password",
    "private_key_alias": "my-key-alias",
    "private_key_password": "my-key-password",
    "truststore_path": "my-truststore-path",
    "truststore_password": "my-truststore-password",
    "truststore_aliases": "my-truststore-aliases",
    "truststore_certs": "my-truststore-certs",
    "log_level": "ANY"
}
dummy_args = make_tuple(sample_args)

downloaded_data = {
    'Certificate': 'downloaded-cert',
    'CertificateChain': 'downloaded-chain',
    'PrivateKey': 'downloaded-encrypted-key'
}

dummy_certs_data = [
    {"alias": "a1", "cert": "c1", "source": "s1"}
]

dummy_certs_data_extended = copy.copy(dummy_certs_data)
dummy_certs_data_extended.append(
    {"alias": "aws-cert-chain", "cert": 'downloaded-chain', "source": "memory"}
)


class TestRetriever(unittest.TestCase):

    @mock.patch('acm_common.truststore_utils.parse_trusted_cert_arg')
    @mock.patch('acm_common.truststore_utils.generate_keystore')
    @mock.patch('acm_common.truststore_utils.generate_truststore')
    @mock.patch('acm_cert_retriever.retriever.logger')
    def test_retrieve_key_and_cert_will_throw_exception_when_arn_is_bad(
            self,
            mocked_logger,
            mocked_generate_truststore,
            mocked_generate_keystore,
            mocked_parse_trusted_cert_arg):
        """Test a bad ARN scenario.

        Sample trace from real test:
        Failed to fetch arn:aws:acm:eu-west-2:475593055014:certificate/bad-arn:
        Error = An error occurred (ResourceNotFoundException) when calling the
        ExportCertificate operation: Could not find certificate
        arn:aws:acm:eu-west-2:475593055014:certificate/bad-arn.

        """

        # Given
        acm_client = MagicMock()
        acm_client.export_certificate = MagicMock()
        acm_client.export_certificate.side_effect = Exception('Bad ARN!')

        rsa_util = MagicMock()
        rsa_util.import_key = MagicMock()

        s3_client = MagicMock()

        bad_sample_args = {
            "acm_cert_arn": "bad-arn",
            "acm_key_passphrase": "my-key-passphrase"
        }
        bad_args = make_tuple(bad_sample_args)

        # When
        try:
            retriever.retrieve_key_and_cert_and_make_stores(acm_client,
                                                            s3_client,
                                                            truststore_utils,
                                                            rsa_util,
                                                            bad_args)
        except Exception as expected:
            self.assertEqual('Bad ARN!', str(expected))
        else:
            self.fail("Expected the method under test to blow up")

        # Then
        mocked_logger.exception.assert_called_with('Failed to fetch bad-arn: Error = Bad ARN!')
        acm_client.export_certificate.assert_called_once_with(
            CertificateArn='bad-arn', Passphrase='my-key-passphrase')

        rsa_util.import_key.assert_not_called()
        mocked_generate_keystore.assert_not_called()
        mocked_parse_trusted_cert_arg.assert_not_called()
        mocked_generate_truststore.assert_not_called()

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
        dummy_rsakey_object = MagicMock()
        rsa_util.import_key.return_value = dummy_rsakey_object
        dummy_rsakey_object.export_key = MagicMock()
        dummy_rsakey_object.export_key.return_value = 'in-memory-decrypted-key'

        s3_client = MagicMock()

        mocked_parse_trusted_cert_arg.return_value = dummy_certs_data

        # When
        retriever.retrieve_key_and_cert_and_make_stores(acm_client,
                                                        s3_client,
                                                        truststore_utils,
                                                        rsa_util,
                                                        dummy_args)

        # Then
        acm_client.export_certificate.assert_called_once_with(
            CertificateArn='my-cert-arn', Passphrase='my-key-passphrase')

        rsa_util.import_key.assert_called_once_with('downloaded-encrypted-key', 'my-key-passphrase')

        mocked_generate_keystore.assert_called_once_with(
            "my-keystore-path",
            "my-keystore-password",
            'in-memory-decrypted-key',
            'downloaded-cert',
            "my-key-alias",
            "my-key-password"
        )

        mocked_parse_trusted_cert_arg.assert_called_once_with(
            "my-truststore-aliases",
            "my-truststore-certs"
        )

        mocked_generate_truststore.assert_called_once_with(
            s3_client,
            "my-truststore-path",
            "my-truststore-password",
            dummy_certs_data_extended
        )


if __name__ == '__main__':
    unittest.main()
