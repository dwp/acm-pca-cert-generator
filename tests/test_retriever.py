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
    "acm_key_arn": "my-key-arn",
    "acm_cert_arn": "my-cert-arn",
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

result_key = {
    'Certificate': 'result-key-cert',
    'CertificateChain': 'result-key-chain'
}

result_cert = {
    'Certificate': 'result-cert-cert',
    'CertificateChain': 'result-cert-chain'
}


def dummy_client(*args, **kwargs):
    # if args[0] == 's3':
    mock_client = MagicMock()

    if args[0] == 'acm':
        mock_client.get_certificate = MagicMock()

    return mock_client


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

        acm_client = MagicMock()
        acm_client.get_certificate = MagicMock()
        s3_client = MagicMock()

        acm_client.get_certificate.side_effect = [result_key, result_cert]
        mocked_parse_trusted_cert_arg.return_value = "result-trusted-certs"

        # retrieve_key_and_cert(args, acm_client, s3_client, truststore_utils)
        retriever.retrieve_key_and_cert(dummy_args, acm_client, s3_client, truststore_utils)
        acm_client_calls = [call(CertificateArn='my-key-arn'), call(CertificateArn='my-cert-arn')]
        acm_client.get_certificate.assert_has_calls(acm_client_calls)

        mocked_generate_keystore.assert_called_once_with(
            "my-keystore-path",
            "my-keystore-password",
            result_key['Certificate'],
            result_cert['Certificate'],
            "my-key-alias",
            "my-key-password"
        )

        mocked_parse_trusted_cert_arg.assert_called_once_with(
            "my-truststore-alias",
            "my-truststore-certs"
        )

        # s3_util, args.truststore_path, args.truststore_password, trusted_certs
        mocked_generate_truststore.assert_called_once_with(
            s3_client,
            "my-truststore-path",
            "my-truststore-password",
            "result-trusted-certs"
        )


if __name__ == '__main__':
    unittest.main()
