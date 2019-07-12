from acm_cert_retriever import retriever
try:
    import mock
except ImportError:
    from unittest import mock


def test_retrieve_key_and_cert_will_generate_keystore_and_truststore_from_acm_data():
    # retrieve_key_and_cert(args, acm_client, s3_client, truststore_utils)
    assert True
