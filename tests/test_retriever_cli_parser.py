import os
from acm_cert_retriever import retriever


def test_parse_args_for_retrieve_cert_will_return_valid_args_when_given_correct_list():

    # add-downloaded-chain-to-keystore Allowed missing, 'true', 'false', 'yes', 'no', '1' or '0'
    args = """
        --acm-cert-arn A
        --acm-key-passphrase B
        --add-downloaded-chain-to-keystore
        --keystore-path D 
        --keystore-password E
        --private-key-alias F
        --private-key-password G
        --truststore-path H
        --truststore-password I
        --truststore-aliases J
        --truststore-certs K
        --log-level CRITICAL
    """

    result = retriever.parse_args(args)

    assert result.acm_cert_arn == "A"
    assert result.acm_key_passphrase == "B"
    assert result.add_downloaded_chain_to_keystore  # boolean True
    assert result.keystore_path == "D"
    assert result.keystore_password == "E"
    assert result.private_key_alias == "F"
    assert result.private_key_password == "G"
    assert result.truststore_path == "H"
    assert result.truststore_password == "I"
    assert result.truststore_aliases == "J"
    assert result.truststore_certs == "K"
    assert result.log_level == "CRITICAL"


def test_parse_args_for_retrieve_cert_add_downloaded_chain_to_keystore_is_optional():

    # add-downloaded-chain-to-keystore Allowed missing, 'true', 'false', 'yes', 'no', '1' or '0'
    args = """
        --acm-cert-arn A
        --acm-key-passphrase B
        --keystore-path D 
        --keystore-password E
        --private-key-alias F
        --private-key-password G
        --truststore-path H
        --truststore-password I
        --truststore-aliases J
        --truststore-certs K
        --log-level CRITICAL
    """

    result = retriever.parse_args(args)

    assert result.acm_cert_arn == "A"
    assert result.acm_key_passphrase == "B"
    assert result.add_downloaded_chain_to_keystore == False
    assert result.keystore_path == "D"
    assert result.keystore_password == "E"
    assert result.private_key_alias == "F"
    assert result.private_key_password == "G"
    assert result.truststore_path == "H"
    assert result.truststore_password == "I"
    assert result.truststore_aliases == "J"
    assert result.truststore_certs == "K"
    assert result.log_level == "CRITICAL"


def test_parse_args_for_retrieve_cert_will_return_valid_args_when_given_valid_env_vars():

    os.environ['RETRIEVER_ACM_CERT_ARN'] = "A"
    os.environ['RETRIEVER_ACM_KEY_PASSPHRASE'] = "B"
    # Allowed missing, 'true', 'false', 'yes', 'no', '1' or '0'
    os.environ['RETRIEVER_ADD_DOWNLOADED_CHAIN'] = "no"
    os.environ['RETRIEVER_KEYSTORE_PATH'] = "D"
    os.environ['RETRIEVER_KEYSTORE_PASSWORD'] = "E"
    os.environ['RETRIEVER_PRIVATE_KEY_ALIAS'] = "F"
    os.environ['RETRIEVER_PRIVATE_KEY_PASSWORD'] = "G"
    os.environ['RETRIEVER_TRUSTSTORE_PATH'] = "H"
    os.environ['RETRIEVER_TRUSTSTORE_PASSWORD'] = "I"
    os.environ['RETRIEVER_TRUSTSTORE_ALIASES'] = "J"
    os.environ['RETRIEVER_TRUSTSTORE_CERTS'] = "K"
    os.environ['RETRIEVER_LOG_LEVEL'] = "CRITICAL"

    result = retriever.parse_args("")

    os.environ.clear()

    assert result.acm_cert_arn == "A"
    assert result.acm_key_passphrase == "B"
    assert result.add_downloaded_chain_to_keystore == False  # boolean True
    assert result.keystore_path == "D"
    assert result.keystore_password == "E"
    assert result.private_key_alias == "F"
    assert result.private_key_password == "G"
    assert result.truststore_path == "H"
    assert result.truststore_password == "I"
    assert result.truststore_aliases == "J"
    assert result.truststore_certs == "K"
    assert result.log_level == "CRITICAL"

