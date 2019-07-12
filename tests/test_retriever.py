from acm_cert_retriever import retriever


def test_parse_args_for_retrieve_cert_will_return_valid_args_when_given_correct_list():
    args = """
        --acm-key-arn A
        --acm-cert-arn B
        --keystore-path C 
        --keystore-password D
        --private-key-alias E
        --private-key-password F
        --truststore-path G 
        --truststore-password H
        --truststore-aliases I
        --truststore-certs J
        --log-level CRITICAL
    """
    result = retriever.parse_args(args)
    assert result.acm_key_arn == "A"
    assert result.acm_cert_arn == "B"
    assert result.keystore_path == "C"
    assert result.keystore_password == "D"
    assert result.private_key_alias == "E"
    assert result.private_key_password == "F"
    assert result.truststore_path == "G"
    assert result.truststore_password == "H"
    assert result.truststore_aliases == "I"
    assert result.truststore_certs == "J"
    assert result.log_level == "CRITICAL"
