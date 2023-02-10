from acm_pca_cert_generator import certgen
import configargparse
import pytest
import os


valid_args = [
    "--key-type",
    "RSA",
    "--key-length",
    "2048",
    "--subject-c",
    "GB",
    "--subject-st",
    "MyCounty",
    "--subject-l",
    "MyCity",
    "--subject-o",
    "DWP",
    "--subject-ou",
    "Working Age",
    "--subject-cn",
    "myfqdn.example.com",
    "--subject-emailaddress",
    "joebloggs@example.com",
    "--ca-arn",
    "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/506a130d-8519-45dc-903d-2a30709d6a33",
    "--signing-algorithm",
    "SHA384WITHRSA",
    "--validity-period",
    "1d",
    "--keystore-path",
    "tmp/keystore.jks",
    "--keystore-password",
    "password1",
    "--private-key-alias",
    "mypk",
    "--truststore-path",
    "tmp/truststore.jks",
    "--truststore-password",
    "password2",
    "--truststore-aliases",
    "trustedcert1,trustedcert2",
    "--truststore-certs",
    "s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem",
]


def test_parse_args_for_certgen_will_return_valid_args_when_given_correct_list():
    args = """
        --key-type DSA
        --key-length 8192
        --key-digest-algorithm sha384
        --subject-c A
        --subject-st B
        --subject-l C
        --subject-o D
        --subject-ou E
        --subject-emailaddress F
        --ca-arn G
        --signing-algorithm SHA512WITHRSA
        --validity-period 22y
        --keystore-path H
        --keystore-password I
        --private-key-alias J
        --private-key-password K
        --truststore-path L 
        --truststore-password M
        --truststore-aliases N
        --truststore-certs O
        --log-level CRITICAL
    """

    result = certgen.parse_args(args)

    assert result.key_type == "DSA"
    assert result.key_length == 8192
    assert result.key_digest_algorithm == "sha384"
    assert result.subject_c == "A"
    assert result.subject_st == "B"
    assert result.subject_l == "C"
    assert result.subject_o == "D"
    assert result.subject_ou == "E"
    assert result.subject_emailaddress == "F"
    assert result.ca_arn == "G"
    assert result.signing_algorithm == "SHA512WITHRSA"
    assert result.validity_period == "22y"
    assert result.keystore_path == "H"
    assert result.keystore_password == "I"
    assert result.private_key_alias == "J"
    assert result.private_key_password == "K"
    assert result.truststore_path == "L"
    assert result.truststore_password == "M"
    assert result.truststore_aliases == "N"
    assert result.truststore_certs == "O"
    assert result.log_level == "CRITICAL"


def test_parse_args_for_certgen_will_return_valid_args_when_given_valid_env_vars():
    os.environ["CERTGEN_KEY_TYPE"] = "DSA"
    os.environ["CERTGEN_KEY_LENGTH"] = "8192"
    os.environ["CERTGEN_KEY_DIGEST_ALGORITHM"] = "sha384"
    os.environ["CERTGEN_SUBJECT_C"] = "A"
    os.environ["CERTGEN_SUBJECT_ST"] = "B"
    os.environ["CERTGEN_SUBJECT_L"] = "C"
    os.environ["CERTGEN_SUBJECT_O"] = "D"
    os.environ["CERTGEN_SUBJECT_OU"] = "E"
    os.environ["CERTGEN_SUBJECT_EMAILADDRESS"] = "F"
    os.environ["CERTGEN_CA_ARN"] = "G"
    os.environ["CERTGEN_SIGNING_ALGORITHM"] = "SHA512WITHRSA"
    os.environ["CERTGEN_VALIDITY_PERIOD"] = "22y"
    os.environ["CERTGEN_KEYSTORE_PATH"] = "H"
    os.environ["CERTGEN_KEYSTORE_PASSWORD"] = "I"
    os.environ["CERTGEN_PRIVATE_KEY_ALIAS"] = "J"
    os.environ["CERTGEN_PRIVATE_KEY_PASSWORD"] = "K"
    os.environ["CERTGEN_TRUSTSTORE_PATH"] = "L"
    os.environ["CERTGEN_TRUSTSTORE_PASSWORD"] = "M"
    os.environ["CERTGEN_TRUSTSTORE_ALIASES"] = "N"
    os.environ["CERTGEN_TRUSTSTORE_CERTS"] = "O"
    os.environ["CERTGEN_LOG_LEVEL"] = "CRITICAL"

    result = certgen.parse_args("")

    os.environ.clear()

    assert result.key_type == "DSA"
    assert result.key_length == 8192
    assert result.key_digest_algorithm == "sha384"
    assert result.subject_c == "A"
    assert result.subject_st == "B"
    assert result.subject_l == "C"
    assert result.subject_o == "D"
    assert result.subject_ou == "E"
    assert result.subject_emailaddress == "F"
    assert result.ca_arn == "G"
    assert result.signing_algorithm == "SHA512WITHRSA"
    assert result.validity_period == "22y"
    assert result.keystore_path == "H"
    assert result.keystore_password == "I"
    assert result.private_key_alias == "J"
    assert result.private_key_password == "K"
    assert result.truststore_path == "L"
    assert result.truststore_password == "M"
    assert result.truststore_aliases == "N"
    assert result.truststore_certs == "O"
    assert result.log_level == "CRITICAL"


def test_check_key_length_valid():
    assert certgen.check_key_length("2048") == 2048


def test_check_key_length_not_number():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_key_length("test")


def test_check_key_length_invalid_choice():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_key_length("1024")


def test_check_validity_period_valid():
    assert certgen.check_validity_period("365d") == "365d"
    assert certgen.check_validity_period("12m") == "12m"
    assert certgen.check_validity_period("1y") == "1y"


def test_check_validity_period_invalid():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_validity_period("52w")


def test_check_subject_cn_not_found():
    # Tox won't pass HOSTNAME through, so this tests for the case where both the
    # arg and environment variable are missing
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_subject_cn(None)


def test_check_subject_cn_blank_cn():
    with pytest.raises(configargparse.ArgumentTypeError):
        certgen.check_subject_cn("")


def test_check_subject_cn_hostname_available():
    os.environ["HOSTNAME"] = "myfqdn.example.com"
    assert certgen.check_subject_cn(None) == "myfqdn.example.com"


def test_parse_args_valid():
    assert type(certgen.parse_args(valid_args)) is configargparse.Namespace


def missing_arg_test(args_to_remove):
    invalid_args = list(valid_args)
    for arg in args_to_remove:
        invalid_args.remove(arg)
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        certgen.parse_args(invalid_args)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 2


def test_parse_args_missing_key_type():
    missing_arg_test(["--key-type", "RSA"])


def test_parse_args_missing_key_length():
    missing_arg_test(["--key-length", "2048"])


def test_parse_args_missing_key_subject_c():
    missing_arg_test(["--subject-c", "GB"])


def test_parse_args_missing_subect_st():
    missing_arg_test(["--subject-st", "MyCounty"])


def test_parse_args_missing_subject_l():
    missing_arg_test(["--subject-l", "MyCity"])


def test_parse_args_missing_subject_o():
    missing_arg_test(["--subject-o", "DWP"])


def test_parse_args_missing_subject_emailaddress():
    missing_arg_test(["--subject-emailaddress", "joebloggs@example.com"])


def test_parse_args_missing_ca_arn():
    missing_arg_test(
        [
            "--ca-arn",
            "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/506a130d-8519-45dc-903d-2a30709d6a33",
        ]
    )


def test_parse_args_missing_signing_algorithm():
    missing_arg_test(["--signing-algorithm", "SHA384WITHRSA"])


def test_parse_args_missing_validity_period():
    missing_arg_test(["--validity-period", "1d"])


def test_parse_args_missing_private_key_alias():
    missing_arg_test(["--private-key-alias", "mypk"])


def test_parse_args_missing_truststore_aliases():
    missing_arg_test(["--truststore-aliases", "trustedcert1,trustedcert2"])


def missing_arg_test_missing_truststore_certs():
    missing_arg_test(
        [
            "--truststore-certs",
            "s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem",
        ]
    )
