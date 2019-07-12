from acm_pca_cert_generator import certgen
import configargparse
import pytest

valid_args = [
    "--key-type",
    "RSA",
    "--key-length",
    "2048",
    "--subject-c",
    "GB",
    "--subject-st",
    "Yorkshire",
    "--subject-l",
    "Leeds",
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
    missing_arg_test(["--subject-st", "Yorkshire"])


def test_parse_args_missing_subject_l():
    missing_arg_test(["--subject-l", "Leeds"])


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


def test_parse_args_missing_keystore_path():
    missing_arg_test(["--keystore-path", "tmp/keystore.jks"])


def test_parse_args_missing_keystore_password():
    missing_arg_test(["--keystore-password", "password1"])


def test_parse_args_missing_private_key_alias():
    missing_arg_test(["--private-key-alias", "mypk"])


def test_parse_args_missing_truststore_path():
    missing_arg_test(["--truststore-path", "tmp/truststore.jks"])


def test_parse_args_missing_truststore_password():
    missing_arg_test(["--truststore-password", "password2"])


def test_parse_args_missing_truststore_aliases():
    missing_arg_test(["--truststore-aliases", "trustedcert1,trustedcert2"])


def missing_arg_test_missing_truststore_certs():
    missing_arg_test(
        [
            "--truststore-certs",
            "s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem",
        ]
    )

