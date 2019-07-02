# acm-pca-cert-generator
`acm-pca-cert-generator` generates a Java KeyStore containing a keypair signed
by ACM PCA, and a Java TrustStore containing one or more trusted certificates
held on S3.

# Installation:

`pip install acm-pca-cert-generator`

Note that if you only want to dev/test locally, you don't need to run this.

# Pre-Requisites:

The AWS services that call this script need the following permissions:

* `acm-pca:IssueCertificate` on the ACM PCA specified in the `--ca-arn` argument
  - e.g. `arn:aws:acm-pca:AWS_Region:AWS_Account:certificate-authority/*`
* `acm-pca:GetCertficate` on the ACM PCA specified in the `--ca-arn` argument
  - e.g. `arn:aws:acm-pca:AWS_Region:AWS_Account:certificate-authority/*`
* `s3:GetObject` on all buckets specified in the `--truststore-certs` argument
  - e.g. `arn:aws:s3:::examplebucket/*`

# Running

The installation command above will place an `acm-pca-cert-generator` command in
your path. The script takes a number of command line arguments, the vast
majority of which are mandatory. Alternatively, the same information can be
specified using environment variables:

```
acm-pca-cert-generator --help

usage: certgen.py [-h] --key-type {RSA,DSA} --key-length KEY_LENGTH
                  [--key-digest-algorithm {sha256,sha384,sha512}] --subject-c
                  SUBJECT_C --subject-st SUBJECT_ST --subject-l SUBJECT_L
                  --subject-o SUBJECT_O --subject-ou SUBJECT_OU --subject-cn
                  SUBJECT_CN --subject-emailaddress SUBJECT_EMAILADDRESS
                  --ca-arn CA_ARN --signing-algorithm
                  {SHA256WITHECDSA,SHA384WITHECDSA,SHA512WITHECDSA,SHA256WITHRSA,SHA384WITHRSA,SHA512WITHRSA}
                  --validity-period VALIDITY_PERIOD --keystore-path
                  KEYSTORE_PATH --keystore-password KEYSTORE_PASSWORD
                  --private-key-alias PRIVATE_KEY_ALIAS
                  [--private-key-password PRIVATE_KEY_PASSWORD]
                  --truststore-path TRUSTSTORE_PATH --truststore-password
                  TRUSTSTORE_PASSWORD --truststore-aliases TRUSTSTORE_ALIASES
                  --truststore-certs TRUSTSTORE_CERTS
                  [--log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}]

Args that start with '--' (eg. --key-type) can also be set in a config file
(/etc/acm_pca_cert_generator/acm_pca_cert_generator.conf or
~/.config/acm_pca_cert_generator/acm_pca_cert_generator.conf). Config file
syntax allows: key=value, flag=true, stuff=[a,b,c] (for details, see syntax at
https://goo.gl/R74nmi). If an arg is specified in more than one place, then
commandline values override environment variables which override config file
values which override defaults.

optional arguments:
  -h, --help            show this help message and exit
  --key-type {RSA,DSA}  [env var: CERTGEN_KEY_TYPE]
  --key-length KEY_LENGTH
                        [env var: CERTGEN_KEY_LENGTH]
  --key-digest-algorithm {sha256,sha384,sha512}
                        [env var: CERTGEN_KEY_DIGEST]
  --subject-c SUBJECT_C
                        Certificate subject country [env var:
                        CERTGEN_SUBJECT_C]
  --subject-st SUBJECT_ST
                        Certificate subject state/province/county [env var:
                        CERTGEN_SUBJECT_ST]
  --subject-l SUBJECT_L
                        Certificate subject locality (city/town) [env var:
                        CERTGEN_SUBJECT_L]
  --subject-o SUBJECT_O
                        Certificate subject organisation [env var:
                        CERTGEN_SUBJECT_O]
  --subject-ou SUBJECT_OU
                        Certificate subject organisational unit [env var:
                        CERTGEN_SUBJECT_OU]
  --subject-cn SUBJECT_CN
                        Certificate subject common name [env var:
                        CERTGEN_SUBJECT_CN]
  --subject-emailaddress SUBJECT_EMAILADDRESS
                        Certificate subject email address [env var:
                        CERTGEN_SUBJECT_EMAILADDRESS]
  --ca-arn CA_ARN       ACM PCA ARN [env var: CERTGEN_CA_ARN]
  --signing-algorithm {SHA256WITHECDSA,SHA384WITHECDSA,SHA512WITHECDSA,SHA256WITHRSA,SHA384WITHRSA,SHA512WITHRSA}
                        The algorithm that ACM PCA will use to sign the
                        certificate [env var: CERTGEN_SIGNING_ALGORITHM]
  --validity-period VALIDITY_PERIOD
                        How long the certificate is valid for, e.g. 1d, 1m, 1y
                        for 1 day, 1 month and 1 year respectively [env var:
                        CERTGEN_VALIDITY_PERIOD]
  --keystore-path KEYSTORE_PATH
                        Filename of the keystore to save the signed keypair to
                        Should be different to truststore-path
                        [env var: CERTGEN_KEYSTORE_PATH]
  --keystore-password KEYSTORE_PASSWORD
                        Password for the Java Keystore [env var:
                        CERTGEN_KEYSTORE_PASSWORD]
  --private-key-alias PRIVATE_KEY_ALIAS
                        The alias to store the private key under in the Java
                        KeyStore [env var: CERTGEN_PRIVATE_KEY_ALIAS]
  --private-key-password PRIVATE_KEY_PASSWORD
                        The password used to protect [env var:
                        CERTGEN_PRIVATE_KEY_PASSWORD]
  --truststore-path TRUSTSTORE_PATH
                        Filename of the keystore to save trusted certificates
                        Should be different to keystore-path
                        to [env var: CERTGEN_TRUSTSTORE_PATH]
  --truststore-password TRUSTSTORE_PASSWORD
                        Password for the Java TrustStore [env var:
                        CERTGEN_TRUSTSTORE_PASSWORD]
  --truststore-aliases TRUSTSTORE_ALIASES
                        Comma-separated list of aliases to use for entries in
                        the Java TrustStore [env var:
                        CERTGEN_TRUSTSTORE_ALIASES]
  --truststore-certs TRUSTSTORE_CERTS
                        Comma-separated list of S3 URIs pointing at
                        certificates to be added to the Java TrustStore [env
                        var: CERTGEN_TRUSTSTORE_CERTS]
  --log-level {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        [env var: CERTGEN_LOG_LEVEL]
```

If you want to run from a local git clone, rather than installing using `pip`
you can run:

`python ./src/acm_pca_cert_generator/certgen.py --help`

## Example

The following example generates a 2048-bit RSA certificate and has it signed by
an entirely fictitious ACM-PCA:

```
acm-pca-cert-generator --key-type RSA --key-length 2048 --subject-c "GB" \
--subject-st "Greater London" --subject-l "London" --subject-o "My Company" \
--subject-ou "IT Department" --subject-cn "myfqdn.example.com" \
--subject-emailaddress "me@example.com" \
--ca-arn "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/506a130d-8519-45dc-903d-2a30709d6a33" \
--signing-algorithm "SHA384WITHRSA" --validity-period=1d \
--keystore-path /tmp/keystore.jks --keystore-password P4ssw0rd1 \
--private-key-alias mykey --truststore-path /tmp/truststore.jks \
--truststore-password P4ssw0rd2 --truststore-aliases ca1,ca2 \
--truststore-certs s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem
```


# Testing locally

To run the acm-pa-cert-generator self tests, you will need [tox](https://tox.readthedocs.io/en/latest/) installed:

`pip install tox`

After that, simply running `tox` from the root of your git clone will run all
the tests.

Note that there is no requirement to have an active ACM-PCA in your AWS account
for the tests to run; that functionality is stubbed to avoid incurring any
costs when running the tests.
