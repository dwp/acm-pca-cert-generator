# acm-pca-cert-generator
Automatic creation of TLS certs generated with AWS' ACM PCA service

# Installation:

`pip install acm-pca-cert-generator`

Note that if you only want to dev/test locally, you don't need to run this.

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
                  --validity-period VALIDITY_PERIOD [--log-level LOG_LEVEL]

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
  --log-level LOG_LEVEL
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
--signing-algorithm "SHA256WITHRSA" --validity-period=1d
```


# Testing locally

To run the acm-pa-cert-generator self tests, you will need [tox](https://tox.readthedocs.io/en/latest/) installed:

`pip install tox`

After that, simply running `tox` from the root of your git clone will run all
the tests.

Note that there is no requirement to have an active ACM-PCA in your AWS account
for the tests to run; that functionality is stubbed to avoid incurring any
costs when running the tests.
