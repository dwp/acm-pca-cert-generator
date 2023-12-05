# DO NOT USE THIS REPO - MIGRATED TO GITLAB

# acm-cert-helper

This contains two related utilities, both of which are detailed below, that work with ACM
and ACM-PCA to make local Keystore and Truststore files.


## Testing locally

To run the acm-cert-helper self tests, you will need [tox](https://tox.readthedocs.io/en/latest/) installed:

```
$ pip install tox
$ tox
```

Running `tox` from the root of your git clone will run all the tests.

Note that there is no requirement to have an active ACM or ACM-PCA in your AWS account
for the tests to run; that functionality is stubbed to avoid incurring any
costs when running the tests.

## Installing locally from source.

Running `tox` as above will compile the project. You can also build and install it locally using

```
$ python setup.py build install
```

The installation command above will place two commands in your path, `acm-cert-retriever`  and
`acm-pca-cert-generator`.  Each script takes a number of command line arguments, most of
which are mandatory. Alternatively, the same information can be specified using environment variables.


## Cleaning outputs locally

Running the following will remove all the local files created by tox, in case you need to tidy up:

```
rm -rf build dist .tox
```

## Installing from github:

`pip install acm-cert-helper`

Note that if you only want to dev/test locally, you don't need to run this.


## acm-cert-retriever
`acm-cert-retriever` generates a Java KeyStore containing a keypair and cert it has fetched
from ACM, and a Java TrustStore containing one or more trusted certificates held on S3.


### Pre-Requisites:

The AWS services that call this script need the following permissions:

* `acm-pca:GetCertficate` on the ACM data specified in the `--acm-key-arn` argument
  - e.g. `arn:aws:acm:AWS_Region:AWS_Account:certificate/*`
* `s3:GetObject` on all buckets and objects specified in the `--truststore-certs` argument
  - e.g. `arn:aws:s3:::examplebucket/*`

### Running

The installation command above will place an `acm-cert-retriever` command in
your path.
The script takes a number of command line arguments, most of which are mandatory.
Alternatively, the same information can be specified using environment variables:
The help text is the authoritative source for this:

```
acm-pca-cert-retriever --help
```

If you want to run from a local git clone, rather than installing using `pip`
you can run:

`python ./src/acm_cert_retriever/retriever.py --help`

### Example

The following downloads a fictitious key and cert for the Keystore and adds two CAs from s3 to
the Truststore:

```
acm-cert-retriever \
--acm-cert-arn arn:aws:acm:us-east-1:012345678901:certificate/123a456b-7890-12cd-345e-6f78901f2a34 \
--acm-key-passphrase P4ssw0rd1 \
--keystore-path /tmp/keystore.jks \
--keystore-password P4ssw0rd2 \
--private-key-alias mykey \
--truststore-path /tmp/truststore.jks \
--truststore-password P4ssw0rd3 \
--truststore-aliases ca1,ca2 \
--truststore-certs s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem
```


## acm-pca-cert-generator
`acm-pca-cert-generator` generates a Java KeyStore containing a keypair signed
by ACM PCA, and a Java TrustStore containing one or more trusted certificates
held on S3.

### Pre-Requisites:

The AWS services that call this script need the following permissions:

* `acm-pca:IssueCertificate` on the ACM PCA specified in the `--ca-arn` argument
  - e.g. `arn:aws:acm-pca:AWS_Region:AWS_Account:certificate-authority/*`
* `acm-pca:GetCertficate` on the ACM PCA specified in the `--ca-arn` argument
  - e.g. `arn:aws:acm-pca:AWS_Region:AWS_Account:certificate-authority/*`
* `s3:GetObject` on all buckets and objects specified in the `--truststore-certs` argument
  - e.g. `arn:aws:s3:::examplebucket/*`

### Running

The installation command above will place an `acm-pca-cert-generator` command in
your path.
The script takes a number of command line arguments, most of which are mandatory.
Alternatively, the same information can be specified using environment variables:
The help text is the authoritative source for this:

```
acm-pca-cert-generator --help
```

If you want to run from a local git clone, rather than installing using `pip`
you can run:

`python ./src/acm_pca_cert_generator/certgen.py --help`

### Example

The following example generates a 2048-bit RSA certificate and has it signed by
an entirely fictitious ACM-PCA:

```
acm-pca-cert-generator \
--key-type RSA \
--key-length 2048 \
--subject-c "GB" \
--subject-st "Greater London" \
--subject-l "London" \
--subject-o "My Company" \
--subject-ou "IT Department" \
--subject-cn "myfqdn.example.com" \
--subject-emailaddress "me@example.com" \
--ca-arn "arn:aws:acm-pca:us-east-1:012345678901:certificate-authority/123a456b-7890-12cd-345e-6f78901f2a34" \
--signing-algorithm "SHA384WITHRSA" --validity-period=1d \
--keystore-path /tmp/keystore.jks --keystore-password P4ssw0rd1 --private-key-alias mykey \
--truststore-path /tmp/truststore.jks --truststore-password P4ssw0rd2 \
--truststore-aliases ca1,ca2 \
--truststore-certs s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem
```

In this example, the certificate is being generated via Terraform instead of
via `acm-pca-cert-generator`. It is then retrived and placed in the OS
certificate and key stores only, not in a Java KeyStore:

Terraform:
```
resource "aws_acm_certificate" "tarball_ingestion" {
     certificate_authority_arn = data.terraform_remote_state.certificate_authority.outputs.root_ca.arn
     domain_name               = "${local.tarball_ingestion_name}.${local.env_prefix[local.environment]}dataworks.dwp.gov.uk"

     options {
       certificate_transparency_logging_preference = "DISABLED"
     }

     tags = merge(
       local.common_tags,
       {
         Name = "tarball-ingester-cert"
       },
     )
   }
```

ACM call:

```
ACM_KEY_PASSWORD=$(uuidgen -r)

acm-cert-retriever \
--acm-cert-arn "${acm_cert_arn}" \
--acm-key-passphrase "$ACM_KEY_PASSWORD" \
--private-key-alias "private-key" \
--truststore-aliases "ca1, ca2" \
--truststore-certs s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem >> /var/log/acm-cert-retriever.log 2>&1
```

The `private-key-alias` can be any string unique to your deployment.


### Container Image

The container image in the same pattern as the standard process.  The entrypoint is designed in such a way that you can pass the required parameters via environemnt variables. eg.
```
environment_variables = jsonencode([
      {
        name  = "LOG_LEVEL",
        value = "DEBUG"
      },
      {
        name  = "ACM_CERT_ARN",
        value = "${data.terraform_remote_state.snapshot_sender.outputs.ss_cert[0].arn}"
      },
      {
        name  = "PRIVATE_KEY_ALIAS",
        value = "${local.environment}"
      },
      {
        name  = "TRUSTSTORE_ALIASES",
        value = "${local.ss_host_truststore_aliases[local.environment]}"
      },
      {
        name  = "TRUSTSTORE_CERTS",
        value = "${local.ss_host_truststore_certs[local.environment]}"
      }
    ])
```

By running the container as a sidecar, and sharing the same mount point, you can use the container image to retrieve certs for your other containers.

```
mount_points = jsonencode([
      {
        "container_path" : "/acm-cert-helper",
        "source_volume" : "certs"
      }
    ])
```
The containers sharing this mount point can install certs from this location.
