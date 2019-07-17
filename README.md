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

Running the following will remove all the local files created by tox, incase you need to tidy up:

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
--keystore-path /tmp/keystore.jks --keystore-password P4ssw0rd1 \
--private-key-alias mykey --truststore-path /tmp/truststore.jks \
--truststore-password P4ssw0rd2 --truststore-aliases ca1,ca2 \
--truststore-certs s3://certbucket/certs/ca_1.pem,s3://certbucket/certs/ca_2.pem
```
