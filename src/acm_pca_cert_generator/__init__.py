"""ACM PCA Certificate Generator.

Creates a new local key and csr, and has that signed by ACM-PCA.
Then, adds the key and signed cert to a local Keystore and Truststore.
Also adds configured remote S3 certs to the Truststore.

"""
