"""ACM Certificate Retriever.

Fetches a remote key and cert from ACM.
Then, adds the key and signed cert to a local Keystore and Truststore.
Also adds configured remote S3 certs to the Truststore.

"""
