#!/bin/sh
set -e

# If either of the AWS credentials variables were provided, validate them
if [ -n "${AWS_ACCESS_KEY_ID}${AWS_SECRET_ACCESS_KEY}" ]; then
    if [ -z "${AWS_ACCESS_KEY_ID}" -o -z "${AWS_SECRET_ACCESS_KEY}" ]; then
        echo "ERROR: You must provide both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY variables if you want to use access key based authentication"
        exit 1
    else
        echo "INFO: Using supplied access key for authentication"
    fi
    
    # If either of the ASSUMEROLE variables were provided, validate them and configure a shared credentials fie
    if [ -n "${AWS_ASSUMEROLE_ACCOUNT}${AWS_ASSUMEROLE_ROLE}" ]; then
        if [ -z "${AWS_ASSUMEROLE_ACCOUNT}" -o -z "${AWS_ASSUMEROLE_ROLE}" ]; then
            echo "ERROR: You must provide both the AWS_ASSUMEROLE_ACCOUNT and AWS_ASSUMEROLE_ROLE variables if you want to assume role"
            exit 1
        else
            ASSUME_ROLE="arn:aws:iam::${AWS_ASSUMEROLE_ACCOUNT}:role/${AWS_ASSUMEROLE_ROLE}"
            echo "INFO: Configuring AWS credentials for assuming role to ${ASSUME_ROLE}..."
            mkdir ~/.aws
      cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id=${AWS_ACCESS_KEY_ID}
aws_secret_access_key=${AWS_SECRET_ACCESS_KEY}

[${AWS_ASSUMEROLE_ROLE}]
role_arn=${ASSUME_ROLE}
source_profile=default
EOF
            PROFILE_OPTION="--profile ${AWS_ASSUMEROLE_ROLE}"
        fi
    fi
    if [ -n "${AWS_SESSION_TOKEN}" ]; then
        sed -i -e "/aws_secret_access_key/a aws_session_token=${AWS_SESSION_TOKEN}" ~/.aws/credentials
    fi
else
    echo "INFO: Using attached IAM roles/instance profiles to authenticate as no AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY have been provided"
fi

if [ !"${LOG_LEVEL}" ]; then
    LOG_LEVEL="INFO"
fi

# Retrieve certificates
TRUSTSTORE_PASSWORD=$(uuidgen -r)
KEYSTORE_PASSWORD=$(uuidgen -r)
PRIVATE_KEY_PASSWORD=$(uuidgen -r)
ACM_KEY_PASSWORD=$(uuidgen -r)

if [ "${LOG_LEVEL}" == "DEBUG" ]; then
    echo "INFO: Start up params"
    echo "acm-cert-arn: ${ACM_CERT_ARN} \n
    acm-key-passphrase: ${ACM_KEY_PASSWORD} \n
    add-downloaded-chain-to-keystore: true \n
    keystore-path: /acm-cert-helper/keystore.jks \n
    keystore-password: ${KEYSTORE_PASSWORD} \n
    private-key:-alias ${PRIVATE_KEY_ALIAS} \n
    private-key:-password ${PRIVATE_KEY_PASSWORD} \n
    truststore-path: /acm-cert-helper/truststore.jks \n
    truststore-password: ${TRUSTSTORE_PASSWORD} \n
    truststore-aliases: ${TRUSTSTORE_ALIASES} \n
    truststore-certs: ${TRUSTSTORE_CERTS} \n
    log-level: ${LOG_LEVEL}"
fi

echo "INFO: Starting acm-cert-helper..."
exec acm-cert-retriever \
--acm-cert-arn "${ACM_CERT_ARN}" \
--acm-key-passphrase "${ACM_KEY_PASSWORD}" \
--add-downloaded-chain-to-keystore true \
--keystore-path "/acm-cert-helper/keystore.jks" \
--keystore-password "${KEYSTORE_PASSWORD}" \
--private-key-alias "${PRIVATE_KEY_ALIAS}" \
--private-key-password "${PRIVATE_KEY_PASSWORD}" \
--truststore-path "/acm-cert-helper/truststore.jks" \
--truststore-password "${TRUSTSTORE_PASSWORD}" \
--truststore-aliases "${TRUSTSTORE_ALIASES}" \
--truststore-certs "${TRUSTSTORE_CERTS}" \
--log-level ${LOG_LEVEL}
