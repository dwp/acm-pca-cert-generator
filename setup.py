"""setuptools packaging."""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="acm_cert_helper",
    version="0.4.0",
    author="DWP DataWorks",
    author_email="dataworks@digital.uc.dwp.gov.uk",
    description="Creates a local Keystore and Truststore by generating a cert "
                "using ACM PCA or fetching a key and cert using ACM.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dwp/acm-cert-helper",
    entry_points={
        "console_scripts": [
            "acm-pca-cert-generator=acm_pca_cert_generator.certgen:main",
            "acm-cert-retriever=acm_cert_retriever.retriever:main"
        ]
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    install_requires=["ConfigArgParse", "boto3", "pyjks", "pyopenssl", "pycryptodome"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
