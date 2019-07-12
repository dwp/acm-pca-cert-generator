"""setuptools packaging."""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="acm_pca_cert_generator",
    version="0.0.1",
    author="Matt Burgess",
    author_email="matthewburgess@digital.uc.dwp.gov.uk",
    description="Generate certs using ACM PCA",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dwp/acm-pca-cert-generator",
    entry_points={
        "console_scripts": [
            "acm-pca-cert-generator=acm_pca_cert_generator.certgen:main"
        ]
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    install_requires=["ConfigArgParse", "boto3", "pyjks", "pyopenssl"],
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
