import OpenSSL
import botocore.session
import configargparse
import io
import jks
import logging
import os
import pytest
from acm_pca_cert_generator import certgen
from acm_common import truststore_utils
from botocore.stub import Stubber, ANY

