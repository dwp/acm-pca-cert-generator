#!/usr/bin/env python

"""Common logging functions."""
import boto3
import logging


def setup_logging(logger, log_level):
    """
    Configure the logger and boto3 to match.

    Args:
        logger (Object): The target to configure
        log_level (str): The log level
    """
    level = logging.getLevelName(log_level)
    logger.setLevel(level)
    boto3.set_stream_logger("", level)
    logger.info("Logging level set to {}".format(log_level))
