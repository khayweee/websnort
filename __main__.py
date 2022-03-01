"""
Instantiate logging configurations
"""
import sys
from os import path
import traceback
import configparser
import logging, logging.config

from src.main import main

LOGGER_CONF_PATH = "src/conf/logging.conf"

logger = logging.getLogger(__name__)

if __name__=="__main__":
    config = configparser.ConfigParser()
    logger.info('Current Directory: ', path.abspath(__file__))
    log_file_path = path.join(path.dirname(path.abspath(__file__)), LOGGER_CONF_PATH)
    logger.info("log_file_oath : ", log_file_path)
    config.read(log_file_path)
    logging.config.fileConfig(config, disable_existing_loggers=False)

    try:
        sys.exit(main())
    except Exception:
        logger.error("Uncaught exception: %s", traceback.format_exc())
        print("Bye Bye :(")