"""
Instantiate logging configurations
"""
import sys
import traceback
import configparser
import logging, logging.config
from src.main import main

LOGGER_CONF_PATH = "conf/logging.conf"

logger = logging.getLogger(__name__)

if __name__=="__main__":
    config = configparser.ConfigParser()
    config.read(LOGGER_CONF_PATH)
    logging.config.fileConfig(config, disable_existing_loggers=False)

    try:
        sys.exit(main())
    except Exception:
        logger.error("Uncaught exception: %s", traceback.format_exc())
        print("Bye Bye :(")