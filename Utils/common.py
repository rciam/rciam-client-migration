import logging.config
import logging


def get_log_conf(log_config_file=None):
    """
    Method that searches and gets the default location of configuration and logging configuration
    """
    if log_config_file is not None:
        logging.config.fileConfig(log_config_file, disable_existing_loggers=False)
    else:
        logging.basicConfig(level=logging.INFO, format=logging.BASIC_FORMAT)


"""
Method that creates the Keycloak issuer based on `auth_server` + `realm`

Parameters:
    config (dict): Keycloak's config options

Returns:
    return (string): Keycloak's issuer URL
"""


def get_keycloak_issuer(config):
    return config["auth_server"] + "/realms/" + config["realm"]
