from json import dump, load

"""
Config file functions to use throughout the project.
"""

CONFIG_FILE = r"config.json"


def create_config_file(file_path: str, data: dict) -> None:
    """
    Creates a config file.
    :param file_path: For the file path.
    :param data: For the data to dump into the file.
    :return: None.
    """
    try:
        with open(file_path, 'w') as cf:
            dump(data, cf, indent=2)
    except Exception as err:
        raise CreateConfigFileError(f"Unable to create config file '{file_path}', Error: {err}")


def parse_config_file(config_file: str) -> dict:
    """
    Parses a given JSON file.
    :param config_file: For the file to parse.
    :return: The parsed JSON file as a dictionary.
    """
    try:
        with open(config_file, 'r') as cf:
            return load(cf)
    except Exception as err:
        raise ParseConfigFileError(f"Unable to parse config file '{config_file}', Error: {err}")


def get_configuration(value: str):
    """
    Gets the wanted configuration according to a given type.
    :param value: For the configuration line.
    :return: The configuration line.
    """
    try:
        data = parse_config_file(CONFIG_FILE)
        return data[value]
    except (ParseConfigFileError, KeyError, TypeError) as err:
        raise GetConfigurationError(err)


"""
Auxiliary class for config constants to use throughout the project.
"""


class ConfigConstants:
    # For parsing configuration
    TRUE = "true"
    FALSE = "false"

    # For config file
    LOG_FILE_NAME = "log_file_name"
    LOG_FILE_FORMAT = "log_file_format"
    DATE_FORMAT = "date_format"
    DEBUG_MODE = "debug_mode"
    CLIENT_UNIQUE_LOG_FILE = "create_client_unique_log_file"
    SERVER_VERSION = "server_version"
    PORT_LOWER_BOUND = "port_lower_bound"
    PORT_UPPER_BOUND = "port_upper_bound"
    PORT_FILE_PATH = "port_file_path"
    SERVER_PORT_NUM = "server_port_number"
    SERVER_DEFAULT_PORT_NUM = "server_default_port_number"
    SERVER_IP_ADDRESS = "server_ip_address"
    GENERIC_LOG_FIELD = "generic_log_field"
    CLIENT_ROOT_DIR = "clients_root_dir"
    SERVER_DATABASE_NAME = "server_database_name"
    CLIENTS_TABLE_NAME = "clients_table_name"
    FILES_TABLE_NAME = "files_table_name"
    EXPORT_DB_TO_JSON = "export_db_to_json"
    DB_JSON_FILE_PATH = "db_json_file_path"


"""
Auxiliary template to create a config file with initial configurations.
"""

config_file_template = {
    ConfigConstants.LOG_FILE_NAME: "server.log",
    ConfigConstants.LOG_FILE_FORMAT: "[%(asctime)s] - [%(name)-16s] - [%(levelname)s] --- [%(custom_attribute)s]: %(message)s",
    ConfigConstants.DATE_FORMAT: "%d/%m/%y %H:%M:%S",
    ConfigConstants.DEBUG_MODE: "false",
    ConfigConstants.CLIENT_UNIQUE_LOG_FILE: "true",
    ConfigConstants.SERVER_VERSION: 3,
    ConfigConstants.PORT_LOWER_BOUND: 1,
    ConfigConstants.PORT_UPPER_BOUND: 65535,
    ConfigConstants.PORT_FILE_PATH: "port.info",
    ConfigConstants.SERVER_PORT_NUM: 8080,
    ConfigConstants.SERVER_DEFAULT_PORT_NUM: 1234,
    ConfigConstants.SERVER_IP_ADDRESS: "127.0.0.1",
    ConfigConstants.GENERIC_LOG_FIELD: "Generic Log",
    ConfigConstants.CLIENT_ROOT_DIR: "Clients",
    ConfigConstants.SERVER_DATABASE_NAME: "server.db",
    ConfigConstants.CLIENTS_TABLE_NAME: "clients",
    ConfigConstants.FILES_TABLE_NAME: "files",
    ConfigConstants.EXPORT_DB_TO_JSON: "false",
    ConfigConstants.DB_JSON_FILE_PATH: "server_db.json"
}

"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class CreateConfigFileError(Exception):
    pass


class ParseConfigFileError(Exception):
    pass


class GetConfigurationError(Exception):
    pass