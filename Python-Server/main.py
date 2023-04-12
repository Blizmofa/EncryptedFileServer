from os import path
from sys import exit
from server_logic import ServerLogicConfigurationError
from server_core import ServerCore
from server_utils import ServerUtils, UtilsConfigurationError, ParsingPortFileError
from logger import CustomFilter, SetLoggerAttributesError
from config_parser import create_config_file, get_configuration, CONFIG_FILE, \
    config_file_template, ConfigConstants, CreateConfigFileError, GetConfigurationError

"""
Server main method.
"""


def main():

    # Validate config file
    if not path.exists(CONFIG_FILE):
        try:
            create_config_file(CONFIG_FILE, config_file_template)
        except CreateConfigFileError as err:
            print(err)
            exit()

    # Defining Server static ip address and port number
    try:
        server_ip_address = str(get_configuration(ConfigConstants.SERVER_IP_ADDRESS))
        server_port = int(get_configuration(ConfigConstants.SERVER_PORT_NUM))

        # Setting a custom log field
        CustomFilter.filter_name = str(get_configuration(ConfigConstants.GENERIC_LOG_FIELD))

        # Creating port file and parse port number from it
        server_utils = ServerUtils()
        server_utils.create_port_file(server_port)
        try:
            client_port = server_utils.get_port_num()

        except (FileNotFoundError, ParsingPortFileError):
            # In case port.info file is corrupted
            client_port = int(get_configuration(ConfigConstants.SERVER_DEFAULT_PORT_NUM))

        # Validate connection credentials
        if server_utils.validate_connection_credentials(client_port, server_ip_address):

            # Run server main method
            server = ServerCore(server_ip_address, client_port)
            server.run()
            
        else:
            print("[!] Invalid connection credentials.")
            exit()

    except (GetConfigurationError, SetLoggerAttributesError,
            UtilsConfigurationError, ServerLogicConfigurationError) as err:
        print(f"[!] Config file is corrupted, missing entry {err}, delete it and run server again.")
        exit()


if __name__ == '__main__':
    main()
