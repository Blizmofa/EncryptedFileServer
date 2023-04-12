from base64 import b64encode, b64decode
from uuid import uuid4
from os import makedirs, path, remove
from zlib import crc32
from datetime import datetime
from re import match
from logger import Logger
from config_parser import get_configuration, ConfigConstants, GetConfigurationError

"""
Class for server utils functions.
"""

# Constants
CRC_CHUNK_SIZE = 65536
DEFAULT_NUM_OF_LINES = 1


class ServerUtils:

    def __init__(self):
        """Class Constructor."""
        self.port_file_path = self.set_server_utils_configuration(ConfigConstants.PORT_FILE_PATH)
        self.clients_root_dir_path = self.set_server_utils_configuration(ConfigConstants.CLIENT_ROOT_DIR)
        self.class_logger = Logger('Server Utils')

    @staticmethod
    def set_server_utils_configuration(value: str) -> str:
        """
        Return the server utils needed configuration from config file.
        Mainly for error handling.
        :return: The needed value to config.
        """
        try:
            return str(get_configuration(value))

        except GetConfigurationError as err:
            raise UtilsConfigurationError(err)

    def create_port_file(self, port_num: int) -> None:
        """
        Creates the server needed port.info file.
        :param port_num: For the port number to write.
        :return: None.
        """
        with open(self.port_file_path, 'w') as port_file:
            port_file.write(str(port_num))
        self.class_logger.logger.debug(f"Created '{self.port_file_path}' file successfully.")

    def validate_connection_credentials(self, port: str, ip: str) -> bool:
        """
        Validates a given Port number and IP Address.
        :param port: For the port number to validate.
        :param ip: For the ip address to validate.
        :return: True if the given credentials are valid, False otherwise.
        """
        try:
            if self.validate_port_range(port) and self.validate_ip_address(ip):
                return True
            else:
                self.class_logger.logger.error(f"Invalid connection credentials {ip}:{port}")
                return False
        except PortRangeError as err:
            raise UtilsConfigurationError(err)

    def validate_ip_address(self, ip_address: str) -> bool:
        """
        Validates a given IP Address value and format.
        :param ip_address: For the IP Address to validate.
        :return: True if the IP Address is valid, False otherwise.
        """
        # Regular expression pattern for IP address validation
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        if match(pattern, ip_address):
            self.class_logger.logger.debug(f"IP Address '{ip_address}' is valid.")
            return True
        else:
            self.class_logger.logger.error(f"IP Address '{ip_address}' is invalid.")
            return False

    def validate_port(self, port: str) -> str:
        """
        Validates a given port value and bounds.
        :return: The validated port number as a string value.
        """
        try:
            if self.validate_port_range(port):
                self.class_logger.logger.debug(f"Parsed '{self.port_file_path}' successfully.")
                return port

        except PortRangeError as err:
            self.class_logger.logger.error(err)
            raise UtilsConfigurationError(err)

    def get_port_num(self) -> str:
        """
        Returns the server port number.
        :return: a String representation of the server port number.
        """
        with open(self.port_file_path, 'r') as f:
            lines = f.readlines()

        # Port file cant contain only one line
        try:
            if len(lines) == DEFAULT_NUM_OF_LINES:
                port = lines[0]
                return port
            else:
                raise ParsingPortFileError(f"'{self.port_file_path}' needs to contain one line.")

        except ValueError as err:
            raise ParsingPortFileError(err)

    def validate_port_range(self, port: str) -> bool:
        """
        Validates port range between 1-65535.
        :param port: For the port to validate.
        :return: True if the number is in valid port bounds, False otherwise.
        """
        try:
            port = int(port)
            port_lower_bound = int(get_configuration(ConfigConstants.PORT_LOWER_BOUND))
            port_upper_bound = int(get_configuration(ConfigConstants.PORT_UPPER_BOUND))
            if port < port_lower_bound or port > port_upper_bound:
                self.class_logger.logger.error(
                    f"port '{port}' is out of bounds, check port number in '{self.port_file_path}'.")
                return False
            else:
                self.class_logger.logger.debug(f"port {port} range validation success.")
                return True

        except (Exception, GetConfigurationError) as err:
            raise PortRangeError(f"Unable to cast {port} to a valid integer, Error: {err}")

    def update_ram_dict(self, dict_db_to_update: dict, key_to_update: str, value_to_update) -> None:
        """
        Updates the created RAM Memory dictionary temporary database.
        :param dict_db_to_update: For the dictionary to update.
        :param key_to_update: For the dictionary key.
        :param value_to_update: For the dictionary value.
        :return: None.
        """
        for key, value in dict_db_to_update.items():
            if key == key_to_update:
                try:
                    dict_db_to_update[key_to_update] = value.format(value_to_update)
                    self.class_logger.logger.debug(f"Updated '{dict_db_to_update}' where '{key_to_update}' "
                                                   f"with '{value_to_update}' successfully.")
                except Exception as err:
                    raise UpdateDictionaryError(f"Unable to update '{dict_db_to_update}', Error: {err}")

    def generate_client_uuid(self) -> bytes:
        """
        Generates a client bytes UUID in a specific size.
        :return: The newly generated client UUID.
        """
        client_uuid = uuid4().bytes
        self.class_logger.logger.debug(f"Generated client UUID: '{client_uuid}' successfully.")
        return client_uuid

    def last_seen(self) -> str:
        """
        Auxiliary function to return the current date and time in a custom format.
        :return: The current date and time in a custom format.
        """
        try:
            now = datetime.now()
            format_data = str(get_configuration(ConfigConstants.DATE_FORMAT))
            return now.strftime(format_data)

        except GetConfigurationError as err:
            self.class_logger.logger.error(err)

    def encode_base64(self, content: bytes) -> str:
        """
        Encode a given bytes content to base64 format.
        :param content: For the content to encode.
        :return: A string representation of the encoded bytes.
        """
        try:
            encoded = b64encode(content)
            self.class_logger.logger.debug(f"{content} has been encoded to base64 successfully.")
            return encoded.decode()

        except ValueError as err:
            raise Base64Error(f"Unable to encode {content} to base64, Error: {err}")

    def decode_base64(self, content: str) -> bytes:
        """
        Decode a given base64 content to bytes.
        :param content: For the content to decode.
        :return: A bytes stream of the decoded content.
        """
        try:
            decoded = b64decode(content)
            self.class_logger.logger.debug(f"{content} has been decoded from base64 successfully.")
            return decoded

        except ValueError as err:
            raise Base64Error(f"Unable to decode {content} from base64, Error: {err}")

    def convert_hex_to_bytes(self, content: str) -> bytes:
        """
        Covert hex string to bytes stream.
        :param content: For the content to convert.
        :return: A bytes stream representation of the hex content.
        """
        try:
            converted = bytes.fromhex(content)
            self.class_logger.logger.debug(f"Converted '{content}' to {converted} successfully.")
            return converted

        except (ValueError, TypeError) as err:
            raise ConversionError(f"Unable to convert '{content}', Error: {err}")

    def calculate_crc32(self, file: str) -> int:
        """
        Calculates CRC of a given file.
        :param file: For the file to process.
        :return: The checksum of the given file.
        """
        try:
            with open(file, 'rb') as crc_file:
                checksum = 0
                while chunk := crc_file.read(CRC_CHUNK_SIZE):
                    checksum = crc32(chunk, checksum)
                self.class_logger.logger.debug(f"File '{file}' CRC is: {checksum}")
                return checksum

        except Exception as err:
            raise CRCError(f"Unable to calculate crc for '{file}', Error: {err}")

    def create_directory(self, dir_path: str) -> None:
        """
        Generic method to create directory in a given path.
        :param dir_path: For the directory creation wanted path.
        :return: None
        """
        if not self.is_exists(dir_path):
            try:
                makedirs(dir_path, exist_ok=True)
                self.class_logger.logger.debug(f"Directory '{dir_path}' has been created successfully.")

            except Exception as err:
                raise CreateDirectoryError(f"Unable to create '{dir_path}', Error: {err}")

    def create_clients_root_directory(self) -> None:
        """
        Creates the server Clients root directory.
        :return: None
        """
        try:
            self.create_directory(self.clients_root_dir_path)
        except CreateDirectoryError as err:
            self.class_logger.logger.error(err)

    def create_client_unique_directory(self, client_name: str) -> None:
        """
        Creates the new registered client folder according to a given username.
        :param client_name: For the client username.
        :return: None
        """
        try:
            self.create_directory(f"{self.clients_root_dir_path}/{client_name}")
        except CreateDirectoryError as err:
            self.class_logger.logger.error(err)

    def create_client_log_file(self, client_name: str, handle_list: list,
                               client_ram_template: dict, file_ram_template: dict) -> None:
        """
        Creates a custom log file to each client.
        :param client_name: For the client username.
        :param handle_list: For the client summery list.
        :param client_ram_template: For the client RAM dictionary.
        :param file_ram_template: For the file RAM dictionary.
        :return: None.
        """
        try:
            file_path = path.join(f'{self.clients_root_dir_path}/{client_name}/{client_name}.log')
            file_permissions = self.set_file_permissions(file_path)

            with open(file_path, file_permissions) as log_file:
                log_file.write("\n" + "=" * MAX_CHAR_FORMAT)
                log_file.write(f"\nServer and '{client_name}' connection summery from {self.last_seen()}:")
                log_file.write("\n" + "-" * MAX_CHAR_FORMAT + "\n\n")
                log_file.write("Connection Summery:\n")
                for line in handle_list:
                    log_file.write(f"{line}\n")

                # For client RAM template
                log_file.write("\nDatabase Summery:\n")
                for key, value in client_ram_template.items():
                    log_file.write(f"{key}: {value}\n")

                # For files RAM template
                for key, value in file_ram_template.items():
                    if key == "ID":
                        pass
                    else:
                        log_file.write(f"{key}: {value}\n")
                log_file.write("=" * MAX_CHAR_FORMAT)

        except Exception as err:
            raise SessionLogsError(f"Unable to write session logs to '{client_name}' log file, Error: {err}")

    def create_a_copy_of_client_file(self, client_name: str, file_name: str, content: bytes) -> str:
        """
        Creates server directory for client files.
        Server will create a subdirectory for each registered client with his username.
        Client file will be stored in his subdirectory.
        :param client_name: For the client username.
        :param file_name: For the client file name.
        :param content: For the file content.
        :return: A string representation of the new created file path.
        """
        client_directory = f"{self.clients_root_dir_path}/{client_name}"
        file_path = path.join(f"{client_directory}/{file_name}")
        if self.is_exists(client_directory):
            try:
                with open(file_path, 'wb') as write_file:
                    write_file.write(content)
                self.class_logger.logger.debug(f"Created folder for '{client_name}' successfully.")
                return file_path

            except Exception as err:
                raise CreateClientFileCopyError(f"Unable to create folder for '{client_name}', Error: {err}")

    def remove_file(self, file_path: str) -> None:
        """
        Removes client subdirectory and saved files.
        :param file_path: For the file to remove.
        """
        try:
            remove(file_path)
            self.class_logger.logger.debug(f"Removed file '{file_path}' successfully.")

        except FileNotFoundError as err:
            raise RemoveFileError(f"Unable to remove file '{file_path}', Error: {err}")

    def is_exists(self, file_path: str) -> bool:
        """
        Validates if a given path exists.
        :param file_path: For the path to validate.
        :return: True if the path exists, False otherwise.
        """
        if path.exists(file_path):
            self.class_logger.logger.debug(f"Validate {file_path} successfully.")
            return True
        else:
            self.class_logger.logger.debug(f"Invalid path {file_path}.")
            return False

    def set_file_permissions(self, file_path: str) -> str:
        """
        Create the file if not exist with write permission,
        Otherwise add to file with append permissions.
        :param file_path: For the file to Check.
        :return: a String representation of the file permissions.
        """
        if self.is_exists(file_path):
            return 'a'
        else:
            return 'w'

    def validate_length(self, item: bytes, wanted_length: int) -> bool:
        """
        Validates a given item length.
        :param item: For the item to validate.
        :param wanted_length: For the item wanted length.
        :return: True if item length has been validated successfully, False otherwise.
        """
        if len(item) != wanted_length:
            self.class_logger.logger.error(f"Invalid size for '{item}'.")
            return False
        else:
            self.class_logger.logger.debug(f"'{item}' size validation success.")
            return True


# Constants
MAX_CHAR_FORMAT = 70
ENUMERATE_START_INDEX = 1


def server_welcome_message(log_file_path: str) -> None:
    """
    Customize format Welcome message to show in console at server start.
    :param log_file_path: For the server log file path.
    :return: None.
    """
    print("=" * MAX_CHAR_FORMAT)
    title = f"Welcome to Encrypted File Server!!!"
    print(title)
    for letter in range(len(title)):
        print("-", end='')
    content = "\n- The server will run automatically with indicative outputs.\n- " \
              f"In order to read the running processes in detail,\n  please read server logs at: '{log_file_path}'."
    print(content)
    print("=" * MAX_CHAR_FORMAT + "\n")


# Customize ASCII Art to show in console at server start
server_art = """
  _____                             _           _   _____ _ _        ____                           
 | ____|_ __   ___ _ __ _   _ _ __ | |_ ___  __| | |  ___(_) | ___  / ___|  ___ _ ____   _____ _ __ 
 |  _| | '_ \ / __| '__| | | | '_ \| __/ _ \/ _` | | |_  | | |/ _ \ \___ \ / _ \ '__\ \ / / _ \ '__|
 | |___| | | | (__| |  | |_| | |_) | ||  __/ (_| | |  _| | | |  __/  ___) |  __/ |   \ V /  __/ |   
 |_____|_| |_|\___|_|   \__, | .__/ \__\___|\__,_| |_|   |_|_|\___| |____/ \___|_|    \_/ \___|_|   
                        |___/|_|                                                                   
"""

"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class UtilsConfigurationError(Exception):
    pass


class ParsingPortFileError(Exception):
    pass


class PortRangeError(Exception):
    pass


class Base64Error(Exception):
    pass


class ConversionError(Exception):
    pass


class CRCError(Exception):
    pass


class UpdateDictionaryError(Exception):
    pass


class CreateDirectoryError(Exception):
    pass


class CreateClientFileCopyError(Exception):
    pass


class SessionLogsError(Exception):
    pass


class RemoveFileError(Exception):
    pass
