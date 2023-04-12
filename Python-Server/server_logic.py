from socket import socket, error as socket_error
from abc import ABC, abstractmethod
from server_db import ServerDB, CreateTableError, NotFoundError, UpdateTableError, InsertValueError, ExportDBError
from config_parser import get_configuration, ConfigConstants, GetConfigurationError
from server_utils import ServerUtils, SessionLogsError, UpdateDictionaryError, Base64Error, ConversionError, \
    CreateClientFileCopyError, RemoveFileError, CRCError, CreateDirectoryError
from protocol_handler import ProtocolHandlersUtils, ProtocolHandler, UnpackPacketError, PackEncryptedKeyPacketError, \
    PackRegisterApprovedPacketError, PackNoPayloadPacketError, PackCRCPacketError
from encryptor import Encryptor, CreateAESSessionKeyError, EncryptServerAESKeyError, \
    DecryptFileContentError, CreateClientDecryptedFileError
from logger import Logger, CustomFilter
from server_templates import ParsingConstants, ServerDBConstants

"""
ServerInterfaces Class is an auxiliary class to improve server performances.
"""


class ServerInterfaces(ABC):

    @abstractmethod
    def send_packet(self, sock: socket, packet: bytes) -> None:
        """Main send packet method to be override."""
        pass

    @abstractmethod
    def receive_packet(self, sock: socket) -> bytes:
        """Main receive packet method to be override."""
        pass


"""
ServerLogic Class represents the client handling methods and logic.
"""


class ServerLogic(ServerInterfaces):

    def __init__(self):
        """Class Constructor."""
        self.db = ServerDB(self.set_server_logic_configuration(ConfigConstants.SERVER_DATABASE_NAME))
        self.clients_table_name = self.set_server_logic_configuration(ConfigConstants.CLIENTS_TABLE_NAME)
        self.files_table_name = self.set_server_logic_configuration(ConfigConstants.FILES_TABLE_NAME)
        self.server_utils = ServerUtils()
        self.protocol_utils = ProtocolHandlersUtils()
        self.protocol_handler = ProtocolHandler()
        self.encryptor = Encryptor()
        self.class_logger = Logger('Server Logic')

    @staticmethod
    def set_server_logic_configuration(value: str) -> str:
        """
        Return the server logic needed configuration from config file.
        Mainly for error handling.
        :return: The needed value to config.
        """
        try:
            return str(get_configuration(value))

        except GetConfigurationError as err:
            raise ServerLogicConfigurationError(err)

    def create_server_database(self) -> None:
        """
        Creates the needed Server database.
        :return: None.
        """
        try:
            # Create clients DB table
            self.db.create_table(self.clients_table_name,
                                 f"{ServerDBConstants.ID} {ServerDBConstants.TEXT_TYPE} {ServerDBConstants.PRIMARY_KEY}, "
                                 f"{ServerDBConstants.CLIENT_NAME} {ServerDBConstants.TEXT_TYPE}, "
                                 f"{ServerDBConstants.PUBLIC_KEY}, "
                                 f"{ServerDBConstants.LAST_SEEN} {ServerDBConstants.DATE_TYPE}, "
                                 f"{ServerDBConstants.AES_KEY}")

            # Create files DB table
            self.db.create_table(self.files_table_name,
                                 f"{ServerDBConstants.ID} {ServerDBConstants.TEXT_TYPE}, "
                                 f"{ServerDBConstants.FILE_NAME} {ServerDBConstants.TEXT_TYPE}, "
                                 f"{ServerDBConstants.FILE_PATH} {ServerDBConstants.TEXT_TYPE}, "
                                 f"{ServerDBConstants.FILE_CRC} {ServerDBConstants.PRIMARY_KEY}, "
                                 f"{ServerDBConstants.VERIFIED} {ServerDBConstants.BOOLEAN_TYPE}")

        except CreateTableError as err:
            raise CreateServerDBError(f"Unable to create server DB, Error: {err}")

    def setup_server_logic(self):
        """
        Setup the server needed ServerLogic methods.
        :return: None
        """
        try:
            self.create_server_database()
            self.server_utils.create_clients_root_directory()

        except (CreateServerDBError, CreateDirectoryError) as err:
            raise SetupServerLogicError(err)

    def parse_socket_object(self, connection: socket, parsed_format: str) -> str:
        """
        Parse a given socket object to a custom format.
        Mainly for logging and printing purposes.
        :param connection: For the socket to parse.
        :param parsed_format: For the format to parse to.
        :return: A string representation of the customize socket format.
        """
        value = None
        try:
            if parsed_format == ParsingConstants.LOG:
                value = f"source {connection.getsockname()} for peer {connection.getpeername()}"
            elif parsed_format == ParsingConstants.CONSOLE:
                value = f"{connection.getpeername()[0]}:{connection.getpeername()[1]}"
            self.class_logger.logger.debug(f"Parsed {connection} to {value} successfully.")
            return value

        except (OSError, ValueError) as err:
            self.class_logger.logger.error(f"Unable to parse {connection}, Error: {err}")

    def create_client_unique_log_file(self, username: str, handle_list: list,
                                      client_template: dict, files_template: dict) -> None:
        """
        Creates a unique log file per client according to a given configuration.
        :param username: For the client username.
        :param handle_list: For the client session handle list.
        :param client_template: For the client RAM template to write from.
        :param files_template: For the file RAM template to write from.
        :return: None.
        """
        try:
            flag = str(get_configuration(ConfigConstants.CLIENT_UNIQUE_LOG_FILE))

            if flag == ConfigConstants.TRUE.lower():
                try:
                    self.server_utils.create_client_log_file(username, handle_list, client_template, files_template)
                    self.class_logger.logger.info(f"Wrote session logs to '{username}' directory successfully.")

                except SessionLogsError as err:
                    self.class_logger.logger.error(err)

        except GetConfigurationError as err:
            self.class_logger.logger.error(err)

    def export_server_db_to_json(self) -> None:
        """
        Exports server database to a JSON file according to a given configuration.
        :return: None.
        """
        try:
            flag = str(get_configuration(ConfigConstants.EXPORT_DB_TO_JSON))
            file_path = str(get_configuration(ConfigConstants.DB_JSON_FILE_PATH))

            if flag == ConfigConstants.TRUE.lower():
                try:
                    tables = self.db.get_all_database_tables()
                    self.db.export_table_to_json(tables, file_path)
                    self.class_logger.logger.debug(f"Exported '{self.db.name}' to JSON file successfully.")

                except (NotFoundError, ExportDBError) as err:
                    self.class_logger.logger.error(err)

        except GetConfigurationError as err:
            self.class_logger.logger.error(err)

    def send_packet(self, connection: socket, packet: bytes) -> None:
        """
        Main send method to send packed packet to client.
        :param connection: For the client connection to send to.
        :param packet: For the packet to send.
        :return: None
        """
        send_message = self.parse_socket_object(connection, parsed_format=ParsingConstants.LOG)
        try:
            connection.send(packet)
            self.class_logger.logger.debug(
                f"Sent packet from {send_message} successfully.")

        except Exception as err:
            connection.close()
            raise SendPacketError(f"Unable to send message from {send_message}, Error: {err}")

    def receive_packet(self, connection: socket) -> bytes:
        """
        Main receive method, receives client packet and return it for unpacking purposes.
        :param connection: For the clients connection to receive from.
        :return: The received packet.
        """
        receive_message = self.parse_socket_object(connection, parsed_format=ParsingConstants.LOG)
        try:
            while True:
                packet = connection.recv(self.protocol_utils.SERVER_RECEIVE_BUFFER_SIZE)
                if not packet:
                    # Client has disconnected
                    break
                self.class_logger.logger.debug(f"Received packet from {receive_message} successfully.")
                return packet

        except (socket_error, ValueError) as err:
            connection.close()
            raise ReceivePacketError(f"Unable to receive request from {receive_message}, Error: {err}")

    def receive_file_content(self, connection: socket, size: int) -> bytes:
        """
        Auxiliary receive method to receive large files content.
        Supports TCP packet fragmentation and reassembly.
        :param connection: For the clients connection to receive from.
        :param size: For the file content size.
        :return: The received file content after reassembly.
        """
        receive_message = self.parse_socket_object(connection, parsed_format=ParsingConstants.LOG)
        packet_fragments = b''
        try:
            while len(packet_fragments) < size:
                fragment = connection.recv(size - len(packet_fragments))
                if not fragment:
                    # Client has disconnected
                    break
                packet_fragments += fragment
            self.class_logger.logger.debug(
                f"Received packet from {receive_message} successfully.")
            return packet_fragments

        except (socket_error, ValueError) as err:
            connection.close()
            raise ReceivePacketError(f"Unable to receive request from {receive_message}, Error: {err}")

    def process_register_request(self, connection: socket, client_template: dict,
                                 files_template: dict, summery: list) -> None:
        """
        Processing registration request with a given client.
        :param connection: For the client connection.
        :param client_template: For the client RAM template to update.
        :param files_template: For the files RAM template to update.
        :param summery: For the client summery list to update.
        :return: None.
        """
        registration_message = f"Processing registration request from " \
                               f"{self.parse_socket_object(connection, parsed_format=ParsingConstants.CONSOLE)}"
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} {registration_message}")
        self.class_logger.logger.info(registration_message)

        # Receiving registration request packet from client and unpack it
        try:
            registration_request = self.receive_packet(connection)
            registration_request_unpacked = self.protocol_handler.unpack_request(
                self.protocol_utils.CLIENT_REG_REQUEST, registration_request)

            # Unpacking client username from received packet
            client_username = registration_request_unpacked[self.protocol_utils.CLIENT_USERNAME_INDEX][
                              :registration_request_unpacked[self.protocol_utils.CLIENT_PAYLOAD_SIZE_INDEX]].decode()

            # Log output
            self.class_logger.logger.info(f"Received '{client_username}' registration request.")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Received registration request.")

            # Update client RAM dict
            self.server_utils.update_ram_dict(client_template, ServerDBConstants.CLIENT_NAME, client_username)

            # Setting a customize log field to the username of the new connected client.
            CustomFilter.filter_name = client_username

            # Handle registration request protocol logic
            self.handle_registration_request_logic(connection, client_username,
                                                   client_template, files_template, summery)

        except (ReceivePacketError, UnpackPacketError, UpdateDictionaryError, ValueError) as err:
            self.class_logger.logger.error(err)
            summery.append(err)

    def process_public_key_request(self, connection: socket, template: dict, summery: list) -> None:
        """
        Processing keys exchange request with a given client.
        :param connection: For the client connection.
        :param template: For the client RAM template to update.
        :param summery: For the client summery list to update.
        :return: None
        """
        client_username = template[ServerDBConstants.CLIENT_NAME]
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} Processing public key request from Alias "
              f"'{client_username}'.")

        # Receiving public key request packet from client and unpack it
        try:
            client_pub_key_packet = self.receive_packet(connection)
            client_pub_key_packet_unpacked = self.protocol_handler.unpack_request(
                self.protocol_utils.CLIENT_PUBKEY_REQUEST,
                client_pub_key_packet)

            # Fetching needed data
            client_id = self.db.fetch_by_column_value(self.clients_table_name, ServerDBConstants.ID,
                                                      ServerDBConstants.CLIENT_NAME, client_username)
            client_public_key = client_pub_key_packet_unpacked[self.protocol_utils.CLIENT_PUBKEY_INDEX]

            # Lof output
            self.class_logger.logger.info(f"Received '{client_username}' RSA public key request.")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Received RSA public key.")

            # Handle public key request protocol logic
            self.handle_public_key_request_logic(connection, client_public_key, client_id,
                                                 client_username, template, summery)

        except (ReceivePacketError, UnpackPacketError, NotFoundError, ValueError) as err:
            self.class_logger.logger.error(err)
            summery.append(err)

    def process_encrypted_file_request(self, connection: socket, client_template: dict,
                                       files_template: dict, summery: list) -> None:
        """
        Processing encrypted file request with a given client.
        :param connection: For the client connection.
        :param client_template: For the client RAM template to update.
        :param files_template: For the files RAM template to update.
        :param summery: For the client summery list to update.
        :return: None
        """
        client_username = client_template[ServerDBConstants.CLIENT_NAME]
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} Processing encrypted file request from Alias "
              f"'{client_username}'.")

        # Receiving encrypted file request packet from client and unpack it
        try:

            # Receiving encrypted file request header to adjust sizes
            encrypted_file_request_header = self.receive_packet(connection)
            encrypted_file_request_header_unpacked = self.protocol_handler.unpack_request(
                self.protocol_utils.CLIENT_ENCRYPTED_FILE_REQUEST, encrypted_file_request_header)

            # Log output
            self.class_logger.logger.info(f"Received '{client_username}' encrypted file request header.")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Received encrypted file header.")

            # Fetching and parsing needed details
            client_uuid = self.db.fetch_by_column_value(self.clients_table_name, ServerDBConstants.ID,
                                                        ServerDBConstants.CLIENT_NAME, client_username)
            server_session_key = self.db.fetch_by_column_value(self.clients_table_name, ServerDBConstants.AES_KEY,
                                                               ServerDBConstants.ID, client_uuid)
            file_content_size = encrypted_file_request_header_unpacked[
                self.protocol_utils.CLIENT_FILE_REQUEST_CONTENT_SIZE_INDEX]

            file_name_size = encrypted_file_request_header_unpacked[self.protocol_utils.CLIENT_PAYLOAD_SIZE_INDEX] \
                             - file_content_size - self.protocol_utils.CLIENT_UUID_SIZE

            file_name = encrypted_file_request_header_unpacked[
                            self.protocol_utils.CLIENT_FILE_NAME_INDEX][:file_name_size].decode()

            # Handle encrypted file request protocol logic
            self.handle_encrypted_file_request_logic(connection, client_username, client_uuid,
                                                     server_session_key, file_content_size, file_name_size,
                                                     file_name, files_template, summery)

        except (ReceivePacketError, UnpackPacketError, NotFoundError, ValueError) as err:
            self.class_logger.logger.error(err)
            summery.append(err)

    def process_crc_validation_request(self, connection: socket, client_template: dict,
                                       files_template: dict, summery: list) -> None:
        """
        Processing validation of file CRC request with a given client.
        :param connection: For the client socket.
        :param client_template: For the client RAM template to update.
        :param files_template: For the files RAM template to update.
        :param summery: For the client summery list to update.
        :return: None
        """
        client_username = client_template[ServerDBConstants.CLIENT_NAME]
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} Processing CRC Validation request from Alias "
              f"'{client_username}'.")

        # Fetching needed details from RAM dict
        try:

            file_crc = files_template[ServerDBConstants.FILE_CRC]
            file_name = files_template[ServerDBConstants.FILE_NAME]
            file_path = files_template[ServerDBConstants.FILE_PATH]

            # Handle CRC request protocol logic
            self.handle_crc_request_logic(connection, client_username, file_name, file_path,
                                          file_crc, client_template, files_template, summery)

        except ValueError as err:
            self.class_logger.logger.error(err)
            summery.append(err)

    def handle_registration_request_logic(self, connection: socket, username: str, client_template: dict,
                                          files_template: dict, summery: list) -> None:
        """
        Auxiliary method to handle all registration request protocol logic.
        :param connection: For the client socket.
        :param username: For the client username.
        :param client_template: For the client RAM template to update.
        :param files_template: For the files RAM template to update.
        :param summery: For the client summery list to update.
        :return: None.
        """
        # For username has not yet been registered case
        if self.db.insert_if_not_exists(self.clients_table_name, ServerDBConstants.CLIENT_NAME, username):

            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Inserting new user '{username}' to server DB.")

            # Create new registered client folder
            self.server_utils.create_client_unique_directory(username)

            # Generate new registered client UUID and validate it's length
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Creating UUID for new registered user '{username}'.")
            client_uuid = self.server_utils.generate_client_uuid()

            # Validating UUID length
            if self.server_utils.validate_length(client_uuid, self.protocol_utils.CLIENT_UUID_SIZE):

                self.class_logger.logger.info(f"New registered client '{username}' ID is: {client_uuid.hex()}")

                # Updating server and RAM databases
                try:
                    self.db.update_table(self.clients_table_name, ServerDBConstants.LAST_SEEN,
                                         client_template[ServerDBConstants.LAST_SEEN],
                                         ServerDBConstants.CLIENT_NAME, username)

                    self.db.update_table(self.clients_table_name, ServerDBConstants.ID, client_uuid.hex(),
                                         ServerDBConstants.CLIENT_NAME, username)

                    self.server_utils.update_ram_dict(client_template, ServerDBConstants.ID, client_uuid.hex())

                    self.server_utils.update_ram_dict(files_template, ServerDBConstants.ID, client_uuid.hex())

                except (UpdateTableError, InsertValueError, UpdateDictionaryError) as err:
                    self.class_logger.logger.error(err)

            # UUID length is not valid
            else:
                self.class_logger.logger.error(f"Client UUID: '{client_uuid}' validation error.")

            # Packing registration approval packet and sent it to client
            try:
                registration_approval = self.protocol_handler.pack_registration_approved_response(
                    self.protocol_utils.SERVER_REG_SUCCESS_RESPONSE, client_uuid)
                self.send_packet(connection, registration_approval)

                # Log output
                summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Sending registration approval to "
                               f"{client_uuid.hex()} Alias: '{username}'.")

            except (PackRegisterApprovedPacketError, SendPacketError) as err:
                summery.append(err)

        # For username already registered case
        else:
            # Fetching needed data and updating RAM dictionary
            try:
                client_id = self.db.fetch_by_column_value(self.clients_table_name, ServerDBConstants.ID,
                                                          ServerDBConstants.CLIENT_NAME, username)
                self.server_utils.update_ram_dict(client_template, ServerDBConstants.ID, client_id)
                self.server_utils.update_ram_dict(files_template, ServerDBConstants.ID, client_id)

            except (NotFoundError, UpdateDictionaryError) as err:
                self.class_logger.logger.error(err)

            # Validate client directory for client directory deletion error
            if not self.server_utils.is_exists(f"{self.server_utils.clients_root_dir_path}/{username}"):
                self.server_utils.create_client_unique_directory(username)

            # Packing registration error packet and sent it to client
            try:
                registration_error = self.protocol_handler.pack_no_payload_response(
                    self.protocol_utils.SERVER_REG_FAILED_RESPONSE)
                self.send_packet(connection, registration_error)

                # Log output
                self.class_logger.logger.info(f"'{username}' already registered, sending registration error to client.")
                summery.append(f"{ParsingConstants.SERVER_CONSOLE_FAIL} You are already registered.")

            except (PackNoPayloadPacketError, SendPacketError) as err:
                summery.append(err)

    def handle_public_key_request_logic(self, connection: socket, client_public_key: bytes, client_id: str,
                                        username: str, template: dict, summery: list) -> None:
        """
         Auxiliary method to handle all public key request protocol logic.
        :param connection: For the client socket.
        :param client_public_key: For the client RSA public key.
        :param client_id: For the client UUID.
        :param username: For the client username.
        :param template: For the client RAM template to update.
        :param summery: For the client summery list to update.
        :return: None.
        """
        # Validating client public key length
        if self.server_utils.validate_length(client_public_key, self.protocol_utils.CLIENT_PUBKEY_SIZE):

            # Log output
            self.class_logger.logger.info(f"Generated server private AES key for '{username}'")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Generated server private AES key.")

            # Encode client public key in base64 format
            encoded_public_key = None
            try:
                encoded_public_key = self.server_utils.encode_base64(client_public_key)

            except Base64Error as err:
                self.class_logger.logger.error(err)

            # Update server database and RAM dictionary
            try:
                self.db.update_table(self.clients_table_name, ServerDBConstants.PUBLIC_KEY, encoded_public_key,
                                     ServerDBConstants.ID, client_id)
                self.server_utils.update_ram_dict(template, ServerDBConstants.PUBLIC_KEY, encoded_public_key)
                self.server_utils.update_ram_dict(template, ServerDBConstants.PUBLIC_KEY_LENGTH, len(client_public_key))

            except (UpdateTableError, UpdateDictionaryError) as err:
                self.class_logger.logger.error(err)

            # Creating server AES session key
            server_session_aes_key = None
            try:
                server_session_aes_key = self.encryptor.create_aes_session_key()

            except CreateAESSessionKeyError as err:
                self.class_logger.logger.error(err)

            # Validating server AES key length
            if self.server_utils.validate_length(server_session_aes_key, self.protocol_utils.SERVER_AES_KEY_SIZE):

                # Encode server AES key in base64 format
                encoded_aes_key = self.server_utils.encode_base64(server_session_aes_key)
                self.db.update_table(self.clients_table_name, ServerDBConstants.AES_KEY,
                                     encoded_aes_key, ServerDBConstants.ID, client_id)

                # Encrypting server AES key with client public key
                encrypted_key = None
                try:
                    encrypted_key = self.encryptor.encrypt(server_session_aes_key, client_public_key)

                    # Log output
                    self.class_logger.logger.info(f"Encrypted private key with client '{username}' public key.")
                    summery.append(
                        f"{ParsingConstants.SERVER_CONSOLE_ACK} Encrypted private key with client public key.")

                except EncryptServerAESKeyError as err:
                    self.class_logger.logger.error(err)

                # Validating encrypted AES key length
                if self.server_utils.validate_length(encrypted_key, self.protocol_utils.SERVER_ENCRYPTED_AES_KEY_SIZE):

                    # Encode server AES encrypted key in base64 format
                    encoded_encrypted_key = self.server_utils.encode_base64(encrypted_key)

                    # Update server database and RAM dictionary
                    try:
                        self.server_utils.update_ram_dict(template, ServerDBConstants.ENCRYPTED_AES_KEY,
                                                          encoded_encrypted_key)
                        self.server_utils.update_ram_dict(template, ServerDBConstants.ENCRYPTED_AES_KEY_LENGTH,
                                                          len(encrypted_key))
                        self.server_utils.update_ram_dict(template, ServerDBConstants.AES_KEY, encoded_aes_key)
                        self.server_utils.update_ram_dict(template, ServerDBConstants.AES_KEY_LENGTH,
                                                          len(server_session_aes_key))

                    except UpdateDictionaryError as err:
                        self.class_logger.logger.error(err)

                # Server encrypted AES key validation error
                else:
                    self.class_logger.logger.error(f"Server encrypted AES key length validation error.")

            # Server AES key validation error
            else:
                self.class_logger.logger.error(f"Server AES session key length validation error.")

            # Packing public key error packet and sent it to client
            try:
                # Fetching needed data
                converted_client_id = self.server_utils.convert_hex_to_bytes(client_id)
                encrypted_key = self.server_utils.decode_base64(template[ServerDBConstants.ENCRYPTED_AES_KEY])

                # Pack and send
                encrypted_key_packet = self.protocol_handler.pack_encrypted_key_response(
                    self.protocol_utils.SERVER_ENCRYPTED_KEY_RESPONSE, converted_client_id, encrypted_key)
                self.send_packet(connection, encrypted_key_packet)

                # Log output
                self.class_logger.logger.info(f"Sent encrypted key response to client '{username}'.")
                summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Sent encrypted key response to client.")

            except (Base64Error, ConversionError, PackEncryptedKeyPacketError, SendPacketError) as err:
                summery.append(err)

        # Client public key validation error
        else:
            self.class_logger.logger.error(f"Client public key length validation error.")

    def handle_encrypted_file_request_logic(self, connection: socket, username: str, client_id: str,
                                            server_session_key: str, file_content_size: int, copy_file_name_size: int,
                                            copy_file_name: str, template: dict, summery: list) -> None:
        """
        Auxiliary method to handle all encrypted file request protocol logic.
        :param connection: For the client socket.
        :param username: For the client username.
        :param client_id: For the client UUID.
        :param server_session_key: For the server AES session key.
        :param file_content_size: For the received file content size.
        :param copy_file_name_size: For the received file name size.
        :param copy_file_name: For the received file name.
        :param template: For the files RAM template to update.
        :param summery: For the client summery list to update.
        :return: None.
        """
        # Updating RAM database with the received file parameters
        try:
            self.server_utils.update_ram_dict(template, ServerDBConstants.ID, client_id)
            self.server_utils.update_ram_dict(template, ServerDBConstants.COPY_FILE_NAME, copy_file_name)
            self.server_utils.update_ram_dict(template, ServerDBConstants.COPY_FILE_NAME_SIZE, copy_file_name_size)
            self.server_utils.update_ram_dict(template, ServerDBConstants.COPY_FILE_CONTENT_SIZE, file_content_size)

        except UpdateDictionaryError as err:
            self.class_logger.logger.error(err)

        # Receiving encrypted file content and creating a file copy
        try:
            encrypted_file_content = self.receive_file_content(connection, file_content_size)
            encrypted_file_path = self.server_utils.create_a_copy_of_client_file(username, copy_file_name,
                                                                                 encrypted_file_content)
            self.server_utils.update_ram_dict(template, ServerDBConstants.COPY_FILE_PATH, encrypted_file_path)

            # Log output
            self.class_logger.logger.info(f"Received '{username}' encrypted file request content.")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Received Encrypted file content.")

        except (ReceivePacketError, CreateClientFileCopyError, UpdateDictionaryError) as err:
            self.class_logger.logger.error(err)
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_FAIL} {err}")

        # Creating a decrypted client file
        try:
            encrypted_file_path = template[ServerDBConstants.COPY_FILE_PATH]
            decoded_key = self.server_utils.decode_base64(server_session_key)
            decrypted_content = self.encryptor.decrypt_file(encrypted_file_path, decoded_key)
            decrypted_file_path = encrypted_file_path[:-ProtocolHandlersUtils.ENCRYPTED_FILE_NAME_SUFFIX]
            file_name = copy_file_name[:-ProtocolHandlersUtils.ENCRYPTED_FILE_NAME_SUFFIX]
            self.encryptor.create_client_decrypted_file(decrypted_file_path, decrypted_content)
            self.server_utils.remove_file(encrypted_file_path)

            # Log output
            self.class_logger.logger.info(f"Decrypted '{username}' file successfully in path '{decrypted_file_path}'.")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Created decrypted file in '{decrypted_file_path}'.")

            # Update RAM database
            self.server_utils.update_ram_dict(template, ServerDBConstants.FILE_PATH, decrypted_file_path)
            self.server_utils.update_ram_dict(template, ServerDBConstants.FILE_NAME, file_name)
            self.server_utils.update_ram_dict(template, ServerDBConstants.FILE_NAME_SIZE, len(copy_file_name))
            self.server_utils.update_ram_dict(template, ServerDBConstants.FILE_CONTENT_SIZE, len(decrypted_content))

        except (Base64Error, DecryptFileContentError, RemoveFileError, CreateClientDecryptedFileError,
                UpdateDictionaryError) as err:
            self.class_logger.logger.error(err)
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Unable to create file.")
            connection.close()

        # Calculating file CRC and updating RAM database
        try:
            decrypted_file_path = template[ServerDBConstants.FILE_PATH]
            file_crc = self.server_utils.calculate_crc32(decrypted_file_path)
            self.server_utils.update_ram_dict(template, ServerDBConstants.FILE_CRC, file_crc)

            # Fetching needed data
            file_name = template[ServerDBConstants.FILE_NAME]
            file_path = template[ServerDBConstants.FILE_PATH]

            # Inserting new file entries to server database according to CRC to avoid duplicates
            if self.db.insert_if_not_exists(self.files_table_name, ServerDBConstants.FILE_CRC, str(file_crc)):
                self.db.update_table(self.files_table_name, ServerDBConstants.ID, client_id,
                                     ServerDBConstants.FILE_CRC, str(file_crc))
                self.db.update_table(self.files_table_name, ServerDBConstants.FILE_NAME, file_name,
                                     ServerDBConstants.FILE_CRC, str(file_crc))
                self.db.update_table(self.files_table_name, ServerDBConstants.FILE_PATH, file_path,
                                     ServerDBConstants.FILE_CRC, str(file_crc))
            else:
                self.class_logger.logger.info(f"File '{file_path}' already exists in server DB.")

        except (UpdateTableError, UpdateDictionaryError, CRCError) as err:
            self.class_logger.logger.error(err)

        # Packing CRC response packet and send it to client
        try:
            # Fetching and parsing needed data
            file_crc = template[ServerDBConstants.FILE_CRC]
            file_name = template[ServerDBConstants.FILE_NAME]
            converted_client_id = self.server_utils.convert_hex_to_bytes(client_id)
            payload_size = self.protocol_utils.CLIENT_UUID_SIZE + file_content_size + len(file_name) + len(str(file_crc))

            # Pack and send
            client_file_crc_response = self.protocol_handler.pack_file_crc_response(
                self.protocol_utils.SERVER_FILE_CRC_RESPONSE, payload_size,
                converted_client_id, file_content_size, file_name, str(file_crc).encode())
            self.send_packet(connection, client_file_crc_response)

            # Log output
            self.class_logger.logger.info(f"Sent CRC response to client '{username}'.")
            summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Sent CRC response.")

        except (ConversionError, PackCRCPacketError, SendPacketError) as err:
            self.class_logger.logger.error(err)

    def handle_crc_request_logic(self, connection: socket, username: str, file_name: str, file_path: str,
                                 file_crc: str, client_template: dict, files_template: dict, summery: list) -> None:
        """
        Auxiliary method to handle all CRC request protocol logic.
        :param connection: For the client socket.
        :param username: For the client username.
        :param file_name: For the file name.
        :param file_path: For the file path to calculate CRC.
        :param file_crc: For the client received file CRC.
        :param client_template: For the client RAM template to update.
        :param files_template: For the files RAM template to update.
        :param summery: For the client summery list to update.
        :return: None.
        """
        # CRC validation main loop
        for i in range(self.protocol_utils.CRC_RE_RECEIVE_MAX):

            # Receive CRC request packet from client and unpack it
            crc_request_code = None
            try:
                crc_validation_request = self.receive_packet(connection)
                crc_validation_request_unpacked = self.protocol_handler.unpack_request(
                    self.protocol_utils.CLIENT_UNPACK_CRC_REQUEST_CODE, crc_validation_request)

                crc_request_code = crc_validation_request_unpacked[self.protocol_utils.CLIENT_REQUEST_CODE_INDEX]

                # Log output
                self.class_logger.logger.info(f"Received '{username}' CRC request.")
                summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} Received CRC request.")

            except (ReceivePacketError, UnpackPacketError, TypeError) as err:
                self.class_logger.logger.error(err)

            # For CRC is valid case
            if crc_request_code == self.protocol_utils.CLIENT_VALID_CRC_REQUEST:

                print(f"{ParsingConstants.SERVER_CONSOLE_ACK} CRC validation success for '{file_name}' "
                      f"from client '{username}'.")

                # CRC is valid, update server and RAM databases
                try:
                    self.db.update_table(self.files_table_name, ServerDBConstants.VERIFIED, True,
                                         ServerDBConstants.FILE_CRC, file_crc)
                    self.server_utils.update_ram_dict(files_template, ServerDBConstants.VERIFIED, True)
                except (UpdateTableError, UpdateDictionaryError) as err:
                    self.class_logger.logger.error(err)

                # Packing CRC validation response and sent it to client
                try:
                    crc_validation_accept = self.protocol_handler.pack_no_payload_response(
                        self.protocol_utils.SERVER_ACK_RESPONSE)

                    # Log output
                    self.class_logger.logger.info(f"CRC from '{username}' has been verified successfully.")
                    summery.append(f"{ParsingConstants.SERVER_CONSOLE_ACK} CRC has been verified on try #{i + 1}.")

                    self.send_packet(connection, crc_validation_accept)
                    break

                except (PackNoPayloadPacketError, SendPacketError) as err:
                    self.class_logger.logger.error(err)

            # For CRC request code 1105
            elif crc_request_code == self.protocol_utils.CLIENT_INVALID_CRC_REQUEST:
                invalid_crc_message = f"{ParsingConstants.SERVER_CONSOLE_FAIL} Invalid CRC, try #{i + 1}."
                self.class_logger.logger.info(invalid_crc_message)
                summery.append(invalid_crc_message)

                # Waiting for CRC request code 1103
                self.process_encrypted_file_request(connection, client_template, files_template, summery)

            # For CRC request code 1106
            elif crc_request_code == self.protocol_utils.CLIENT_INVALID_CRC_FOURTH_TIME_REQUEST:

                # Remove the corrupted file
                self.server_utils.remove_file(file_path)

                # Log output
                self.class_logger.logger.info(
                    f"{ParsingConstants.SERVER_CONSOLE_FAIL} Invalid CRC error from client '{username}', "
                    f"deleting file '{file_name}'.")
                summery.append(f"{ParsingConstants.SERVER_CONSOLE_FAIL} '{file_path}' has been removed.")

                # Update server and RAM databases
                try:
                    self.db.update_table(self.files_table_name, ServerDBConstants.VERIFIED, False,
                                         ServerDBConstants.FILE_CRC, file_crc)
                    self.server_utils.update_ram_dict(files_template, ServerDBConstants.VERIFIED, False)

                    # Log output
                    self.class_logger.logger.debug(f"CRC from '{username}' is invalid after {i + 1} tries.")
                    summery.append(f"{ParsingConstants.SERVER_CONSOLE_FAIL} CRC is invalid after {i + 1} tries.")
                    break

                except (UpdateTableError, UpdateDictionaryError) as err:
                    self.class_logger.logger.error(err)


"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class ServerLogicConfigurationError(Exception):
    pass


class SetupServerLogicError(Exception):
    pass


class SendPacketError(Exception):
    pass


class ReceivePacketError(Exception):
    pass


class CreateServerDBError(Exception):
    pass
