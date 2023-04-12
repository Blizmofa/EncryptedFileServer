from socket import socket, AF_INET, SOCK_STREAM, error as socket_error
from sys import exit
from threading import Thread, Lock
from logger import Logger
from server_db import UpdateTableError
from server_utils import ServerUtils, server_art, server_welcome_message
from server_logic import ServerLogic, ServerDBConstants, ParsingConstants, SetupServerLogicError
from server_templates import ram_clients_template, ram_files_template

"""
ServerCore Class represents a Multi Threaded server,
Can process requests from multiple clients simultaneously.
"""


class ServerCore(Thread):

    def __init__(self, ip: str, port: int):
        """
        Server Class Constructor.
        :param ip: For the IP Address to connect to.
        :param port: For the Port Number to connect to.
        """
        Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.active_connections = 0
        self.active_connections_list = []
        self.threads = []
        self.class_logger = Logger('Server Core')
        self.server_logic = ServerLogic()
        self.server_utils = ServerUtils()
        self.lock = Lock()
        self.server = None

    def create_socket(self) -> socket:
        """
        Creates a new TCP Server Socket.
        :return: The new created TCP Server Socket.
        """
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            self.class_logger.logger.debug(f"Socket {sock} has been created successfully.")
            return sock

        except socket_error as err:
            raise CreateSocketError(f"Unable to create server socket, Error: {err}")

    def bind_socket(self, sock: socket) -> None:
        """
        Binds the given socket needed on server ip and port.
        :param sock: For the socket to bind.
        :return: None
        """
        try:
            self.port = int(self.port)
            sock.bind((self.ip, self.port))
            self.class_logger.logger.debug(f"Bind successfully on {self.ip}:{self.port}.")

        except (Exception, socket_error) as err:
            sock.close()
            raise BindSocketError(f"Unable to bind, Error: {err}.")

    def start_listener(self, sock: socket) -> None:
        """
        Starts the given socket needed listen function.
        :param sock: For the socket to listen to.
        :return: None
        """
        try:
            sock.listen()
            self.class_logger.logger.debug("Listener has been started successfully.")

        except (Exception, socket_error) as err:
            sock.close()
            raise StartListenerError(f"Unable to start listener, Error: {err}.")

    def cleanup(self, connection: socket) -> None:
        """
        Disconnect from client.
        :param connection: For the clients socket to close.
        :return: None.
        """
        log_peer = self.server_logic.parse_socket_object(connection, parsed_format=ParsingConstants.LOG)
        console_peer = self.server_logic.parse_socket_object(connection, parsed_format=ParsingConstants.CONSOLE)
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} Disconnected from peer {console_peer}.")
        self.class_logger.logger.info(f"Closed {log_peer} successfully.")
        self.class_logger.logger.debug(f"Removed {log_peer} from list of active connections.")

        # Remove client from server list
        try:
            self.active_connections_list.remove(connection)
            self.active_connections -= 1

        finally:
            connection.close()

    def setup_server_core(self) -> None:
        """
        Setup the server needed ServerCore methods.
        :return: None
        """
        try:
            self.server = self.create_socket()
            self.bind_socket(self.server)
            self.start_listener(self.server)

        except (CreateSocketError, BindSocketError, StartListenerError) as err:
            raise SetupServerCoreError(err)

    def new_connection(self, connection: socket) -> None:
        """
        Method to manage a new connection.
        :param connection: For the connection socket to manage.
        :return: None
        """
        peer = self.server_logic.parse_socket_object(connection, parsed_format=ParsingConstants.LOG)
        # Add client to server list
        try:
            self.active_connections_list.append(connection)
            self.active_connections += 1
            self.class_logger.logger.debug(f"Added {peer} to list of active connections.")
            self.class_logger.logger.info(f"Server Active connections are: {self.active_connections}.")

        except AttributeError as err:
            self.class_logger.logger.error(f"Unable to add {peer} to active connection list, Error: {err}.")

    def handle_new_client(self, connection: socket) -> None:
        """
        Method to handle all new client protocol logic.
        :param connection: For the new client connection to be handled.
        :return: None.
        """
        # Acquire lock before accessing shared resources
        self.lock.acquire()

        # Update server list and logs with the new connection
        self.new_connection(connection)

        # Create new client RAM dictionary template and summery list
        clients_ram_template = ram_clients_template.copy()
        files_ram_template = ram_files_template.copy()
        client_summery = []

        # Update last seen RAM dict template
        clients_ram_template[ServerDBConstants.LAST_SEEN] = self.server_utils.last_seen()

        # Receiving registration request from client and handle response
        self.server_logic.process_register_request(connection, clients_ram_template,
                                                   files_ram_template, client_summery)

        # Receiving public key request from client and handle response
        self.server_logic.process_public_key_request(connection, clients_ram_template, client_summery)

        # Receiving encrypted file request from client and handle response
        self.server_logic.process_encrypted_file_request(connection, clients_ram_template,
                                                         files_ram_template, client_summery)

        # Receiving CRC validation request from client and handle response
        self.server_logic.process_crc_validation_request(connection, clients_ram_template,
                                                         files_ram_template, client_summery)

        # Write client logs and update last seen field in server database
        client_name = clients_ram_template[ServerDBConstants.CLIENT_NAME]
        try:
            self.server_logic.db.update_table(self.server_logic.clients_table_name, ServerDBConstants.LAST_SEEN,
                                              self.server_utils.last_seen(), ServerDBConstants.CLIENT_NAME, client_name)
        except UpdateTableError as err:
            self.class_logger.logger.error(err)

        # Create client log file in his unique directory according to the a given configuration
        self.server_logic.create_client_unique_log_file(username=client_name, handle_list=client_summery,
                                                        client_template=clients_ram_template,
                                                        files_template=files_ram_template)

        # Exports server database to a JSON file according to the a given configuration
        self.server_logic.export_server_db_to_json()

        # Clear data structures for the next client
        clients_ram_template.clear()
        files_ram_template.clear()
        client_summery.clear()
        self.cleanup(connection)

        # Release the lock after accessing shared resources
        self.lock.release()

    def run(self) -> None:
        """
        ServerCore main method to run all server logic.
        :return: None.
        """
        # Initializing Server
        try:
            self.setup_server_core()
            self.server_logic.setup_server_logic()

        except (SetupServerCoreError, SetupServerLogicError) as err:
            print(f"{ParsingConstants.SERVER_CONSOLE_FAIL} Error establish server connection, "
                  f"check ip and port values, Error: {err}")
            # Cleanup
            self.server.close()
            exit()

        print(server_art, end='\n\n')
        server_welcome_message(self.class_logger.log_file)
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} Starting Server...")
        print(f"{ParsingConstants.SERVER_CONSOLE_ACK} Server is listening on {self.ip}:{self.port}")

        # Waiting for clients requests
        while True:
            connection, address = self.server.accept()
            print(
                f"{ParsingConstants.SERVER_CONSOLE_ACK} Connected to peer "
                f"{self.server_logic.parse_socket_object(connection, parsed_format=ParsingConstants.CONSOLE)}")

            # Starting the threading process to accept connections from multiple clients
            try:
                client_thread = Thread(target=self.handle_new_client, args=(connection,))
                client_thread.start()
                self.threads.append(client_thread)

            except (KeyboardInterrupt, Exception) as err:

                # Stopping server and cleanup
                print(f"{ParsingConstants.SERVER_CONSOLE_FAIL} Stopping server due to: {err}")
                self.server.close()

                # Wait for all threads to finish
                for thread in self.threads:
                    thread.join()


"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class CreateSocketError(Exception):
    pass


class BindSocketError(Exception):
    pass


class StartListenerError(Exception):
    pass


class SetupServerCoreError(Exception):
    pass