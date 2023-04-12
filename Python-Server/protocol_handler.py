from abc import ABC, abstractmethod
from struct import pack, unpack, error as struct_error
from logger import Logger

"""
ProtocolHandlerInterfaces Class is an auxiliary class to improve server performances.
"""


class ProtocolHandlerInterfaces(ABC):

    @abstractmethod
    def pack_request(self, fmt: str, *args) -> bytes:
        """Main pack packet method to be override."""
        pass

    @abstractmethod
    def unpack_request(self, request_code: int, received_packet: bytes) -> tuple:
        """Main unpack packet method to be override."""
        pass


"""
ServerProtocolHandler Class for packing and unpacking bytes packed packets.
"""


class ProtocolHandler(ProtocolHandlerInterfaces):

    def __init__(self):
        """Class Constructor."""
        self.RESPONSE_CODE = 0
        self.PAYLOAD_SIZE = 0
        self.class_logger = Logger('Protocol Handler')

    def pack_request(self, fmt: str, *args) -> bytes:
        """
        Generic method to packing server responses.
        :param fmt: For the format code to pack with.
        :param args: For the different packing arguments needed to implement the server protocol.
        :return: The packed packet.
        """
        try:
            packed = pack(fmt, *args)
            self.class_logger.logger.debug(f"Packed packet '{self.RESPONSE_CODE}' successfully.")
            return packed

        except (struct_error, TypeError) as err:
            raise PackPacketError(f"Unable to pack packet '{self.RESPONSE_CODE}', Error: {err}")

    def unpack_request(self, request_code: int, received_packet: bytes) -> tuple:
        """
        Unpacks received packets according to a given request code.
        :param request_code: For the client protocol request code.
        :param received_packet: For the packet to unpack.
        :return: The unpacked packet.
        """
        try:
            payload_sizes = self.get_client_payload_sizes(ProtocolHandlersUtils.client_request_template, request_code)
            unpacked = unpack(f'{ProtocolHandlersUtils.UNPACK_DEFAULT_FORMAT}{payload_sizes}', received_packet)
            self.class_logger.logger.debug(f"Unpacked packet '{request_code}' successfully.")
            return unpacked

        except (struct_error, TypeError) as err:
            raise UnpackPacketError(f"Unable to unpack '{request_code}' packet, Error: {err}")

    def pack_registration_approved_response(self, response_code: int, client_id: bytes) -> bytes:
        """
        Packs registration approved response.
        :param response_code: For the server protocol response code.
        :param client_id: For the payload to pack.
        :return: The packed registration approval packet.
        """
        try:
            self.get_server_response_code(ProtocolHandlersUtils.server_response_template, response_code)
            fmt = f"{ProtocolHandlersUtils.PACK_DEFAULT_FORMAT}{self.PAYLOAD_SIZE}s"
            packed = self.pack_request(fmt, ProtocolHandlersUtils.SERVER_VERSION,
                                       self.RESPONSE_CODE, self.PAYLOAD_SIZE, client_id)
            return packed

        except (PackPacketError, ValueError) as err:
            raise PackRegisterApprovedPacketError(err)

    def pack_no_payload_response(self, response_code: int) -> bytes:
        """
        Packs no payload response.
        :param response_code: For the server protocol response code.
        :return: The packed no payload packet.
        """
        self.get_server_response_code(ProtocolHandlersUtils.server_response_template, response_code)
        fmt = f"{ProtocolHandlersUtils.PACK_DEFAULT_FORMAT}"
        try:
            packed = self.pack_request(fmt, ProtocolHandlersUtils.SERVER_VERSION, self.RESPONSE_CODE, self.PAYLOAD_SIZE)
            return packed

        except (PackPacketError, ValueError) as err:
            raise PackNoPayloadPacketError(err)

    def pack_encrypted_key_response(self, response_code: int, client_id: bytes, encrypted_aes_key: bytes) -> bytes:
        """
        Packs encrypted key response.
        :param response_code: For the server protocol response code.
        :param client_id: For the client id payload to pack.
        :param encrypted_aes_key: For the encrypted AES key payload to pack.
        :return: The packed encrypted key packet.
        """
        try:
            self.get_server_response_code(ProtocolHandlersUtils.server_response_template, response_code)
            fmt = f"{ProtocolHandlersUtils.PACK_DEFAULT_FORMAT}{ProtocolHandlersUtils.CLIENT_UUID_SIZE}s" \
                  f"{ProtocolHandlersUtils.SERVER_ENCRYPTED_AES_KEY_SIZE}s"
            packed = self.pack_request(fmt, ProtocolHandlersUtils.SERVER_VERSION, self.RESPONSE_CODE, self.PAYLOAD_SIZE,
                                       client_id, encrypted_aes_key)
            return packed

        except (PackPacketError, ValueError) as err:
            raise PackEncryptedKeyPacketError(err)

    def pack_file_crc_response(self, response_code: int, payload_size: int, client_id: bytes,
                               content_size: int, file_name: bytes, file_crc: bytes) -> bytes:
        """
        Packs CRC response.
        :param response_code: For the server protocol response code.
        :param payload_size: For the payload size.
        :param client_id: For the client ID.
        :param content_size: For the content size.
        :param file_name: For the file name.
        :param file_crc: For the file CRC.
        :return: The packed CRC packet.
        """
        # Validate file name is in bytes format
        if type(file_name) != bytes:
            file_name = file_name.encode()
        try:
            self.get_server_response_code(ProtocolHandlersUtils.server_response_template, response_code)
            fmt = f"{ProtocolHandlersUtils.PACK_DEFAULT_FORMAT}{ProtocolHandlersUtils.CLIENT_UUID_SIZE}sI" \
                  f"{ProtocolHandlersUtils.CLIENT_FILE_NAME_SIZE}s{len(file_crc)}s"
            packed = self.pack_request(fmt, ProtocolHandlersUtils.SERVER_VERSION, response_code,
                                       payload_size, client_id, content_size, file_name, file_crc)
            return packed

        except (PackPacketError, ValueError) as err:
            raise PackCRCPacketError(err)

    def get_client_payload_sizes(self, template: dict, request_code: int) -> str:
        """
        Auxiliary method to return the needed unpack values according to a given client request code.
        :param template: For the client formats template.
        :param request_code: For the client request code.
        :return: The unpack format value.
        """
        try:
            for key, value in template.items():
                if request_code == key:
                    self.class_logger.logger.debug(f"Parsed request code: {request_code}")
                    return value

        except ValueError as err:
            self.class_logger.logger.error(f"Unable to parse client request code: {request_code}, Error: {err}")

    def get_server_response_code(self, template: dict, response_code: int) -> None:
        """
        Auxiliary method to return the needed pack values according to a given server response code.
        :param template: For the server formats template.
        :param response_code: For the server response code.
        :return: The pack format value.
        """
        try:
            for key, value in template.items():
                if response_code == key:
                    for k, v in value.items():
                        if k == ProtocolHandlersUtils.SERVER_RESPONSE_CODE_STR:
                            self.RESPONSE_CODE = v
                        if k == ProtocolHandlersUtils.SERVER_PAYLOAD_SIZE_STR:
                            self.PAYLOAD_SIZE = v

        except ValueError as err:
            self.class_logger.logger.error(f"Unable to parse server response code: {response_code}, Error: {err}")


"""
Auxiliary Class for protocol constants and templates.
"""


class ProtocolHandlersUtils:
    SERVER_VERSION = 3

    # Default sizes
    DEFAULT_VALUE = 0
    SERVER_RECEIVE_BUFFER_SIZE = 1024
    CLIENT_UUID_SIZE = 16
    CLIENT_PUBKEY_SIZE = 160
    CLIENT_FILE_NAME_SIZE = 255
    SERVER_AES_KEY_SIZE = 16
    SERVER_ENCRYPTED_AES_KEY_SIZE = 128
    FILE_CONTENT_SIZE = 4
    CRC_SIZE = 4
    CRC_RE_RECEIVE_MAX = 3
    CRC_CHUNK_SIZE = 3
    ENCRYPTED_FILE_NAME_SUFFIX = 4

    # Packet indexes
    CLIENT_ID_INDEX = 0
    CLIENT_VERSION_INDEX = 1
    CLIENT_REQUEST_CODE_INDEX = 2
    CLIENT_PAYLOAD_SIZE_INDEX = 3
    CLIENT_USERNAME_INDEX = 4
    CLIENT_PUBKEY_INDEX = 5
    CLIENT_FILE_REQUEST_CONTENT_SIZE_INDEX = 5
    CLIENT_FILE_NAME_INDEX = 6

    # Client request codes
    CLIENT_REG_REQUEST = 1100
    CLIENT_PUBKEY_REQUEST = 1101
    CLIENT_ENCRYPTED_FILE_REQUEST = 1103
    CLIENT_VALID_CRC_REQUEST = 1104
    CLIENT_INVALID_CRC_REQUEST = 1105
    CLIENT_INVALID_CRC_FOURTH_TIME_REQUEST = 1106
    CLIENT_UNPACK_CRC_REQUEST_CODE = 1111

    # Packet unpack/pack formats
    UNPACK_DEFAULT_FORMAT = "<16sBHI"
    PACK_DEFAULT_FORMAT = "BHI"

    # Server response codes and strings
    SERVER_REG_SUCCESS_RESPONSE = 2100
    SERVER_REG_FAILED_RESPONSE = 2101
    SERVER_ENCRYPTED_KEY_RESPONSE = 2102
    SERVER_FILE_CRC_RESPONSE = 2103
    SERVER_ACK_RESPONSE = 2104
    SERVER_RESPONSE_CODE_STR = "response_code"
    SERVER_PAYLOAD_SIZE_STR = "payload_size"

    # Auxiliary template for client payload sizes according to the different request codes
    client_request_template = {
        CLIENT_REG_REQUEST: '255s',
        CLIENT_PUBKEY_REQUEST: '255s160s',
        CLIENT_ENCRYPTED_FILE_REQUEST: '16sI255s',
        CLIENT_UNPACK_CRC_REQUEST_CODE: '16s255s'
    }

    # Auxiliary template for server response codes and payload sizes
    server_response_template = {

        # For response 2100
        SERVER_REG_SUCCESS_RESPONSE: {
            SERVER_RESPONSE_CODE_STR: SERVER_REG_SUCCESS_RESPONSE,
            SERVER_PAYLOAD_SIZE_STR: CLIENT_UUID_SIZE
        },

        # For response 2101
        SERVER_REG_FAILED_RESPONSE: {
            SERVER_RESPONSE_CODE_STR: SERVER_REG_FAILED_RESPONSE,
            SERVER_PAYLOAD_SIZE_STR: DEFAULT_VALUE
        },

        # For response 2102
        SERVER_ENCRYPTED_KEY_RESPONSE: {
            SERVER_RESPONSE_CODE_STR: SERVER_ENCRYPTED_KEY_RESPONSE,
            SERVER_PAYLOAD_SIZE_STR: CLIENT_UUID_SIZE + SERVER_ENCRYPTED_AES_KEY_SIZE
        },

        # For response 2103
        SERVER_FILE_CRC_RESPONSE: {
            SERVER_RESPONSE_CODE_STR: SERVER_FILE_CRC_RESPONSE,
            SERVER_PAYLOAD_SIZE_STR: CLIENT_UUID_SIZE + FILE_CONTENT_SIZE + CLIENT_FILE_NAME_SIZE + CRC_SIZE
        },

        # For response 2104
        SERVER_ACK_RESPONSE: {
            SERVER_RESPONSE_CODE_STR: SERVER_ACK_RESPONSE,
            SERVER_PAYLOAD_SIZE_STR: DEFAULT_VALUE
        }
    }


"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class PackPacketError(Exception):
    pass


class UnpackPacketError(Exception):
    pass


class PackRegisterApprovedPacketError(Exception):
    pass


class PackNoPayloadPacketError(Exception):
    pass


class PackEncryptedKeyPacketError(Exception):
    pass


class PackCRCPacketError(Exception):
    pass
