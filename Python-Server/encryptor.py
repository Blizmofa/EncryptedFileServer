from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from logger import Logger
from Crypto.Util.Padding import unpad
from protocol_handler import ProtocolHandlersUtils


"""
Encryptor class for decryption and encryption methods with RSA and AES cryptographic keys.
"""


class Encryptor:

    def __init__(self):
        """Class Constructor."""
        self.class_logger = Logger('Encryptor')

    def create_aes_session_key(self) -> bytes:
        """
        Creates a fixed length AES session key.
        :return: The server session key.
        """
        try:
            private_key = get_random_bytes(ProtocolHandlersUtils.SERVER_AES_KEY_SIZE)
            self.class_logger.logger.debug(f"Created new AES private key: {private_key} "
                                           f"length: {len(private_key)} successfully.")
            return private_key

        except Exception as err:
            raise CreateAESSessionKeyError(f"Unable to create server AES session key, Error: {err}")

    def encrypt(self, aes_key: bytes, rsa_public_key: bytes) -> bytes:
        """
        Encrypts the server AES session key with the client received RSA public key.
        :param aes_key: For the server session key.
        :param rsa_public_key: For the client public key.
        :return: The encrypted server key.
        """
        try:
            key = RSA.importKey(rsa_public_key)
            cipher = PKCS1_OAEP.new(key)
            self.class_logger.logger.debug(f"{aes_key} has been encrypted with "
                                           f"{rsa_public_key} successfully.")
            return cipher.encrypt(aes_key)

        except Exception as err:
            raise EncryptServerAESKeyError(f"Unable to encrypt server session AES key, Error: {err}")

    def decrypt(self, aes_key: bytes, encrypted_text: bytes) -> bytes:
        """
        Decrypts a given text.
        :param aes_key: For the server AES session key to decrypt with.
        :param encrypted_text: For the text to decrypt.
        :return: The decrypted text.
        """
        try:
            iv = bytes([0] * AES.block_size)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            result = unpad(cipher.decrypt(encrypted_text), AES.block_size)
            self.class_logger.logger.debug(f"text has been decrypted successfully.")
            return result

        except Exception as err:
            raise AESDecryptionError(f"Unable to decrypt text, Error: {err}")

    def decrypt_file(self, file_path: str, key: bytes) -> bytes:
        """
        Decrypts file content.
        :param file_path: For the file to decrypt.
        :param key: For the key to decrypt with.
        :return: The decrypted bytes content of the file.
        """
        try:

            with open(file_path, 'rb') as encrypted_file:
                ciphered_text = encrypted_file.read()

            decrypted = self.decrypt(key, ciphered_text)
            self.class_logger.logger.debug(f"File '{file_path}' has been decrypted successfully.")
            return decrypted

        except (AESDecryptionError, FileNotFoundError) as err:
            raise DecryptFileContentError(err)

    def create_client_decrypted_file(self, file_path: str, decrypted_content: bytes) -> None:
        """
        Creates file from a given bytes stream.
        :param file_path: For the path to create the file in.
        :param decrypted_content: For the bytes stream to write into the file.
        :return: None.
        """
        try:
            with open(file_path, 'wb') as df:
                df.write(decrypted_content)
            self.class_logger.logger.debug(f"Created decrypted file '{file_path}' successfully.")

        except DecryptFileContentError as err:
            raise CreateClientDecryptedFileError(f"Unable to create decrypted file '{file_path}', Error: {err}")


"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class CreateAESSessionKeyError(Exception):
    pass


class EncryptServerAESKeyError(Exception):
    pass


class AESDecryptionError(Exception):
    pass


class DecryptFileContentError(Exception):
    pass


class CreateClientDecryptedFileError(Exception):
    pass
