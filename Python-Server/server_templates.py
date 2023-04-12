"""
Auxiliary classes for Server Constants.
"""


class ParsingConstants:
    LOG = "LOG"
    CONSOLE = "CONSOLE"
    SERVER_CONSOLE_ACK = "[+]"
    SERVER_CONSOLE_FAIL = "[-]"


class ServerDBConstants:
    ID = "ID"
    CLIENT_NAME = "Client_Name"
    PUBLIC_KEY = "Public_Key"
    PUBLIC_KEY_LENGTH = "Public_Key_Length"
    LAST_SEEN = "Last_Seen"
    AES_KEY = "AES_Key"
    AES_KEY_LENGTH = "AES_Key_Length"
    ENCRYPTED_AES_KEY = "Encrypted_AES_Key"
    ENCRYPTED_AES_KEY_LENGTH = "Encrypted_AES_Key_Length"
    FILE_NAME = "File_Name"
    FILE_NAME_SIZE = "File_Name_Size"
    COPY_FILE_NAME = "Copy_File_Name"
    COPY_FILE_NAME_SIZE = "Copy_File_Name_Size"
    FILE_PATH = "File_Path"
    COPY_FILE_PATH = "Copy_File_Path"
    FILE_CONTENT_SIZE = "File_Content_Size"
    COPY_FILE_CONTENT_SIZE = "Copy_File_Content_Size"
    FILE_CRC = "FILE_CRC"
    VERIFIED = "Verified"
    TEXT_TYPE = "TEXT"
    PRIMARY_KEY = "PRIMARY KEY"
    DATE_TYPE = "DATE"
    BOOLEAN_TYPE = "BOOLEAN"


"""
Auxiliary data structures templates.
"""

# Dictionary format for saving clients data in RAM memory
ram_clients_template = {
    ServerDBConstants.ID: '{}',
    ServerDBConstants.CLIENT_NAME: '{}',
    ServerDBConstants.PUBLIC_KEY: '{}',
    ServerDBConstants.PUBLIC_KEY_LENGTH: '{}',
    ServerDBConstants.LAST_SEEN: '{}',
    ServerDBConstants.AES_KEY: '{}',
    ServerDBConstants.AES_KEY_LENGTH: '{}',
    ServerDBConstants.ENCRYPTED_AES_KEY: '{}',
    ServerDBConstants.ENCRYPTED_AES_KEY_LENGTH: '{}'
}

# Dictionary format for saving files data in RAM memory
ram_files_template = {
    ServerDBConstants.ID: '{}',
    ServerDBConstants.FILE_NAME: '{}',
    ServerDBConstants.FILE_NAME_SIZE: '{}',
    ServerDBConstants.COPY_FILE_NAME: '{}',
    ServerDBConstants.COPY_FILE_NAME_SIZE: '{}',
    ServerDBConstants.FILE_PATH: '{}',
    ServerDBConstants.COPY_FILE_PATH: '{}',
    ServerDBConstants.FILE_CONTENT_SIZE: '{}',
    ServerDBConstants.COPY_FILE_CONTENT_SIZE: '{}',
    ServerDBConstants.FILE_CRC: '{}',
    ServerDBConstants.VERIFIED: '{}'
}