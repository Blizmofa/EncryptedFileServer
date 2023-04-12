from logging import getLogger, basicConfig, INFO, DEBUG, Filter
from os import path
from config_parser import get_configuration, ConfigConstants, GetConfigurationError

"""
Custom logger class based on python logging library.
"""


class Logger:

    def __init__(self, logger_name: str):
        """
        Class Constructor.
        :param logger_name: For the logger name to be shown in the log file.
        """
        # Create logger
        self.logger = getLogger(logger_name)
        self.log_file = self.set_logger_configuration(ConfigConstants.LOG_FILE_NAME)
        self.log_file_mode = self.set_log_file_mode(self.log_file)
        # Set level and format
        self.log_level = self.set_log_level()
        self.log_format = self.set_logger_configuration(ConfigConstants.LOG_FILE_FORMAT)
        self.date_format = self.set_logger_configuration(ConfigConstants.DATE_FORMAT)
        self.logger.addFilter(CustomFilter())
        basicConfig(filename=self.log_file, filemode=self.log_file_mode, level=self.log_level,
                    format=self.log_format, datefmt=self.date_format)

    @staticmethod
    def set_logger_configuration(value: str) -> str:
        """
        Return the Logger needed configuration from config file.
        Mainly for error handling.
        :return: The needed value to config.
        """
        try:
            return str(get_configuration(value))

        except GetConfigurationError as err:
            raise SetLoggerAttributesError(err)

    @staticmethod
    def set_log_file_mode(log_file: str) -> str:
        """
        Sets the log file mode.
        :param log_file: For the log file to set.
        :return: The log file mode.
        """
        if path.exists(log_file):
            return 'a'
        else:
            return 'w'

    @staticmethod
    def set_log_level() -> int:
        """
        Sets the log level according to the config file.
        :return: The log level.
        """
        try:
            log_level = str(get_configuration(ConfigConstants.DEBUG_MODE))
            if log_level == ConfigConstants.FALSE.lower():
                return INFO
            elif log_level == ConfigConstants.TRUE.lower():
                return DEBUG

        except GetConfigurationError as err:
            raise SetLoggerAttributesError(err)


"""
Auxiliary class to customize the log format.
Adds a custom attribute log entry to associate log message to specific client.
"""


class CustomFilter(Filter):

    # Server will format this name according to the new connected client
    filter_name = None

    def filter(self, record) -> bool:
        record.custom_attribute = self.filter_name
        return True


"""
Custom Exception Class for raising high-level Exceptions,
and make error handling more informative.
"""


class SetLoggerAttributesError(Exception):
    pass