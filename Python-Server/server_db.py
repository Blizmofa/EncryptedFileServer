from sqlite3 import connect, Error as sqlite3_Error
from json import dump
from logger import Logger

"""
Custom Context Manager Class to manage DB resources with the 'with' key word.
"""


class CustomContextManager:

    def __init__(self, name: str):
        """Initializing Database."""
        self.name = name
        self.class_logger = Logger("DB Context Manager")

    def __enter__(self):
        """Opens the connection."""
        self.conn = connect(self.name)
        self.class_logger.logger.debug(f"Connected to '{self.name}' successfully.")
        return self.conn.cursor()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Closes the connection."""
        if self.conn:
            self.conn.commit()
            self.conn.close()
            self.class_logger.logger.debug(f"Saved data and closed the connection to '{self.name}' successfully.")


"""
ServerDB class for creating and customize the server needed SQLite tables.
DB is written with sql parameterized queries to prevent SQL Injection.
"""


class ServerDB:

    def __init__(self, name: str):
        """Class Constructor."""
        self.name = name
        self.class_logger = Logger('DB')

    def create_table(self, table_name: str, columns: str) -> None:
        """
        Creates a table according to a given table name and columns.
        :param table_name: For the table name.
        :param columns: For the table columns.
        :return: None
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({columns})")
                self.class_logger.logger.debug(f"Created Table '{table_name}' successfully.")

        except sqlite3_Error as err:
            raise CreateTableError(f"Unable to create table '{table_name}', Error: {err}.")

    def insert_value(self, table_name: str, table_column: str, value) -> None:
        """
        Inserting a new value to a given database table.
        :param table_name: For the table to insert values to.
        :param table_column: For the column to insert values to.
        :param value: For the value to insert.
        :return: None
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"INSERT INTO {table_name} ({table_column}) VALUES(?)", (value,))
                self.class_logger.logger.debug(f"Inserted '{value}' to '{table_name}' successfully.")

        except sqlite3_Error as err:
            raise InsertValueError(f"Unable to insert '{value}' to '{table_name}', Error: {err}")

    def insert_if_not_exists(self, table_name: str, table_column: str, value) -> bool:
        """
        Inserting a new value to a given database table only if it doesn't already exists.
        :param table_name: For the table to insert values to.
        :param table_column: For the column to insert values to.
        :param value: For the value to insert.
        :return: True if the value has been inserted successfully, False otherwise.
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"SELECT * FROM {table_name} WHERE {table_column}=?", (value,))
                result = cur.fetchone()
                if result is None:
                    # Value does not exist and has been inserted successfully
                    try:
                        self.insert_value(table_name, table_column, value)
                        return True
                    except InsertValueError as err:
                        self.class_logger.logger.error(err)
                        return False
                else:
                    self.class_logger.logger.debug(f"'{value}' Exists in '{table_name}'")
                    return False

        except sqlite3_Error as err:
            self.class_logger.logger.error(f"Error inserting '{value}' from '{table_name}' {err}.")

    def update_table(self, table_name: str, column_to_update: str, value,
                     current_table_column: str, existing_value: str) -> None:
        """
        Updates an existing table with a given value according to a given existing value.
        :param table_name: For the existing table to update.
        :param column_to_update: For the table column to update.
        :param value: For the new value to add.
        :param current_table_column: For the existing table column.
        :param existing_value: For the existing table value.
        :return: None
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"UPDATE {table_name} SET {column_to_update} = ? WHERE {current_table_column} = ?",
                            (value, existing_value))
                self.class_logger.logger.debug(
                    f"Inserted '{value}' to '{column_to_update}' in '{table_name}' successfully.")

        except sqlite3_Error as err:
            raise UpdateTableError(f"Unable to update '{value}' in '{table_name}', Error: {err}.")

    def delete_value(self, table_name: str, table_column: str, value_to_delete: str) -> None:
        """
        Deletes a given value from a given table.
        :param table_name: For the table to delete the value from.
        :param table_column: For the table column to delete from.
        :param value_to_delete: For the value to delete.
        :return: None
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"DELETE FROM {table_name} WHERE {table_column} = ?", (value_to_delete,))
                self.class_logger.logger.debug(f"Deleted '{value_to_delete}' from '{table_name}' successfully.")

        except sqlite3_Error as err:
            raise DeleteValueError(f"Unable to delete '{value_to_delete}' from '{table_name}', Error: {err}.")

    def select_value(self, table_name: str, table_column: str) -> str:
        """
        Selects a specific table value and return it.
        :param table_name: For the table to select from.
        :param table_column: For the table column to select from.
        :return: The table value after unpacking.
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"SELECT {table_column} FROM {table_name}")
                value = cur.fetchone()[0]
                self.class_logger.logger.debug(f"Retrieved '{value}' from column "
                                               f"'{table_column}' in table '{table_name}' successfully.")
                return value

        except (TypeError, sqlite3_Error) as err:
            raise NotFoundError(f"Unable to retrieve value from '{table_name}', Error: {err}.")

    def fetch_by_column_value(self, table_name: str, table_column: str,
                              current_table_column: str, existing_value: str) -> str:
        """
        Retrieve a specific value from a given table according to a given existing value.
        :param table_name: For the table to select from.
        :param table_column: For the table column to select from.
        :param current_table_column: For the existing table column.
        :param existing_value: For the existing table value.
        :return: The table value after unpacking.
        """
        try:
            with CustomContextManager(self.name) as cur:
                cur.execute(f"SELECT {table_column} FROM {table_name} WHERE {current_table_column} = ?",
                            (existing_value,))
                value = cur.fetchone()[0]
                self.class_logger.logger.debug(f"Retrieved '{value}' from column "
                                               f"'{table_column}' in table '{table_name}' successfully.")
                return value

        except (TypeError, sqlite3_Error) as err:
            raise NotFoundError(f"Unable to retrieve value from '{table_name}', Error: {err}.")

    def get_all_database_tables(self) -> list:
        """
        Returns all database tables.
        :return: A list of all database tables.
        """
        tables = []
        try:
            with CustomContextManager(self.name) as cur:

                # Fetch tables
                cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
                value = cur.fetchall()
                self.class_logger.logger.debug(f"Retrieved tables from '{self.name}' successfully.")

                # Unpack value and return
                for table in value:
                    tables.append(table[0])
                return tables

        except (TypeError, sqlite3_Error) as err:
            raise NotFoundError(f"Unable to retrieve tables from '{self.name}', Error: {err}.")

    def export_table_to_json(self, tables: list, file_path: str) -> None:
        """
        Exports the given table data to a JSON file.
        :param tables: A list of DB tables to be exported.
        :param file_path: For the JSON file path to export to.
        :return: None.
        """
        data = {}
        try:
            with CustomContextManager(self.name) as cur:
                for table in tables:

                    # Retrieve data from the table
                    cur.execute(f"SELECT * FROM {table}")
                    rows = cur.fetchall()
                    columns = [column[0] for column in cur.description]

                    # Convert the data to a list of dictionaries
                    table_dicts = [dict(zip(columns, row)) for row in rows]
                    data[table] = table_dicts

                # Dump all data to JSON file
                with open(file_path, 'w') as out_file:
                    dump(data, out_file, indent=2)
                    out_file.write("\n")

        except (TypeError, sqlite3_Error) as err:
            raise ExportDBError(f"Unable to retrieve data from '{self.name}', Error: {err}.")


"""
Custom Exception Classes for raising high-level Exceptions,
and make error handling more informative.
"""


class CreateTableError(Exception):
    pass


class InsertValueError(Exception):
    pass


class UpdateTableError(Exception):
    pass


class DeleteValueError(Exception):
    pass


class NotFoundError(Exception):
    pass


class ExportDBError(Exception):
    pass

