from pyparsing import *

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# UTILITY
#
# Defining helper functionality to optimize code quality.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

class MalleableError(Exception):
    """Custom exception class used to identify local exceptions."""

    @classmethod
    def throw(cls, clss, func, message):
        """Throw a MalleableError.

        Args:
            clss (class): The class containing the exception.
            func (str): The function in which the exception occurred.
            message (str): A description of the exception.

        Raises:
            MalleableError: When called.
        """
        raise(cls("%s::%s - %s" % (clss.__name__, func, message)))

class MalleableUtil(object):
    """Custom utility class used to provide helper functionality."""

    @staticmethod
    def to_hex(byte):
        """Convert a byte into a hex character.

        Args:
            byte (char)

        Returns:
            str: Byte as a hex character.
        """
        return hex(ord(byte)) if byte else None

    @staticmethod
    def from_hex(hex):
        """Convert a hex character into a byte.

        Args:
            hex (str): A single hex character.

        Returns:
            char: byte.
        """
        return hex.split("0x")[-1].zfill(2).decode("hex") if hex else None

class MalleableObject(object):
    """Custom object class used to implement consistent functionality."""
    
    SEMICOLON = Suppress(";")
    FIELD = Word(alphanums + "_-")
    VALUE = (QuotedString("\"", escChar="\\") | QuotedString("'", escChar="\\"))
    COMMENT = Suppress("#") + Suppress(restOfLine)

    def __init__(self):
        """Constructor for a Malleable object."""
        self._defaults()

    def _defaults(self):
        """Default initialization for a Malleable object."""
        pass

    def _clone(self):
        """Deep copy of a Malleable object.

        Returns:
            MalleableObject
        """
        return self.__class__()

    def _serialize(self):
        """Serialize a Malleable object (json).

        Returns:
            dict (str, obj): Serialized data (json)
        """
        return {}

    @classmethod
    def _deserialize(cls, data):
        """Deserialize data (json) into a Malleable object.

        Args:
            data (dict (str, obj)): Serialized data (json)

        Returns:
            Malleable object
        """
        return cls()

    @classmethod
    def _pattern(cls):
        """Define the pattern to recognize this object while parsing a file.

        Returns:
            pyparsing object
        """
        return None

    def _parse(self, data):
        """Store the information from a parsed pyparsing result.

        Args:
            data: pyparsing data
        """
        pass
