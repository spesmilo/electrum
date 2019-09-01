# All SLP-related Exceptions used by the slp package

class Error(Exception):
    ''' Base class for all SLP-related errors '''

class OpreturnError(Error):
    pass

class ParsingError(Error):
    ''' Exceptions caused by malformed or unexpected data found in parsing. '''

class UnsupportedSlpTokenType(ParsingError):
    ''' Cannot parse OP_RETURN due to unrecognized version
        (may or may not be valid) '''

class InvalidOutputMessage(ParsingError):
    ''' This exception (and subclasses) marks a message as definitely invalid
        under SLP consensus rules. (either malformed SLP or just not SLP) '''

class SerializingError(Error):
    ''' Exceptions during creation of SLP message. '''

class OPReturnTooLarge(SerializingError):
    ''' The OPReturn field ended up being > 223 bytes '''

# Other exceptions
class NoMintingBatonFound(Error):
    pass
