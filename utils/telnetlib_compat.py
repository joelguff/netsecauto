"""
Compatibility layer for telnetlib using telnetlib3
"""
import telnetlib3
import sys
from telnetlib3 import TelnetReader, TelnetWriter

# Telnet protocol constants
IAC = bytes([255])  # Interpret As Command
DONT = bytes([254])  # Don't
DO = bytes([253])   # Do
WONT = bytes([252]) # Won't
WILL = bytes([251]) # Will
SB = bytes([250])   # Subnegotiation Begin
SE = bytes([240])   # Subnegotiation End
TTYPE = bytes([24]) # Terminal Type
ECHO = bytes([1])   # Echo
SGA = bytes([3])    # Suppress Go Ahead
NAWS = bytes([31])  # Negotiate About Window Size

class Telnet:
    def __init__(self, host=None, port=0, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.reader = None
        self.writer = None

    async def open(self, host, port=0, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.reader, self.writer = await telnetlib3.open_connection(
            host, port, timeout=timeout
        )

    def read_until(self, expected, timeout=None):
        if not self.reader:
            raise ConnectionError("Not connected")
        return self.reader.read_until(expected)

    def write(self, buffer):
        if not self.writer:
            raise ConnectionError("Not connected")
        self.writer.write(buffer)

    def close(self):
        if self.writer:
            self.writer.close()
            self.reader = None
            self.writer = None

# Create a module-like object
class TelnetlibModule:
    def __init__(self):
        self.Telnet = Telnet
        # Add the constants
        self.IAC = IAC
        self.DONT = DONT
        self.DO = DO
        self.WONT = WONT
        self.WILL = WILL
        self.SB = SB
        self.SE = SE
        self.TTYPE = TTYPE
        self.ECHO = ECHO
        self.SGA = SGA
        self.NAWS = NAWS

# Add the module to sys.modules
sys.modules['telnetlib'] = TelnetlibModule() 