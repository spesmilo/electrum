import serial
import logging

from serial.tools import list_ports
from .jade_error import JadeError

logger = logging.getLogger(__name__)


#
# Low-level Serial backend interface to Jade
# Calls to send and receive bytes over the interface.
# Intended for use via JadeInterface wrapper.
#
# Either:
#  a) use via JadeInterface.create_serial() (see JadeInterface)
# (recommended)
# or:
#  b) use JadeSerialImpl() directly, and call connect() before
#     using, and disconnect() when finished,
# (caveat cranium)
#
class JadeSerialImpl:
    # Used when searching for devices that might be a Jade/compatible hw
    JADE_DEVICE_IDS = [
            (0x10c4, 0xea60), (0x1a86, 0x55d4), (0x0403, 0x6001),
            (0x1a86, 0x7523), (0x303a, 0x4001), (0x303a, 0x1001)]

    @classmethod
    def _get_first_compatible_device(cls):
        jades = []
        for devinfo in list_ports.comports():
            if (devinfo.vid, devinfo.pid) in cls.JADE_DEVICE_IDS:
                jades.append(devinfo.device)

        if len(jades) > 1:
            logger.warning(f'Multiple potential jade devices detected: {jades}')

        return jades[0] if jades else None

    def __init__(self, device, baud, timeout):
        self.device = device or self._get_first_compatible_device()
        self.baud = baud
        self.timeout = timeout
        self.ser = None

    def connect(self):
        assert self.ser is None

        logger.info('Connecting to {} at {}'.format(self.device, self.baud))
        self.ser = serial.Serial(self.device, self.baud,
                                 timeout=self.timeout,
                                 write_timeout=self.timeout)
        assert self.ser is not None

        if not self.ser.is_open:
            try:
                self.ser.open()
            except serial.serialutil.SerialException:
                raise JadeError(1, "Unable to open port", self.device)

        # Ensure RTS and DTR are not set (as this can cause the hw to reboot)
        self.ser.setRTS(False)
        self.ser.setDTR(False)

        logger.info('Connected')

    def disconnect(self):
        assert self.ser is not None

        # Ensure RTS and DTR are not set (as this can cause the hw to reboot)
        # and then close the connection
        self.ser.setRTS(False)
        self.ser.setDTR(False)
        self.ser.close()

        # Reset state
        self.ser = None

    def write(self, bytes_):
        assert self.ser is not None
        return self.ser.write(bytes_)

    def read(self, n):
        assert self.ser is not None
        return self.ser.read(n)
