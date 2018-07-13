from electrum_ltc.util import PrintError


class TrezorTransport(PrintError):

    @staticmethod
    def all_transports():
        """Reimplemented trezorlib.transport.all_transports so that we can
        enable/disable specific transports.
        """
        try:
            # only to detect trezorlib version
            from trezorlib.transport import all_transports
        except ImportError:
            # old trezorlib. compat for trezorlib < 0.9.2
            transports = []
            #try:
            #    from trezorlib.transport_bridge import BridgeTransport
            #    transports.append(BridgeTransport)
            #except BaseException:
            #    pass
            try:
                from trezorlib.transport_hid import HidTransport
                transports.append(HidTransport)
            except BaseException:
                pass
            try:
                from trezorlib.transport_udp import UdpTransport
                transports.append(UdpTransport)
            except BaseException:
                pass
            try:
                from trezorlib.transport_webusb import WebUsbTransport
                transports.append(WebUsbTransport)
            except BaseException:
                pass
        else:
            # new trezorlib.
            transports = []
            #try:
            #    from trezorlib.transport.bridge import BridgeTransport
            #    transports.append(BridgeTransport)
            #except BaseException:
            #    pass
            try:
                from trezorlib.transport.hid import HidTransport
                transports.append(HidTransport)
            except BaseException:
                pass
            try:
                from trezorlib.transport.udp import UdpTransport
                transports.append(UdpTransport)
            except BaseException:
                pass
            try:
                from trezorlib.transport.webusb import WebUsbTransport
                transports.append(WebUsbTransport)
            except BaseException:
                pass
            return transports
        return transports

    def enumerate_devices(self):
        """Just like trezorlib.transport.enumerate_devices,
        but with exception catching, so that transports can fail separately.
        """
        devices = []
        for transport in self.all_transports():
            try:
                new_devices = transport.enumerate()
            except BaseException as e:
                self.print_error('enumerate failed for {}. error {}'
                                 .format(transport.__name__, str(e)))
            else:
                devices.extend(new_devices)
        return devices

    def get_transport(self, path=None):
        """Reimplemented trezorlib.transport.get_transport,
        (1) for old trezorlib
        (2) to be able to disable specific transports
        (3) to call our own enumerate_devices that catches exceptions
        """
        if path is None:
            try:
                return self.enumerate_devices()[0]
            except IndexError:
                raise Exception("No TREZOR device found") from None

        def match_prefix(a, b):
            return a.startswith(b) or b.startswith(a)
        transports = [t for t in self.all_transports() if match_prefix(path, t.PATH_PREFIX)]
        if transports:
            return transports[0].find_by_path(path)
        raise Exception("Unknown path prefix '%s'" % path)
