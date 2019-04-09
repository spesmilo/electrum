from electrum.logging import get_logger


_logger = get_logger(__name__)


class HideezTransport:

    @staticmethod
    def all_transports():
        """Reimplemented hideezlib.transport.all_transports so that we can
        enable/disable specific transports.
        """
        from hideezlib.transport import all_transports
        transports = []
        try:
            from hideezlib.transport.bridge import BridgeTransport
            transports.append(BridgeTransport)
        except BaseException:
            pass
        return transports

    def enumerate_devices(self):
        """Just like hideezlib.transport.enumerate_devices,
        but with exception catching, so that transports can fail separately.
        """
        devices = []
        for transport in self.all_transports():
            try:
                new_devices = transport.enumerate()
            except BaseException as e:
                _logger.info(f'enumerate failed for {transport.__name__}. error {e}')
            else:
                devices.extend(new_devices)
        return devices

    def get_transport(self, path=None):
        """Reimplemented hideezlib.transport.get_transport,
        (1) to be able to disable specific transports
        (2) to call our own enumerate_devices that catches exceptions
        """
        if path is None:
            try:
                return self.enumerate_devices()[0]
            except IndexError:
                raise Exception("No Hideez device found") from None

        def match_prefix(a, b):
            return a.startswith(b) or b.startswith(a)
        transports = [t for t in self.all_transports()
                      if match_prefix(path, t.PATH_PREFIX)]
        if transports:
            return transports[0].find_by_path(path)
        raise Exception("Unknown path prefix '%s'" % path)
