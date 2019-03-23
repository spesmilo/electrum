from test import TestProtocolCase

class TestProtocol(TestProtocolCase):

    def is_protocol_done(self, pThread):
        if pThread.protocol:
            return pThread.protocol.done
        else:
            pThread.done.is_set()

    def test_correct_protocol(self):
        protocolThreads = self.make_clients_threads()
        for pThread in protocolThreads:
            pThread.start()
        done = False
        while not done:
            # read protocol messages
            for pThread in protocolThreads:
                try:
                    message = pThread.logger.get_nowait()
                    print(message)
                except:
                    pass
            done = all([self.is_protocol_done(pThread) for pThread in protocolThreads])
        for pThread in protocolThreads:
            pThread.join()
        for pThread in protocolThreads[1:]:
            self.assertEqual(protocolThreads[0].protocol.tx.raw, pThread.protocol.tx.raw)
