from test import TestProtocolCase
# from electroncash_plugins.shuffle_deprecated.messages import Messages()

class TestProtocol(TestProtocolCase):

    def test_001_server_lost(self):
        protocolThread = self.make_clients_threads(number_of_clients = 1, with_print = True)[0]
        protocolThread.port = self.PORT + 1
        protocolThread.start()
        done = False
        message =''
        while not done:
            try:
                message = protocolThread.logger.get_nowait()
                done = message.startswith("Error")
            except:
                pass
        protocolThread.join()
        self.assertEqual(message, "Error: cannot connect to server")

    def test_002_no_registration_on_the_pool(self):
        protocolThread = self.make_clients_threads(number_of_clients = 1, with_print = True)[0]
        protocolThread.amount = "bad amount"
        protocolThread.start()
        done = False
        message =''
        while not done:
            try:
                message = protocolThread.logger.get_nowait()
                done = message.startswith("Error")
            except:
                pass
        protocolThread.join()
        self.assertEqual(message, "Error: cannot register on the pool")

    # def test_003_bad_waiting_for_announcement(self, with_print = True):
    #     protocolThread = self.make_clients_threads(number_of_clients = 1, with_print = True)[0]
    #     protocolThread.outcome.switch_timeout = 1
    #     protocolThread.start()
    #     done = False
    #     message =''
    #     while not done:
    #         try:
    #             message = protocolThread.logger.get_nowait()
    #             if message.endswith(" get session number.\n"):
    #                 protocolThread.done.set()
    #             done = message.startswith("Error")
    #         except:
    #             pass
    #     protocolThread.join()
    #     self.assertEqual(message, "Error: cannot complete the pool")

    def test_005_bad_gathering_and_sharing_the_keys(self, with_print = True):
        protocolThreads = self.make_clients_threads()
        done = False
        for pThread in protocolThreads:
            pThread.outcome.switch_timeout = 1
            pThread.start()
        message = ''
        while not done:
            for pThread in protocolThreads:
                try:
                    message = pThread.logger.get_nowait()
                    if "is about to share verification key with" in message:
                        pThread.join()
                        # server.kill()
                        break
                except:
                    pass
                if message.startswith('Error'):
                    done = True
                    break
        for pThread in protocolThreads:
            pThread.join()
        self.assertIn(message, ["Error: cannot gather the keys",
                                "Error: cannot share the keys",
                                "Error: cannot complete the pool",
                                "Error: cannot register on the pool"])
