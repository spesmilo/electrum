import unittest
from unittest import mock


class TestNetworkChannelCount(unittest.TestCase):

    def test_network_screen_shows_the_usable_channels(self):
        from electrum.gui.qml.qenetwork import QENetwork
        fake = mock.Mock(_gossipDbNodes=0, _gossipDbChannels=0, _gossipDbPolicies=0)
        QENetwork.on_event_channel_db(fake, 11500, 37000, 48000, 26500)
        self.assertEqual(26500, fake._gossipDbChannels)  # not the 37000 with the ones about to get pruned
        self.assertEqual(11500, fake._gossipDbNodes)
        fake.gossipUpdated.emit.assert_called_once_with()
