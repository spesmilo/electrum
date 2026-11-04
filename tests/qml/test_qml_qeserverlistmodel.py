from unittest.mock import patch

from PyQt6.QtCore import QModelIndex

from electrum.gui.qml.qeserverlistmodel import QEServerListModel, QEServerListSortModel

from .qt_util import QETestCase, QEventReceiver, qt_test


class FakeServerAddr:
    def __init__(self, host, port=50002, protocol='s'):
        self.host = host
        self.port = port
        self.protocol = protocol

    def __str__(self):
        return f'{self.host}:{self.port}:{self.protocol}'

    def to_friendly_name(self):
        return f'{self.host}:{self.port}'


class FakeInterface:
    def __init__(self, host, tip=100):
        self.server = FakeServerAddr(host)
        self.tip = tip
        self.blockchain = None


class FakeBlockchain:
    def __init__(self, name, height=100):
        self._name = name
        self._height = height

    def get_name(self):
        return self._name

    def height(self):
        return self._height

    def get_max_forkpoint(self):
        return 0


class FakeNetwork:
    """Mirrors the surface QEServerListModel reads."""
    def __init__(self):
        self.interface = None
        self.chains = {}  # chain_id -> list of FakeInterface
        self.disconnected = []  # list of FakeServerAddr
        self.bookmarks = set()  # set of str(FakeServerAddr)

    def get_blockchains(self):
        return self.chains

    def get_disconnected_server_addrs(self):
        return self.disconnected

    def is_server_bookmarked(self, server):
        return str(server) in self.bookmarks

    def add_chain(self, chain_id, name, interfaces):
        blockchain = FakeBlockchain(name)
        for i in interfaces:
            i.blockchain = blockchain
        self.chains[chain_id] = interfaces


def role(model, row, name):
    source = model.sourceModel() if isinstance(model, QEServerListSortModel) else model
    return model.data(model.index(row, 0), source._ROLE_RMAP[name])


def names(model):
    return [role(model, row, 'name') for row in range(model.rowCount(QModelIndex()))]


class TestQEServerListModel(QETestCase):

    def _make(self, network):
        with patch.object(QEServerListModel, 'register_callbacks'):
            model = QEServerListModel(network)
        proxy = QEServerListSortModel(model)
        return model, proxy

    def _default_network(self):
        net = FakeNetwork()
        a, b, c = FakeInterface('a'), FakeInterface('b'), FakeInterface('c')
        net.add_chain('main', 'mainchain', [a, b])
        net.add_chain('fork', 'forkchain', [c])
        net.interface = a
        net.disconnected = [FakeServerAddr('x'), FakeServerAddr('y')]
        return net

    @qt_test
    def test_initial_population_and_proxy_order(self):
        net = self._default_network()
        model, proxy = self._make(net)

        self.assertEqual(names(model), ['a:50002:s', 'b:50002:s', 'c:50002:s', 'x:50002:s', 'y:50002:s'])
        # chains sorted by name, disconnected last
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s'])
        self.assertEqual([role(proxy, r, 'chain') for r in range(5)], ['forkchain', 'mainchain', 'mainchain', '', ''])
        self.assertEqual([role(proxy, r, 'is_connected') for r in range(5)], [True, True, True, False, False])
        self.assertEqual([role(proxy, r, 'is_primary') for r in range(5)], [False, True, False, False, False])
        self.assertEqual([role(proxy, r, 'is_bookmarked') for r in range(5)], [False] * 5)
        self.assertEqual([role(proxy, r, 'is_lagging') for r in range(5)], [False] * 5)
        self.assertEqual(role(proxy, 0, 'address'), 'c:50002')
        self.assertEqual(role(proxy, 3, 'address'), 'x:50002')
        self.assertEqual(proxy.roleNames(), model.roleNames())

    @qt_test
    def test_all_roles_readable(self):
        net = self._default_network()
        net.disconnected.append(FakeServerAddr('abc.onion'))
        model, proxy = self._make(net)
        for row in range(model.rowCount(QModelIndex())):
            for name in model._ROLE_NAMES:
                role(model, row, name)
        self.assertEqual(role(model, 5, 'is_tor'), True)
        self.assertEqual(role(model, 0, 'is_tor'), False)

    @qt_test
    def test_disconnected_becomes_connected_updates_in_place(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.dataChanged, model.modelReset, model.rowsInserted, model.rowsRemoved)

        # 'x' connects on the main chain
        x = FakeInterface('x', tip=101)
        x.blockchain = net.chains['main'][0].blockchain
        net.chains['main'].append(x)
        net.disconnected = [FakeServerAddr('y')]
        model.updateModel()

        # source row stays where it was
        self.assertEqual(names(model), ['a:50002:s', 'b:50002:s', 'c:50002:s', 'x:50002:s', 'y:50002:s'])
        self.assertEqual(role(model, 3, 'is_connected'), True)
        self.assertEqual(role(model, 3, 'chain'), 'mainchain')
        self.assertEqual(role(model, 3, 'height'), 101)
        # only dataChanged, no structural changes
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 0)
        self.assertEqual(len(receiver.receivedForSignal(model.rowsInserted)), 0)
        self.assertEqual(len(receiver.receivedForSignal(model.rowsRemoved)), 0)
        changed = receiver.receivedForSignal(model.dataChanged)
        self.assertEqual(len(changed), 1)
        top_left, bottom_right, roles = changed[0][1]
        self.assertEqual((top_left.row(), bottom_right.row()), (3, 3))
        self.assertEqual(set(roles), {model._ROLE_RMAP[n] for n in ('is_connected', 'chain', 'height')})
        # proxy moved it into the main chain group, after b (stable within group)
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s'])

    @qt_test
    def test_connected_server_drops(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.dataChanged, model.modelReset, model.rowsInserted, model.rowsRemoved)

        # 'b' disconnects but stays a known server
        net.chains['main'] = [net.chains['main'][0]]
        net.disconnected = [FakeServerAddr('b'), FakeServerAddr('x'), FakeServerAddr('y')]
        model.updateModel()

        self.assertEqual(names(model), ['a:50002:s', 'b:50002:s', 'c:50002:s', 'x:50002:s', 'y:50002:s'])
        self.assertEqual(role(model, 1, 'is_connected'), False)
        self.assertEqual(role(model, 1, 'chain'), '')
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 0)
        self.assertEqual(len(receiver.receivedForSignal(model.rowsRemoved)), 0)
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s'])

        # 'y' is forgotten entirely
        receiver.clear()
        net.disconnected = [FakeServerAddr('b'), FakeServerAddr('x')]
        model.updateModel()
        self.assertEqual(names(model), ['a:50002:s', 'b:50002:s', 'c:50002:s', 'x:50002:s'])
        self.assertEqual(len(receiver.receivedForSignal(model.rowsRemoved)), 1)
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 0)
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s'])

    @qt_test
    def test_new_servers_appended(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.dataChanged, model.modelReset, model.rowsInserted, model.rowsRemoved)

        # a new connected server on the fork chain, and a new known server
        d = FakeInterface('d')
        d.blockchain = net.chains['fork'][0].blockchain
        net.chains['fork'].append(d)
        net.disconnected.append(FakeServerAddr('z'))
        model.updateModel()

        self.assertEqual(names(model), ['a:50002:s', 'b:50002:s', 'c:50002:s', 'x:50002:s', 'y:50002:s', 'd:50002:s', 'z:50002:s'])
        inserted = receiver.receivedForSignal(model.rowsInserted)
        self.assertEqual(len(inserted), 1)
        self.assertEqual((inserted[0][1][1], inserted[0][1][2]), (5, 6))
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 0)
        self.assertEqual(len(receiver.receivedForSignal(model.dataChanged)), 0)
        self.assertEqual(names(proxy), ['c:50002:s', 'd:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s', 'z:50002:s'])

    @qt_test
    def test_no_change_emits_nothing(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.dataChanged, model.modelReset, model.rowsInserted, model.rowsRemoved)
        model.updateModel()
        self.assertEqual(receiver.received, [])

    @qt_test
    def test_update_primary_through_proxy(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.dataChanged, model.modelReset)

        net.interface = net.chains['fork'][0]  # 'c'
        model.updatePrimary()

        changed = receiver.receivedForSignal(model.dataChanged)
        self.assertEqual(len(changed), 2)
        for _, (tl, br, roles) in changed:
            self.assertEqual(list(roles), [model._ROLE_RMAP['is_primary']])
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 0)
        self.assertEqual([role(proxy, r, 'is_primary') for r in range(5)], [True, False, False, False, False])
        # order unaffected
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s'])

        # primary gone
        net.interface = None
        model.updatePrimary()
        self.assertEqual([role(proxy, r, 'is_primary') for r in range(5)], [False] * 5)

    @qt_test
    def test_init_model_resets(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.modelReset)
        model.initModel()
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 1)
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s'])

    @qt_test
    def test_bookmark_toggle_updates_in_place_and_resorts(self):
        net = self._default_network()
        model, proxy = self._make(net)
        receiver = QEventReceiver(model.dataChanged, model.modelReset, model.rowsInserted, model.rowsRemoved)

        # bookmark 'y'
        net.bookmarks.add('y:50002:s')
        model.updateModel()

        changed = receiver.receivedForSignal(model.dataChanged)
        self.assertEqual(len(changed), 1)
        top_left, bottom_right, roles = changed[0][1]
        self.assertEqual((top_left.row(), bottom_right.row()), (4, 4))
        self.assertEqual(list(roles), [model._ROLE_RMAP['is_bookmarked']])
        self.assertEqual(len(receiver.receivedForSignal(model.modelReset)), 0)
        self.assertEqual(len(receiver.receivedForSignal(model.rowsInserted)), 0)
        self.assertEqual(len(receiver.receivedForSignal(model.rowsRemoved)), 0)
        # source row stays where it was, proxy moves it to the top of the disconnected group
        self.assertEqual(names(model), ['a:50002:s', 'b:50002:s', 'c:50002:s', 'x:50002:s', 'y:50002:s'])
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'y:50002:s', 'x:50002:s'])
        self.assertEqual([role(proxy, r, 'is_bookmarked') for r in range(5)], [False, False, False, True, False])

        # remove the bookmark again
        receiver.clear()
        net.bookmarks.clear()
        model.updateModel()
        self.assertEqual(len(receiver.receivedForSignal(model.dataChanged)), 1)
        self.assertEqual(names(proxy), ['c:50002:s', 'a:50002:s', 'b:50002:s', 'x:50002:s', 'y:50002:s'])
        self.assertEqual([role(proxy, r, 'is_bookmarked') for r in range(5)], [False] * 5)

    @qt_test
    def test_bookmarked_connected_server(self):
        net = self._default_network()
        net.bookmarks.add('b:50002:s')
        model, proxy = self._make(net)

        self.assertEqual(role(model, 1, 'is_bookmarked'), True)
        # bookmarked server sorts first within its chain group, chain grouping unaffected
        self.assertEqual(names(proxy), ['c:50002:s', 'b:50002:s', 'a:50002:s', 'x:50002:s', 'y:50002:s'])
        self.assertEqual([role(proxy, r, 'chain') for r in range(5)], ['forkchain', 'mainchain', 'mainchain', '', ''])

        # rebuild from scratch keeps the role
        model.initModel()
        self.assertEqual([role(proxy, r, 'is_bookmarked') for r in range(5)], [False, True, False, False, False])

    @qt_test
    def test_lagging_server(self):
        net = self._default_network()
        # chain height is 100: a tip more than 1 block behind is lagging
        net.chains['main'][1].tip = 98  # 'b'
        model, proxy = self._make(net)
        self.assertEqual([role(model, r, 'is_lagging') for r in range(5)], [False, True, False, False, False])

        receiver = QEventReceiver(model.dataChanged)
        net.chains['main'][1].tip = 99  # one block behind is fine
        model.updateModel()
        self.assertEqual(role(model, 1, 'is_lagging'), False)
        changed = receiver.receivedForSignal(model.dataChanged)
        self.assertEqual(len(changed), 1)
        self.assertEqual(set(changed[0][1][2]), {model._ROLE_RMAP[n] for n in ('is_lagging', 'height')})
