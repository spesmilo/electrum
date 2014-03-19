from kivy.app import App
from kivy.uix.screenmanager import Screen
from kivy.properties import ObjectProperty
from kivy.clock import Clock


class CScreen(Screen):

    __events__ = ('on_activate', 'on_deactivate')

    action_view = ObjectProperty(None)

    def _change_action_view(self):
        app = App.get_running_app()
        action_bar = app.root.manager.current_screen.ids.action_bar
        _action_view = self.action_view

        if (not _action_view) or _action_view.parent:
            return
        action_bar.clear_widgets()
        action_bar.add_widget(_action_view)

    def on_activate(self):
        Clock.schedule_once(lambda dt: self._change_action_view())

    def on_deactivate(self):
        Clock.schedule_once(lambda dt: self._change_action_view())


class ScreenDashboard(CScreen):

    tab = ObjectProperty(None)

    def show_tx_details(
        self, date, address, amount, amount_color, balance,
        tx_hash, conf, quote_text):

        ra_dialog = RecentActivityDialog()

        ra_dialog.address = address
        ra_dialog.amount = amount
        ra_dialog.amount_color = amount_color
        ra_dialog.confirmations = conf
        ra_dialog.quote_text = quote_text
        date_time = date.split()
        if len(date_time) == 2:
            ra_dialog.date = date_time[0]
            ra_dialog.time = date_time[1]
            ra_dialog.status = 'Validated'
        else:
            ra_dialog.date = date_time
            ra_dialog.status = 'Pending'
        ra_dialog.tx_hash = tx_hash

        app = App.get_running_app()
        main_gui = app.gui.main_gui
        tx_hash = tx_hash
        tx = app.wallet.transactions.get(tx_hash)

        if tx_hash in app.wallet.transactions.keys():
            is_relevant, is_mine, v, fee = app.wallet.get_tx_value(tx)
            conf, timestamp = app.wallet.verifier.get_confirmations(tx_hash)
            #if timestamp:
            #    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
            #else:
            #    time_str = 'pending'
        else:
            is_mine = False

        ra_dialog.is_mine = is_mine

        if is_mine:
            if fee is not None: 
                ra_dialog.fee = main_gui.format_amount(fee)
            else:
                ra_dialog.fee = 'unknown'

        ra_dialog.open()


class ScreenPassword(Screen):

    __events__ = ('on_release', 'on_deactivate', 'on_activate')

    def on_activate(self):
        app = App.get_running_app()
        action_bar = app.root.main_screen.ids.action_bar
        action_bar.add_widget(self._action_view)

    def on_deactivate(self):
        self.ids.password.text = ''

    def on_release(self, *args):
        pass

class ScreenSend(CScreen):
    pass

class ScreenReceive(CScreen):
    pass

class ScreenContacts(CScreen):

    def add_new_contact(self):
        NewContactDialog().open()
