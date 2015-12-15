from weakref import ref
from decimal import Decimal
import re
import datetime
import traceback, sys
import threading

from kivy.app import App
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.compat import string_types
from kivy.properties import (ObjectProperty, DictProperty, NumericProperty,
                             ListProperty, StringProperty)


from kivy.lang import Builder
from kivy.factory import Factory

from electrum.i18n import _
from electrum.util import profiler, parse_URI, format_time
from electrum import bitcoin
from electrum.util import timestamp_to_datetime
from electrum.plugins import run_hook

from context_menu import ContextMenu

from electrum.paymentrequest import PR_UNPAID, PR_PAID, PR_UNKNOWN, PR_EXPIRED


class CScreen(Factory.Screen):

    __events__ = ('on_activate', 'on_deactivate', 'on_enter', 'on_leave')
    action_view = ObjectProperty(None)
    loaded = False
    kvname = None
    context_menu = None
    menu_actions = []
    app = App.get_running_app()

    def _change_action_view(self):
        app = App.get_running_app()
        action_bar = app.root.manager.current_screen.ids.action_bar
        _action_view = self.action_view

        if (not _action_view) or _action_view.parent:
            return
        action_bar.clear_widgets()
        action_bar.add_widget(_action_view)

    def on_enter(self):
        # FIXME: use a proper event don't use animation time of screen
        Clock.schedule_once(lambda dt: self.dispatch('on_activate'), .25)
        pass

    def update(self):
        pass

    @profiler
    def load_screen(self):
        self.screen = Builder.load_file('gui/kivy/uix/ui_screens/' + self.kvname + '.kv')
        self.add_widget(self.screen)
        self.loaded = True
        self.update()
        setattr(self.app, self.kvname + '_screen', self)

    def on_activate(self):
        if self.kvname and not self.loaded:
            self.load_screen()
        #Clock.schedule_once(lambda dt: self._change_action_view())

    def on_leave(self):
        self.dispatch('on_deactivate')

    def on_deactivate(self):
        self.hide_menu()

    def hide_menu(self):
        if self.context_menu is not None:
            self.remove_widget(self.context_menu)
            self.context_menu = None

    def show_menu(self, obj):
        self.hide_menu()
        self.context_menu = ContextMenu(obj, self.menu_actions)
        self.add_widget(self.context_menu)


class HistoryScreen(CScreen):

    tab = ObjectProperty(None)
    kvname = 'history'

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(HistoryScreen, self).__init__(**kwargs)
        self.menu_actions = [ (_('Label'), self.label_dialog), (_('Details'), self.app.tx_details_dialog)]

    def label_dialog(self, obj):
        from dialogs.label_dialog import LabelDialog
        key = obj.tx_hash
        text = self.app.wallet.get_label(key)[0]
        def callback(text):
            self.app.wallet.set_label(key, text)
            self.update()
        d = LabelDialog(_('Enter Transaction Label'), text, callback)
        d.open()


    def parse_history(self, items):
        for item in items:
            tx_hash, conf, value, timestamp, balance = item
            time_str = _("unknown")
            if conf > 0:
                try:
                    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = _("error")
            if conf == -1:
                time_str = _('unverified')
                icon = "atlas://gui/kivy/theming/light/close"
            elif conf == 0:
                time_str = _('pending')
                icon = "atlas://gui/kivy/theming/light/unconfirmed"
            elif conf < 6:
                conf = max(1, conf)
                icon = "atlas://gui/kivy/theming/light/clock{}".format(conf)
            else:
                icon = "atlas://gui/kivy/theming/light/confirmed"

            if tx_hash:
                label, is_default_label = self.app.wallet.get_label(tx_hash)
            else:
                label = _('Pruned transaction outputs')
                is_default_label = False

            date = timestamp_to_datetime(timestamp)
            rate = run_hook('history_rate', date)
            if self.app.fiat_unit:
                quote_text = "..." if rate is None else "{0:.3} {1}".format(Decimal(value) / 100000000 * Decimal(rate), self.app.fiat_unit)
            else:
                quote_text = ''
            yield (conf, icon, time_str, label, value, tx_hash, quote_text)

    def update(self, see_all=False):
        if self.app.wallet is None:
            return

        history_card = self.screen.ids.history_container
        history = self.parse_history(reversed(
            self.app.wallet.get_history(self.app.current_account)))
        # repopulate History Card
        history_card.clear_widgets()
        history_add = history_card.add_widget
        count = 0
        for item in history:
            count += 1
            conf, icon, date_time, message, value, tx, quote_text = item
            ri = Factory.HistoryItem()
            ri.icon = icon
            ri.date = date_time
            ri.message = message
            ri.value = value
            ri.quote_text = quote_text
            ri.confirmations = conf
            ri.tx_hash = tx
            ri.screen = self
            history_add(ri)
            if count == 8 and not see_all:
                break



class ScreenAddress(CScreen):
    '''This is the dialog that shows a carousel of the currently available
    addresses.
    '''

    labels  = DictProperty({})
    ''' A precached list of address labels.
    '''

    tab =  ObjectProperty(None)
    ''' The tab associated With this Carousel
    '''


class ScreenPassword(Factory.Screen):

    __events__ = ('on_release', 'on_deactivate', 'on_activate')

    def on_activate(self):
        app = App.get_running_app()
        action_bar = app.root.main_screen.ids.action_bar
        action_bar.add_widget(self._action_view)

    def on_deactivate(self):
        self.ids.password.text = ''

    def on_release(self, *args):
        pass



class SendScreen(CScreen):

    kvname = 'send'
    payment_request = None

    def set_URI(self, uri):
        self.screen.address = uri.get('address', '')
        self.screen.message = uri.get('message', '')
        amount = uri.get('amount')
        if amount:
            self.screen.amount = self.app.format_amount_and_units(amount)

    def update(self):
        if self.app.current_invoice:
            self.set_request(self.app.current_invoice)

    def do_clear(self):
        self.screen.amount = ''
        self.screen.message = ''
        self.screen.address = ''
        self.payment_request = None

    def amount_dialog(self):
        Clock.schedule_once(lambda dt: self.app.amount_dialog(self, True), .25)

    def set_request(self, pr):
        self.payment_request = pr
        self.screen.address = pr.get_requestor()
        amount = pr.get_amount()
        if amount:
            self.screen.amount = self.app.format_amount_and_units(amount)
        self.screen.message = pr.get_memo()

    def do_paste(self):
        contents = unicode(self.app._clipboard.get())
        try:
            uri = parse_URI(contents)
        except:
            self.app.show_info("Invalid URI", contents)
            return
        self.set_URI(uri)

    def do_send(self):
        if self.payment_request:
            if self.payment_request.has_expired():
                self.app.show_error(_('Payment request has expired'))
                return
            outputs = self.payment_request.get_outputs()
        else:
            address = str(self.screen.address)
            if not bitcoin.is_address(address):
                self.app.show_error(_('Invalid Bitcoin Address') + ':\n' + address)
                return
            try:
                amount = self.app.get_amount(self.screen.amount)
            except:
                self.app.show_error(_('Invalid amount') + ':\n' + self.screen.amount)
                return
            outputs = [('address', address, amount)]
        message = unicode(self.screen.message)
        fee = None
        self.app.protected(self.send_tx, (outputs, fee, message))

    def send_tx(self, *args):
        self.app.show_info("Sending...")
        threading.Thread(target=self.send_tx_thread, args=args).start()

    def send_tx_thread(self, outputs, fee, label, password):
        # make unsigned transaction
        coins = self.app.wallet.get_spendable_coins()
        try:
            tx = self.app.wallet.make_unsigned_transaction(coins, outputs, self.app.electrum_config, fee)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.app.show_error(str(e))
            return
        # sign transaction
        try:
            self.app.wallet.sign_transaction(tx, password)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self.app.show_error(str(e))
            return
        # broadcast
        ok, txid = self.app.wallet.sendtx(tx)
        self.app.show_info(txid)


class ReceiveScreen(CScreen):

    kvname = 'receive'
    
    def update(self):
        addr = self.app.get_receive_address()
        self.screen.address = addr
        req = self.app.wallet.receive_requests.get(addr)
        if req:
            self.screen.message = unicode(req.get('memo', ''))
            amount = req.get('amount')
            if amount:
                self.screen.amount = self.app.format_amount_and_units(amount)

    def amount_callback(self, popup):
        amount_label = self.screen.ids.get('amount')
        amount_label.text = popup.ids.amount_label.text
        self.update_qr()

    def get_URI(self):
        from electrum.util import create_URI
        amount = self.screen.amount
        if amount:
            a, u = self.screen.amount.split()
            assert u == self.app.base_unit
            amount = Decimal(a) * pow(10, self.app.decimal_point())
        return create_URI(self.screen.address, amount, self.screen.message)

    @profiler
    def update_qr(self):
        uri = self.get_URI()
        qr = self.screen.ids.qr
        qr.set_data(uri)

    def do_copy(self):
        uri = self.get_URI()
        self.app._clipboard.put(uri, 'text/plain')

    def do_save(self):
        addr = str(self.screen.address)
        amount = str(self.screen.amount)
        message = str(self.screen.message) #.ids.message_input.text)
        if not message and not amount:
            self.app.show_error(_('No message or amount'))
            return
        if amount:
            amount = self.app.get_amount(amount)
        else:
            amount = 0
        print "saving", amount, message
        req = self.app.wallet.make_payment_request(addr, amount, message, None)
        self.app.wallet.add_payment_request(req, self.app.electrum_config)
        self.app.show_error(_('Request saved'))
        self.app.update_screen('requests')

    def do_new(self):
        self.app.receive_address = None
        self.screen.amount = ''
        self.screen.message = ''
        self.update()


class ContactsScreen(CScreen):
    kvname = 'contacts'

    def add_new_contact(self):
        dlg = Cache.get('electrum_widgets', 'NewContactDialog')
        if not dlg:
            dlg = NewContactDialog()
            Cache.append('electrum_widgets', 'NewContactDialog', dlg)
        dlg.open()

    def update(self):
        contact_list = self.screen.ids.contact_container
        contact_list.clear_widgets()
        child = -1
        children = contact_list.children
        for key in sorted(self.app.contacts.keys()):
            _type, value = self.app.contacts[key]
            child += 1
            try:
                if children[child].label == value:
                    continue
            except IndexError:
                pass
            ci = Factory.ContactItem()
            ci.address = key
            ci.label = value
            contact_list.add_widget(ci)


class InvoicesScreen(CScreen):
    kvname = 'invoices'

    def update(self):
        self.menu_actions = [(_('Pay'), self.do_pay), (_('Delete'), self.do_delete)]
        invoices_list = self.screen.ids.invoices_container
        invoices_list.clear_widgets()
        for pr in self.app.invoices.sorted_list():
            ci = Factory.InvoiceItem()
            ci.key = pr.get_id()
            ci.requestor = pr.get_requestor()
            ci.memo = pr.memo
            ci.amount = self.app.format_amount_and_units(pr.get_amount())
            status = self.app.invoices.get_status(ci.key)
            if status == PR_PAID:
                ci.icon = "atlas://gui/kivy/theming/light/confirmed"
            elif status == PR_EXPIRED:
                ci.icon = "atlas://gui/kivy/theming/light/important"
            else:
                ci.icon = "atlas://gui/kivy/theming/light/important"
            exp = pr.get_expiration_date()
            ci.date = format_time(exp) if exp else _('Never')
            ci.screen = self
            invoices_list.add_widget(ci)

    def do_pay(self, obj):
        self.app.do_pay(obj)

    def do_delete(self, obj):
        self.app.invoices.remove(obj.key)
        self.app.update_screen('invoices')

class RequestsScreen(CScreen):
    kvname = 'requests'

    def update(self):

        self.menu_actions = [(_('Show'), self.do_show), (_('Delete'), self.do_delete)]

        requests_list = self.screen.ids.requests_container
        requests_list.clear_widgets()
        for req in self.app.wallet.get_sorted_requests(self.app.electrum_config):
            address = req['address']
            timestamp = req.get('time', 0)
            amount = req.get('amount')
            expiration = req.get('exp', None)
            status = req.get('status')
            signature = req.get('sig')
            ci = Factory.RequestItem()
            ci.address = req['address']
            label, is_default = self.app.wallet.get_label(address)
            if label:
                ci.memo = label 
            status = req.get('status')
            if status == PR_PAID:
                ci.icon = "atlas://gui/kivy/theming/light/confirmed"
            elif status == PR_EXPIRED:
                ci.icon = "atlas://gui/kivy/theming/light/important"
            else:
                ci.icon = "atlas://gui/kivy/theming/light/important"
            ci.amount = self.app.format_amount_and_units(amount) if amount else ''
            ci.date = format_time(timestamp)
            ci.screen = self
            requests_list.add_widget(ci)

    def do_show(self, obj):
        self.app.show_request(obj.address)

    def do_delete(self, obj):
        self.app.wallet.remove_payment_request(obj.address, self.app.electrum_config)
        self.update()


class CSpinner(Factory.Spinner):
    '''CustomDropDown that allows fading out the dropdown
    '''

    def _update_dropdown(self, *largs):
        dp = self._dropdown
        cls = self.option_cls
        if isinstance(cls, string_types):
            cls = Factory.get(cls)
        dp.clear_widgets()
        def do_release(option):
            Clock.schedule_once(lambda dt: dp.select(option.text), .25)
        for value in self.values:
            item = cls(text=value)
            item.bind(on_release=do_release)
            dp.add_widget(item)


class TabbedCarousel(Factory.TabbedPanel):
    '''Custom TabbedPanel using a carousel used in the Main Screen
    '''

    carousel = ObjectProperty(None)

    def animate_tab_to_center(self, value):
        scrlv = self._tab_strip.parent
        if not scrlv:
            return
        idx = self.tab_list.index(value)
        n = len(self.tab_list)
        if idx in [0, 1]:
            scroll_x = 1
        elif idx in [n-1, n-2]:
            scroll_x = 0
        else:
            scroll_x = 1. * (n - idx - 1) / (n - 1)

        mation = Factory.Animation(scroll_x=scroll_x, d=.25)
        mation.cancel_all(scrlv)
        mation.start(scrlv)

    def on_current_tab(self, instance, value):
        self.animate_tab_to_center(value)

    def on_index(self, instance, value):
        current_slide = instance.current_slide
        if not hasattr(current_slide, 'tab'):
            return
        tab = current_slide.tab
        ct = self.current_tab
        try:
            if ct.text != tab.text:
                carousel = self.carousel
                carousel.slides[ct.slide].dispatch('on_leave')
                self.switch_to(tab)
                carousel.slides[tab.slide].dispatch('on_enter')
        except AttributeError:
            current_slide.dispatch('on_enter')

    def switch_to(self, header):
        # we have to replace the functionality of the original switch_to
        if not header:
            return
        if not hasattr(header, 'slide'):
            header.content = self.carousel
            super(TabbedCarousel, self).switch_to(header)
            try:
                tab = self.tab_list[-1]
            except IndexError:
                return
            self._current_tab = tab
            tab.state = 'down'
            return

        carousel = self.carousel
        self.current_tab.state = "normal"
        header.state = 'down'
        self._current_tab = header
        # set the carousel to load  the appropriate slide
        # saved in the screen attribute of the tab head
        slide = carousel.slides[header.slide]
        if carousel.current_slide != slide:
            carousel.current_slide.dispatch('on_leave')
            carousel.load_slide(slide)
            slide.dispatch('on_enter')

    def add_widget(self, widget, index=0):
        if isinstance(widget, Factory.CScreen):
            self.carousel.add_widget(widget)
            return
        super(TabbedCarousel, self).add_widget(widget, index=index)


class ELTextInput(Factory.TextInput):
    '''Custom TextInput used in main screens for numeric entry
    '''

    def insert_text(self, substring, from_undo=False):
        if not from_undo:
            if self.input_type == 'numbers':
                numeric_list = map(str, range(10))
                if '.' not in self.text:
                    numeric_list.append('.')
                if substring not in numeric_list:
                    return
        super(ELTextInput, self).insert_text(substring, from_undo=from_undo)
