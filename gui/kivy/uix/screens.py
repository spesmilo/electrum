from kivy.app import App
from kivy.cache import Cache
from kivy.clock import Clock
from kivy.compat import string_types
from kivy.properties import (ObjectProperty, DictProperty, NumericProperty,
                             ListProperty)
from kivy.lang import Builder
from kivy.factory import Factory

from electrum.i18n import _

# Delayed imports
app = None


class CScreen(Factory.Screen):

    __events__ = ('on_activate', 'on_deactivate', 'on_enter', 'on_leave')

    action_view = ObjectProperty(None)
    loaded = False
    kvname = None
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

    def on_activate(self):
        
        if self.kvname and not self.loaded:
            print "loading:" + self.kvname
            self.screen = Builder.load_file('gui/kivy/uix/ui_screens/' + self.kvname + '.kv')
            self.add_widget(self.screen)
            self.loaded = True
            self.update()
            setattr(self.app, self.kvname + '_screen', self)

            #app.history_screen = screen
            #app.recent_activity_card = screen.ids.recent_activity_card
            #app.update_history_tab()

        #Clock.schedule_once(lambda dt: self._change_action_view())

    def on_leave(self):
        self.dispatch('on_deactivate')

    def on_deactivate(self):
        pass
        #Clock.schedule_once(lambda dt: self._change_action_view())


class HistoryScreen(CScreen):

    tab = ObjectProperty(None)
    kvname = 'history'

    def __init__(self, **kwargs):
        self.ra_dialog = None
        super(HistoryScreen, self).__init__(**kwargs)

    def show_tx_details(self, item):
        ra_dialog = Cache.get('electrum_widgets', 'RecentActivityDialog')
        if not ra_dialog:
            Factory.register('RecentActivityDialog',
                             module='electrum_gui.kivy.uix.dialogs.carousel_dialog')
            Factory.register('GridView',
                             module='electrum_gui.kivy.uix.gridview')
            ra_dialog = ra_dialog = Factory.RecentActivityDialog()
            Cache.append('electrum_widgets', 'RecentActivityDialog', ra_dialog)
        ra_dialog.item = item
        ra_dialog.open()

    def parse_histories(self, items):
        for item in items:
            tx_hash, conf, value, timestamp, balance = item
            time_str = _("unknown")
            if conf > 0:
                try:
                    time_str = datetime.datetime.fromtimestamp(
                                    timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = _("error")

            if conf == -1:
                time_str = _('unverified')
                icon = "atlas://gui/kivy/theming/light/close"
            elif conf == 0:
                time_str = _('pending')
                icon = "atlas://gui/kivy/theming/light/unconfirmed"
            elif conf < 6:
                time_str = ''  # add new to fix error when conf < 0
                conf = max(1, conf)
                icon = "atlas://gui/kivy/theming/light/clock{}".format(conf)
            else:
                icon = "atlas://gui/kivy/theming/light/confirmed"

            if value is not None:
                v_str = self.app.format_amount(value, True).replace(',','.')
            else:
                v_str = '--'

            balance_str = self.app.format_amount(balance).replace(',','.')

            if tx_hash:
                label, is_default_label = self.app.wallet.get_label(tx_hash)
            else:
                label = _('Pruned transaction outputs')
                is_default_label = False

            yield (conf, icon, time_str, label, v_str, balance_str, tx_hash)

    def update(self, see_all=False):

        history_card = self.screen.ids.recent_activity_card
        histories = self.parse_histories(reversed(
                        self.app.wallet.get_history(self.app.current_account)))
        # repopulate History Card
        last_widget = history_card.ids.content.children[-1]
        history_card.ids.content.clear_widgets()
        history_add = history_card.ids.content.add_widget
        history_add(last_widget)
        RecentActivityItem = Factory.RecentActivityItem

        from weakref import ref
        from decimal import Decimal

        get_history_rate = self.app.get_history_rate
        count = 0
        for items in histories:
            count += 1
            conf, icon, date_time, address, amount, balance, tx = items
            ri = RecentActivityItem()
            ri.icon = icon
            ri.date = date_time
            mintimestr = date_time.split()[0]
            ri.address = address
            ri.amount = amount
            ri.quote_text = get_history_rate(ref(ri),
                                             Decimal(amount),
                                             mintimestr)
            ri.balance = balance
            ri.confirmations = conf
            ri.tx_hash = tx
            history_add(ri)
            if count == 8 and not see_all:
                break

        history_card.ids.btn_see_all.opacity = (0 if count < 8 else 1)


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
    def set_qr_data(self, uri):
        self.ids.payto_e.text = uri.get('address', '')
        self.ids.message_e.text = uri.get('message', '')
        self.ids.amount_e.text = uri.get('amount', '')

class ReceiveScreen(CScreen):
    kvname = 'receive'

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
        if  idx == 0:
            scroll_x = 1
        elif idx == len(self.tab_list) - 1:
            scroll_x = 0
        else:
            self_center_x = scrlv.center_x
            vcenter_x = value.center_x
            diff_x = (self_center_x - vcenter_x)
            try:
                scroll_x = scrlv.scroll_x - (diff_x / scrlv.width)
            except ZeroDivisionError:
                pass
        mation = Factory.Animation(scroll_x=scroll_x, d=.25)
        mation.cancel_all(scrlv)
        mation.start(scrlv)

    def on_current_tab(self, instance, value):
        if value.text == 'default_tab':
            return
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
