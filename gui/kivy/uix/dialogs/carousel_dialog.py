''' Dialogs intended to be used along with a slidable carousel inside
and indicators on either top, left, bottom or right side. These indicators can
be touched to travel to a particular slide.
'''
from electrum.i18n import _


from kivy.app import App
from kivy.clock import Clock
from kivy.properties import NumericProperty, ObjectProperty
from kivy.factory import Factory
from kivy.lang import Builder

import weakref


class CarouselHeader(Factory.TabbedPanelHeader):
    '''Tabbed Panel Header with a circular image on top to be used as a
    indicator for the current slide.
    '''

    slide = NumericProperty(0)
    ''' indicates the link to carousels slide'''


class CarouselDialog(Factory.AnimatedPopup):
    ''' A Popup dialog with a CarouselIndicator used as the content.
    '''

    carousel_content = ObjectProperty(None)

    def add_widget(self, widget, index=0):
        if isinstance(widget, Factory.Carousel):
            super(CarouselDialog, self).add_widget(widget, index)
            return
        if 'carousel_content' not in self.ids.keys():
            super(CarouselDialog, self).add_widget(widget)
            return
        self.carousel_content.add_widget(widget, index)


class WalletAddressesDialog(CarouselDialog):
    ''' Show current wallets and their addresses using qrcode widget
    '''

    def __init__(self, **kwargs):
        self._loaded = False
        super(WalletAddressesDialog, self).__init__(**kwargs)

    def on_activate(self):
        # do activate routine here
        slide = None

        if not self._loaded:
            self._loaded = True
            CarouselHeader = Factory.CarouselHeader
            ch = CarouselHeader()
            ch.slide = 0 # idx
            slide = Factory.ScreenAddress()

            slide.tab = ch

            self.add_widget(slide)
            self.add_widget(ch)

        app = App.get_running_app()
        if not slide:
            slide = self.carousel_content.carousel.slides[0]

        # add a tab for each wallet
        self.wallet_name = app.wallet.get_account_names()[0]
        labels = app.wallet.labels

        addresses = app.wallet.addresses()
        _labels = {}

        for address in addresses:
            _labels[labels.get(address, address)] = address

        slide.labels = _labels
        Clock.schedule_once(lambda dt: self._setup_slide(slide))

    def _setup_slide(self, slide):
        btn_address = slide.ids.btn_address
        btn_address.values = values = slide.labels.keys()
        if not btn_address.text:
            btn_address.text = values[0]


class RecentActivityDialog(CarouselDialog):
    '''
    '''
    def on_activate(self):

        # animate to first slide
        #carousel = self.carousel_content.carousel
        #carousel.load_slide(carousel.slides[0])

        item = self.item
        try:
            self.address = item.address
        except ReferenceError:
            self.dismiss()
            return

        self.amount = item.amount[1:]
        self.amount_color = item.amount_color
        self.confirmations = item.confirmations
        self.quote_text = item.quote_text
        date_time = item.date.split()
        if len(date_time) == 2:
            self.date = date_time[0]
            self.time = date_time[1]
            self.status = 'Validated'
        else:
            self.date = item.date
            self.status = 'Pending'
        self.tx_hash = item.tx_hash

        app = App.get_running_app()

        tx_hash = item.tx_hash
        tx = app.wallet.transactions.get(tx_hash)
        tx.deserialize()

        if tx_hash in app.wallet.transactions.keys():
            is_relevant, is_mine, v, fee = app.wallet.get_wallet_delta(tx)
            conf, timestamp = app.wallet.get_confirmations(tx_hash)
        else:
            is_mine = False

        self.is_mine = is_mine

        if is_mine:
            if fee is not None:
                self.fee = app.format_amount(fee)
            else:
                self.fee = 'unknown'

        labels = app.wallet.labels
        addresses = app.wallet.addresses()
        _labels = {}

        self.wallet_name = app.wallet.get_account_names()['0']
        for address in addresses:
            _labels[labels.get(address, address)] = address

        self.labels = _labels

    def open(self):
        self._trans_actv = self._det_actv = self._in_actv\
            = self._out_actv = False
        super(RecentActivityDialog, self).open()

    def dismiss(self):
        if self._in_actv:
            self.ids.list_inputs.content = ""
            self.ids.list_inputs.clear_widgets()
        if self._out_actv:
            self.ids.list_outputs.content = ""
            self.ids.list_outputs.clear_widgets()
        super(RecentActivityDialog, self).dismiss()

    def dropdown_selected(self, value):
        app = App.get_running_app()
        try:
            labels = self.labels
        except AttributeError:
            return

        address = labels.get(self.address, self.address[1:])

        if value.startswith(_('Copy')):
            app.copy(address)
        elif value.startswith(_('Send')):
            app.send_payment(address)
            self.dismiss()

    def activate_screen_transactionid(self, screen):
        if self._trans_actv:
            return

        self._trans_actv = True
        Clock.schedule_once(
            lambda dt: self._activate_screen_transactionid(screen), .1)

    def _activate_screen_transactionid(self, screen):
        content = screen.content
        if not content:
            content = Factory.RecentActivityScrTransID()
            screen.content = content
            screen.add_widget(content)
        content.tx_hash = self.tx_hash
        content.text_color = self.text_color
        content.carousel_content = self.carousel_content

    def activate_screen_inputs(self, screen):
        if self._in_actv:
            return

        self._in_actv = True
        Clock.schedule_once(
            lambda dt: self._activate_screen_inputs(screen), .1)

    def _activate_screen_inputs(self, screen):
        content = screen.content
        if not content:
            content = Factory.RecentActivityScrInputs()
            screen.content = content
            screen.add_widget(content)
        self.populate_inputs_outputs(content, 'in')

    def activate_screen_outputs(self, screen):
        if self._out_actv:
            return

        self._out_actv = True
        Clock.schedule_once(
            lambda dt: self._activate_screen_outputs(screen), .1)

    def _activate_screen_outputs(self, screen):
        content = screen.content
        if not content:
            content = Factory.RecentActivityScrOutputs()
            screen.content = content
            screen.add_widget(content)
        self.populate_inputs_outputs(content, 'out')

    def populate_inputs_outputs(self, content, mode):
        app = App.get_running_app()
        tx_hash = self.tx_hash
        if tx_hash:
            tx = app.wallet.transactions.get(tx_hash)
            tx.deserialize()
            if mode == 'out':
                content.data = \
                    [(address, app.format_amount(value))\
                    for _type, address, value in tx.outputs]
            else:
                content.data = \
                    [(input['address'], input['prevout_hash'])\
                    for input in tx.inputs]
