import asyncio
from typing import TYPE_CHECKING, Optional, Union

from kivy.lang import Builder
from kivy.factory import Factory
from kivy.uix.popup import Popup

from electrum.util import bh2u
from electrum.logging import Logger
from electrum.lnutil import LOCAL, REMOTE, format_short_channel_id
from electrum.lnchannel import AbstractChannel, Channel, ChannelState, ChanCloseOption
from electrum.gui.kivy.i18n import _
from electrum.transaction import PartialTxOutput, Transaction
from electrum.util import NotEnoughFunds, NoDynamicFeeEstimates, format_fee_satoshis, quantize_feerate
from electrum.lnutil import ln_dummy_address
from electrum.gui import messages

from ..actiondropdown import ActionButtonOption, ActionDropdown
from .fee_dialog import FeeDialog
from .question import Question
from .qr_dialog import QRDialog
from .choice_dialog import ChoiceDialog

if TYPE_CHECKING:
    from ...main_window import ElectrumWindow
    from electrum import SimpleConfig


Builder.load_string(r'''
<SwapDialog@Popup>
    id: popup
    title: _('Lightning Swap')
    size_hint: 0.8, 0.8
    pos_hint: {'top':0.9}
    mining_fee_text: ''
    fee_rate_text: ''
    method: 0
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('You Send') + ':'
                size_hint: 0.4, 1
            Label:
                id: send_amount_label
                size_hint: 0.6, 1
                text: _('0')
                background_color: (0,0,0,0)
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('You Receive') + ':'
                size_hint: 0.4, 1
            Label:
                id: receive_amount_label
                text: _('0')
                background_color: (0,0,0,0)
                size_hint: 0.6, 1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Server Fee') + ':'
                size_hint: 0.4, 1
            Label:
                id: server_fee_label
                text: _('0')
                background_color: (0,0,0,0)
                size_hint: 0.6, 1
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                id: swap_action_label
                text: _('Adds receiving capacity')
                background_color: (0,0,0,0)
                font_size: '14dp'
        Slider:
            id: swap_slider
            range: 0, 4
            step: 1
            on_value: root.swap_slider_moved(self.value)
        Widget:
            size_hint: 1, 0.5
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Label:
                text: _('Mining Fee') + ':'
                size_hint: 0.4, 1
            Button:
                text: root.mining_fee_text + ' (' + root.fee_rate_text + ')'
                background_color: (0,0,0,0)
                bold: True
                on_release:
                    root.on_fee_button()
        Widget:
            size_hint: 1, 0.5
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            TopLabel:
                id: fee_estimate
                text: ''
                font_size: '14dp'
        Widget:
            size_hint: 1, 0.5
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: 'Cancel'
                size_hint: 0.5, None
                height: '48dp'
                on_release: root.dismiss()
            Button:
                id: ok_button
                text: 'OK'
                size_hint: 0.5, None
                height: '48dp'
                on_release:
                    root.on_ok()
                    root.dismiss()

<LightningChannelItem@CardItem>
    details: {}
    active: False
    short_channel_id: '<channelId not set>'
    status: ''
    is_backup: False
    capacity: ''
    node_alias: ''
    _chan: None
    BoxLayout:
        size_hint: 0.7, None
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        CardLabel:
            font_size: '15sp'
            text: root.node_alias
            shorten: True
            color: (.5,.5,.5,1) if not root.active else (1,1,1,1)
        Widget
        CardLabel:
            font_size: '13sp'
            text: root.short_channel_id
            color: (.5,.5,.5,1)
        Widget
    BoxLayout:
        size_hint: 0.3, None
        spacing: '8dp'
        height: '32dp'
        orientation: 'vertical'
        Widget
        CardLabel:
            text: root.status
            font_size: '13sp'
            halign: 'right'
            color: (.5,.5,.5,1) if not root.active else (1,1,1,1)
        Widget
        CardLabel:
            text: root.capacity
            font_size: '13sp'
            halign: 'right'
            color: (.5,.5,.5,1)
        Widget

<LightningChannelsDialog@Popup>:
    name: 'lightning_channels'
    title: _('Lightning Network')
    has_network: False
    has_lightning: False
    has_gossip: False
    can_send: ''
    can_receive: ''
    num_channels_text: ''
    id: popup
    BoxLayout:
        id: box
        orientation: 'vertical'
        spacing: '2dp'
        padding: '12dp'
        TopLabel:
            text: root.num_channels_text
        BoxLabel:
            text: _('You can send') + ':'
            value: root.can_send
        BoxLabel:
            text: _('You can receive') + ':'
            value: root.can_receive
        ScrollView:
            GridLayout:
                cols: 1
                id: lightning_channels_container
                size_hint: 1, None
                height: self.minimum_height
                spacing: '2dp'
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.3, None
                height: '48dp'
                text: _('Open Channel')
                disabled: not (root.has_network and root.has_lightning)
                on_release: popup.app.popup_dialog('lightning_open_channel_dialog')
            Button:
                size_hint: 0.3, None
                height: '48dp'
                text: _('Swap')
                disabled: not (root.has_network and root.has_lightning)
                on_release: popup.app.popup_dialog('swap_dialog')
            Button:
                size_hint: 0.3, None
                height: '48dp'
                text: _('Gossip')
                disabled: not root.has_gossip
                on_release: popup.app.popup_dialog('lightning')


<ChannelDetailsPopup@Popup>:
    id: popuproot
    data: []
    is_closed: False
    can_be_deleted: False
    node_id:''
    short_id:''
    initiator:''
    capacity:''
    funding_txid:''
    closing_txid:''
    state:''
    local_ctn:0
    remote_ctn:0
    local_csv:0
    remote_csv:0
    feerate:''
    can_send:''
    can_receive:''
    is_open:False
    warning: ''
    is_frozen_for_sending: False
    is_frozen_for_receiving: False
    channel_type:''
    BoxLayout:
        padding: '12dp', '12dp', '12dp', '12dp'
        spacing: '12dp'
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            scroll_wheel_distance: dp(114)
            BoxLayout:
                orientation: 'vertical'
                height: self.minimum_height
                size_hint_y: None
                spacing: '5dp'
                TopLabel:
                    text: root.warning
                    color: .905, .709, .509, 1
                BoxLabel:
                    text: _('Channel ID')
                    value: root.short_id
                BoxLabel:
                    text: _('State')
                    value: root.state
                BoxLabel:
                    text: _('Initiator')
                    value: root.initiator
                BoxLabel:
                    text: _('Capacity')
                    value: root.capacity
                BoxLabel:
                    text: _('Can send')
                    value: root.can_send if root.is_open else 'n/a'
                BoxLabel:
                    text: _('Can receive')
                    value: root.can_receive if root.is_open else 'n/a'
                BoxLabel:
                    text: _('CSV delay')
                    value: 'Local: %d\nRemote: %d' % (root.local_csv, root.remote_csv)
                BoxLabel:
                    text: _('CTN')
                    value: 'Local: %d\nRemote: %d' % (root.local_ctn, root.remote_ctn)
                BoxLabel:
                    text: _('Fee rate')
                    value: '{} sat/byte'.format(root.feerate)
                BoxLabel:
                    text: _('Frozen (for sending)')
                    value: str(root.is_frozen_for_sending)
                BoxLabel:
                    text: _('Frozen (for receiving)')
                    value: str(root.is_frozen_for_receiving)
                BoxLabel:
                    text: _('Channel type')
                    value: str(root.channel_type)
                Widget:
                    size_hint: 1, 0.1
                TopLabel:
                    text: _('Remote Node ID')
                TxHashLabel:
                    data: root.node_id
                    name: _('Remote Node ID')
                TopLabel:
                    text: _('Funding Transaction')
                TxHashLabel:
                    data: root.funding_txid
                    name: _('Funding Transaction')
                    touch_callback: lambda: app.show_transaction(root.funding_txid)
                TopLabel:
                    text: _('Closing Transaction')
                    opacity: int(bool(root.closing_txid))
                TxHashLabel:
                    opacity: int(bool(root.closing_txid))
                    data: root.closing_txid
                    name: _('Closing Transaction')
                    touch_callback: lambda: app.show_transaction(root.closing_txid)
                Widget:
                    size_hint: 1, 0.1
        Widget:
            size_hint: 1, 0.05
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            ActionDropdown:
                id: action_dropdown
                size_hint: 0.5, None
                height: '48dp'
            Widget:
                size_hint: 0.5, None

<ChannelBackupPopup@Popup>:
    id: popuproot
    data: []
    is_funded: False
    can_be_deleted: False
    node_id:''
    short_id:''
    initiator:''
    capacity:''
    funding_txid:''
    closing_txid:''
    state:''
    is_open:False
    BoxLayout:
        padding: '12dp', '12dp', '12dp', '12dp'
        spacing: '12dp'
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            scroll_wheel_distance: dp(114)
            BoxLayout:
                orientation: 'vertical'
                height: self.minimum_height
                size_hint_y: None
                spacing: '5dp'
                BoxLabel:
                    text: _('Channel ID')
                    value: root.short_id
                BoxLabel:
                    text: _('State')
                    value: root.state
                BoxLabel:
                    text: _('Initiator')
                    value: root.initiator
                BoxLabel:
                    text: _('Capacity')
                    value: root.capacity
                Widget:
                    size_hint: 1, 0.1
                TopLabel:
                    text: _('Remote Node ID')
                TxHashLabel:
                    data: root.node_id
                    name: _('Remote Node ID')
                TopLabel:
                    text: _('Funding Transaction')
                TxHashLabel:
                    data: root.funding_txid
                    name: _('Funding Transaction')
                    touch_callback: lambda: app.show_transaction(root.funding_txid)
                TopLabel:
                    text: _('Closing Transaction')
                    opacity: int(bool(root.closing_txid))
                TxHashLabel:
                    opacity: int(bool(root.closing_txid))
                    data: root.closing_txid
                    name: _('Closing Transaction')
                    touch_callback: lambda: app.show_transaction(root.closing_txid)
                Widget:
                    size_hint: 1, 0.1
        Widget:
            size_hint: 1, 0.05
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Request force-close')
                on_release: root.request_force_close()
                disabled: not root.is_funded
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Delete')
                on_release: root.remove_backup()
                disabled: not root.can_be_deleted
''')


class ChannelBackupPopup(Popup, Logger):

    def __init__(self, chan: AbstractChannel, app, **kwargs):
        Popup.__init__(self, **kwargs)
        Logger.__init__(self)
        self.chan = chan
        self.is_funded = chan.get_state() == ChannelState.FUNDED
        self.can_be_deleted = chan.can_be_deleted()
        self.funding_txid = chan.funding_outpoint.txid
        self.app = app
        self.short_id = format_short_channel_id(chan.short_channel_id)
        self.capacity = self.app.format_amount_and_units(chan.get_capacity())
        self.state = chan.get_state_for_GUI()
        self.title = _('Channel Backup')

    def request_force_close(self):
        msg = _('Request force close?')
        Question(msg, self._request_force_close).open()

    def _request_force_close(self, b):
        if not b:
            return
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.request_force_close(self.chan.channel_id), loop)
        try:
            coro.result(5)
            self.app.show_info(_('Request sent'))
        except Exception as e:
            self.logger.exception("Could not close channel")
            self.app.show_info(_('Could not close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def remove_backup(self):
        msg = _('Delete backup?')
        Question(msg, self._remove_backup).open()

    def _remove_backup(self, b):
        if not b:
            return
        self.app.wallet.lnworker.remove_channel_backup(self.chan.channel_id)
        self.dismiss()


class ChannelDetailsPopup(Popup, Logger):

    def __init__(self, chan: Channel, app: 'ElectrumWindow', **kwargs):
        Popup.__init__(self, **kwargs)
        Logger.__init__(self)
        self.is_closed = chan.is_closed()
        self.can_be_deleted = chan.can_be_deleted()
        self.app = app
        self.chan = chan
        self.title = _('Channel details')
        self.node_id = bh2u(chan.node_id)
        self.channel_id = bh2u(chan.channel_id)
        self.funding_txid = chan.funding_outpoint.txid
        self.short_id = format_short_channel_id(chan.short_channel_id)
        self.capacity = self.app.format_amount_and_units(chan.get_capacity())
        self.state = chan.get_state_for_GUI()
        self.local_ctn = chan.get_latest_ctn(LOCAL)
        self.remote_ctn = chan.get_latest_ctn(REMOTE)
        self.local_csv = chan.config[LOCAL].to_self_delay
        self.remote_csv = chan.config[REMOTE].to_self_delay
        self.initiator = 'Local' if chan.constraints.is_initiator else 'Remote'
        feerate_kw = chan.get_latest_feerate(LOCAL)
        self.feerate = str(quantize_feerate(Transaction.satperbyte_from_satperkw(feerate_kw)))
        self.can_send = self.app.format_amount_and_units(chan.available_to_spend(LOCAL) // 1000)
        self.can_receive = self.app.format_amount_and_units(chan.available_to_spend(REMOTE) // 1000)
        self.is_open = chan.is_open()
        closed = chan.get_closing_height()
        if closed:
            self.closing_txid, closing_height, closing_timestamp = closed
        msg = messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP
        self.warning = '' if self.app.wallet.lnworker.channel_db or self.app.wallet.lnworker.is_trampoline_peer(chan.node_id) else _('Warning') + ': ' + msg
        self.is_frozen_for_sending = chan.is_frozen_for_sending()
        self.is_frozen_for_receiving = chan.is_frozen_for_receiving()
        self.channel_type = chan.storage['channel_type'].name_minimal
        self.update_action_dropdown()

    def update_action_dropdown(self):
        action_dropdown = self.ids.action_dropdown  # type: ActionDropdown
        close_options = self.chan.get_close_options()
        options = [
            ActionButtonOption(text=_('Backup'), func=lambda btn: self.export_backup()),
            ActionButtonOption(text=_('Close channel'), func=lambda btn: self.close(close_options), enabled=close_options),
            ActionButtonOption(text=_('Delete'), func=lambda btn: self.remove_channel(), enabled=self.can_be_deleted),
        ]
        if not self.chan.is_closed():
            if not self.chan.is_frozen_for_sending():
                options.append(ActionButtonOption(text=_("Freeze") + "\n(for sending)", func=lambda btn: self.freeze_for_sending()))
            else:
                options.append(ActionButtonOption(text=_("Unfreeze") + "\n(for sending)", func=lambda btn: self.freeze_for_sending()))
            if not self.chan.is_frozen_for_receiving():
                options.append(ActionButtonOption(text=_("Freeze") + "\n(for receiving)", func=lambda btn: self.freeze_for_receiving()))
            else:
                options.append(ActionButtonOption(text=_("Unfreeze") + "\n(for receiving)", func=lambda btn: self.freeze_for_receiving()))
        action_dropdown.update(options=options)

    def close(self, close_options):
        choices = {}
        if ChanCloseOption.COOP_CLOSE in close_options:
            choices[0] = _('Cooperative close')
        if ChanCloseOption.REQUEST_REMOTE_FCLOSE in close_options:
            choices[1] = _('Request force-close')
        if ChanCloseOption.LOCAL_FCLOSE in close_options:
            choices[2] = _('Local force-close')
        dialog = ChoiceDialog(
            title=_('Close channel'),
            choices=choices,
            key = min(choices.keys()),
            callback=self._close,
            description=_(messages.MSG_REQUEST_FORCE_CLOSE),
            keep_choice_order=True)
        dialog.open()

    def _close(self, choice):
        loop = self.app.wallet.network.asyncio_loop
        if choice == 0:
            coro = self.app.wallet.lnworker.close_channel(self.chan.channel_id)
            msg = _('Channel closed')
        elif choice == 1:
            coro = self.app.wallet.lnworker.request_force_close(self.chan.channel_id)
            msg = _('Request sent')
        elif choice == 2:
            self.force_close()
            return
        f = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            f.result(5)
            self.app.show_info(msg)
        except Exception as e:
            self.logger.exception("Could not close channel")
            self.app.show_info(_('Could not close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def remove_channel(self):
        msg = _('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.')
        Question(msg, self._remove_channel).open()

    def _remove_channel(self, b):
        if not b:
            return
        self.app.wallet.lnworker.remove_channel(self.chan.channel_id)
        self.app._trigger_update_history()
        self.dismiss()

    def export_backup(self):
        text = self.app.wallet.lnworker.export_channel_backup(self.chan.channel_id)
        # TODO: some messages are duplicated between Kivy and Qt.
        help_text = ' '.join([
            _("Channel backups can be imported in another instance of the same wallet, by scanning this QR code."),
            _("Please note that channel backups cannot be used to restore your channels."),
            _("If you lose your wallet file, the only thing you can do with a backup is to request your channel to be closed, so that your funds will be sent on-chain."),
        ])
        self.app.qr_dialog(_("Channel Backup " + self.chan.short_id_for_GUI()), text, help_text=help_text)

    def force_close(self):
        if ChanCloseOption.LOCAL_FCLOSE not in self.chan.get_close_options():
            # note: likely channel is already closed, or could be unsafe to do local force-close (e.g. we are toxic)
            self.app.show_error(_('Channel already closed'))
            return
        to_self_delay = self.chan.config[REMOTE].to_self_delay
        help_text = ' '.join([
            _('If you force-close this channel, the funds you have in it will not be available for {} blocks.').format(to_self_delay),
            _('During that time, funds will not be recoverable from your seed, and may be lost if you lose your device.'),
            _('To prevent that, please save this channel backup.'),
            _('It may be imported in another wallet with the same seed.')
        ])
        title = _('Save backup and force-close')
        data = self.app.wallet.lnworker.export_channel_backup(self.chan.channel_id)
        popup = QRDialog(
            title, data,
            show_text=False,
            text_for_clipboard=data,
            help_text=help_text,
            close_button_text=_('Next'),
            on_close=self._confirm_force_close)
        popup.open()

    def _confirm_force_close(self):
        Question(
            _('Confirm force close?'),
            self._do_force_close,
            title=_('Force-close channel'),
            no_str=_('Cancel'),
            yes_str=_('Proceed')).open()

    def _do_force_close(self, b):
        if not b:
            return
        loop = self.app.wallet.network.asyncio_loop
        coro = asyncio.run_coroutine_threadsafe(self.app.wallet.lnworker.force_close_channel(self.chan.channel_id), loop)
        try:
            coro.result(1)
            self.app.show_info(_('Channel closed, you may need to wait at least {} blocks, because of CSV delays'.format(self.chan.config[REMOTE].to_self_delay)))
        except Exception as e:
            self.logger.exception("Could not force close channel")
            self.app.show_info(_('Could not force close channel: ') + repr(e)) # repr because str(Exception()) == ''

    def freeze_for_sending(self):
        lnworker = self.chan.lnworker
        if lnworker.channel_db or lnworker.is_trampoline_peer(self.chan.node_id):
            self.is_frozen_for_sending = not self.is_frozen_for_sending
            self.chan.set_frozen_for_sending(self.is_frozen_for_sending)
            self.update_action_dropdown()
        else:
            self.app.show_info(messages.MSG_NON_TRAMPOLINE_CHANNEL_FROZEN_WITHOUT_GOSSIP)

    def freeze_for_receiving(self):
        self.is_frozen_for_receiving = not self.is_frozen_for_receiving
        self.chan.set_frozen_for_receiving(self.is_frozen_for_receiving)
        self.update_action_dropdown()


class LightningChannelsDialog(Factory.Popup):

    def __init__(self, app: 'ElectrumWindow'):
        super(LightningChannelsDialog, self).__init__()
        self.clocks = []
        self.app = app
        self.has_network = bool(self.app.network)
        self.has_lightning = app.wallet.has_lightning()
        self.has_gossip = self.has_network and self.app.network.channel_db is not None
        self.update()

    def show_item(self, obj):
        chan = obj._chan
        if chan.is_backup():
            p = ChannelBackupPopup(chan, self.app)
        else:
            p = ChannelDetailsPopup(chan, self.app)
        p.open()

    def update_item(self, item):
        chan = item._chan
        item.status = chan.get_state_for_GUI()
        item.short_channel_id = chan.short_id_for_GUI()
        item.capacity = self.app.format_amount_and_units(chan.get_capacity())
        self.update_can_send()

    def update(self):
        channel_cards = self.ids.lightning_channels_container
        channel_cards.clear_widgets()
        if not self.app.wallet:
            return
        lnworker = self.app.wallet.lnworker
        channels = lnworker.get_channel_objects().values() if lnworker else []
        for i in channels:
            item = Factory.LightningChannelItem()
            item.screen = self
            item.active = not i.is_closed()
            item.is_backup = i.is_backup()
            item._chan = i
            item.node_alias = lnworker.get_node_alias(i.node_id) or i.node_id.hex()
            self.update_item(item)
            channel_cards.add_widget(item)
        self.update_can_send()

    def update_can_send(self):
        lnworker = self.app.wallet.lnworker
        if not lnworker:
            self.can_send = 'n/a'
            self.can_receive = 'n/a'
            return
        n = len([c for c in lnworker.channels.values() if c.is_open()])
        self.num_channels_text = _(f'You have {n} open channels.')
        self.can_send = self.app.format_amount_and_units(lnworker.num_sats_can_send())
        self.can_receive = self.app.format_amount_and_units(lnworker.num_sats_can_receive())


# Swaps should be done in due time which is why we recommend a certain fee.
RECOMMEND_BLOCKS_SWAP = 25


class SwapDialog(Factory.Popup):
    def __init__(self, app: 'ElectrumWindow', config: 'SimpleConfig'):
        super(SwapDialog, self).__init__()
        self.app = app
        self.config = config
        self.fmt_amt = self.app.format_amount_and_units
        self.lnworker = self.app.wallet.lnworker

        # swap related
        self.swap_manager = self.lnworker.swap_manager
        self.send_amount: Optional[int] = None
        self.receive_amount: Optional[int] = None
        self.tx = None  # only for forward swap
        self.is_reverse = None

        # init swaps and sliders
        asyncio.run(self.swap_manager.get_pairs())
        self.update_and_init()

    def update_and_init(self):
        self.update_fee_text()
        self.update_swap_slider()
        self.swap_slider_moved(0)

    def on_fee_button(self):
        fee_dialog = FeeDialog(self, self.config, self.after_fee_changed)
        fee_dialog.open()

    def after_fee_changed(self):
        self.update_fee_text()
        self.update_swap_slider()
        self.swap_slider_moved(self.ids.swap_slider.value)

    def update_fee_text(self):
        fee_per_kb = self.config.fee_per_kb()
        fee_per_b = format_fee_satoshis(fee_per_kb / 1000) if fee_per_kb is not None else "unknown"
        # eta is -1 when block inclusion cannot be estimated for low fees
        eta = self.config.fee_to_eta(fee_per_kb)

        suggest_fee = self.config.eta_target_to_fee(RECOMMEND_BLOCKS_SWAP)
        suggest_fee_per_b = format_fee_satoshis(suggest_fee / 1000) if suggest_fee is not None else "unknown"

        s = 's' if eta > 1 else ''
        if eta > RECOMMEND_BLOCKS_SWAP or eta == -1:
            msg = f'Warning: Your fee rate of {fee_per_b} sat/B may be too ' \
                  f'low for the swap to succeed before its timeout. ' \
                  f'The recommended fee rate is at least {suggest_fee_per_b} ' \
                  f'sat/B.'
        else:
            msg = f'Info: Your swap is estimated to be processed in {eta} ' \
                  f'block{s} with an onchain fee rate of {fee_per_b} sat/B.'

        self.fee_rate_text = f'{fee_per_b} sat/B'
        self.ids.fee_estimate.text = msg

    def update_tx(self, onchain_amount: Union[int, str]):
        """Updates the transaction associated with a forward swap."""
        if onchain_amount is None:
            self.tx = None
            self.ids.ok_button.disabled = True
            return
        outputs = [PartialTxOutput.from_address_and_value(ln_dummy_address(), onchain_amount)]
        coins = self.app.wallet.get_spendable_coins(None)
        try:
            self.tx = self.app.wallet.make_unsigned_transaction(
                coins=coins,
                outputs=outputs)
        except (NotEnoughFunds, NoDynamicFeeEstimates):
            self.tx = None
            self.ids.ok_button.disabled = True

    def update_swap_slider(self):
        """Sets the minimal and maximal amount that can be swapped for the swap
        slider."""
        # tx is updated again afterwards with send_amount in case of normal swap
        # this is just to estimate the maximal spendable onchain amount for HTLC
        self.update_tx('!')
        try:
            max_onchain_spend = self.tx.output_value_for_address(ln_dummy_address())
        except AttributeError:  # happens if there are no utxos
            max_onchain_spend = 0
        reverse = int(min(self.lnworker.num_sats_can_send(),
                          self.swap_manager.get_max_amount()))
        max_recv_amt_ln = int(self.swap_manager.num_sats_can_receive())
        max_recv_amt_oc = self.swap_manager.get_send_amount(max_recv_amt_ln, is_reverse=False) or float('inf')
        forward = int(min(max_recv_amt_oc,
                          # maximally supported swap amount by provider
                          self.swap_manager.get_max_amount(),
                          max_onchain_spend))
        # we expect range to adjust the value of the swap slider to be in the
        # correct range, i.e., to correct an overflow when reducing the limits
        self.ids.swap_slider.range = (-reverse, forward)

    def swap_slider_moved(self, position: float):
        position = int(position)
        # pay_amount and receive_amounts are always with fees already included
        # so they reflect the net balance change after the swap
        if position < 0:  # reverse swap
            self.ids.swap_action_label.text = "Adds Lightning receiving capacity."
            self.is_reverse = True

            pay_amount = abs(position)
            self.send_amount = pay_amount
            self.ids.send_amount_label.text = \
                f"{self.fmt_amt(pay_amount)} (offchain)" if pay_amount else ""

            receive_amount = self.swap_manager.get_recv_amount(
                send_amount=pay_amount, is_reverse=True)
            self.receive_amount = receive_amount
            self.ids.receive_amount_label.text = \
                f"{self.fmt_amt(receive_amount)} (onchain)" if receive_amount else ""

            # fee breakdown
            self.ids.server_fee_label.text = \
                f"{self.swap_manager.percentage:0.1f}% + {self.fmt_amt(self.swap_manager.lockup_fee)}"
            self.mining_fee_text = \
                f"{self.fmt_amt(self.swap_manager.get_claim_fee())}"

        else:  # forward (normal) swap
            self.ids.swap_action_label.text = f"Adds Lightning sending capacity."
            self.is_reverse = False
            self.send_amount = position

            self.update_tx(self.send_amount)
            # add lockup fees, but the swap amount is position
            pay_amount = position + self.tx.get_fee() if self.tx else 0
            self.ids.send_amount_label.text = \
                f"{self.fmt_amt(pay_amount)} (onchain)" if self.fmt_amt(pay_amount) else ""

            receive_amount = self.swap_manager.get_recv_amount(
                send_amount=position, is_reverse=False)
            self.receive_amount = receive_amount
            self.ids.receive_amount_label.text = \
                f"{self.fmt_amt(receive_amount)} (offchain)" if receive_amount else ""

            # fee breakdown
            self.ids.server_fee_label.text = \
                f"{self.swap_manager.percentage:0.1f}% + {self.fmt_amt(self.swap_manager.normal_fee)}"
            self.mining_fee_text = \
                f"{self.fmt_amt(self.tx.get_fee())}" if self.tx else ""

        if pay_amount and receive_amount:
            self.ids.ok_button.disabled = False
        else:
            # add more nuanced error reporting?
            self.ids.swap_action_label.text = "Swap below minimal swap size, change the slider."
            self.ids.ok_button.disabled = True

    def do_normal_swap(self, lightning_amount, onchain_amount, password):
        tx = self.tx
        assert tx
        if lightning_amount is None or onchain_amount is None:
            return
        loop = self.app.network.asyncio_loop
        coro = self.swap_manager.normal_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount,
            password=password,
            tx=tx,
        )
        asyncio.run_coroutine_threadsafe(coro, loop)

    def do_reverse_swap(self, lightning_amount, onchain_amount, password):
        if lightning_amount is None or onchain_amount is None:
            return
        loop = self.app.network.asyncio_loop
        coro = self.swap_manager.reverse_swap(
            lightning_amount_sat=lightning_amount,
            expected_onchain_amount_sat=onchain_amount + self.swap_manager.get_claim_fee(),
        )
        asyncio.run_coroutine_threadsafe(coro, loop)

    def on_ok(self):
        if not self.app.network:
            self.window.show_error(_("You are offline."))
            return
        if self.is_reverse:
            lightning_amount = self.send_amount
            onchain_amount = self.receive_amount
            self.app.protected(
                'Do you want to do a reverse submarine swap?',
                self.do_reverse_swap, (lightning_amount, onchain_amount))
        else:
            lightning_amount = self.receive_amount
            onchain_amount = self.send_amount
            self.app.protected(
                'Do you want to do a submarine swap? '
                'You will need to wait for the swap transaction to confirm.',
                self.do_normal_swap, (lightning_amount, onchain_amount))
