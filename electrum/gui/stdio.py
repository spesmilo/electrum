from decimal import Decimal
import getpass
import datetime
import logging
import os
from typing import Optional

from electrum.gui import BaseElectrumGui
from electrum import util
from electrum import WalletStorage, Wallet
from electrum.wallet import Abstract_Wallet
from electrum.wallet_db import WalletDB
from electrum.util import format_satoshis, EventListener, event_listener
from electrum.bitcoin import is_address, COIN
from electrum.transaction import PartialTxOutput
from electrum.network import TxBroadcastError, BestEffortRequestFailed
from electrum.fee_policy import FixedFeePolicy

from electrum.wizard import NewWalletWizard
from electrum import mnemonic

_ = lambda x:x  # i18n

# minimal fdisk like gui for console usage
# written by rofl0r, with some bits stolen from the text gui (ncurses)


class ElectrumGui(BaseElectrumGui, EventListener):

    def __init__(self, *, config, daemon, plugins):
        BaseElectrumGui.__init__(self, config=config, daemon=daemon, plugins=plugins)
        self.daemon = daemon
        self.network = daemon.network
        storage = WalletStorage(config.get_wallet_path())
        password = None
        if not storage.file_exists():
            print("Wallet not found. try 'electrum create'")
            exit()
        if storage.is_encrypted():
            password = getpass.getpass('Password:', stream=None)
            storage.decrypt(password)
        del storage
        self.wallet = self.daemon.load_wallet(config.get_wallet_path(), password)
        self.contacts = self.wallet.contacts

        self.done = 0
        self.last_balance = ""

        self.str_recipient = ""
        self.str_description = ""
        self.str_amount = ""
        self.str_fee = ""

        self.register_callbacks()
        self.commands = [_("[h] - displays this help text"), \
                         _("[i] - display transaction history"), \
                         _("[o] - enter payment order"), \
                         _("[p] - print stored payment order"), \
                         _("[s] - send stored payment order"), \
                         _("[r] - show own receipt addresses"), \
                         _("[c] - display contacts"), \
                         _("[b] - print server banner"), \
                         _("[q] - quit")]
        self.num_commands = len(self.commands)

    @event_listener
    def on_event_wallet_updated(self, wallet):
        self.updated()

    @event_listener
    def on_event_network_updated(self):
        self.updated()

    @event_listener
    def on_event_banner(self, *args):
        self.print_banner()

    def main_command(self):
        self.print_balance()
        c = input("enter command: ")
        if c == "h" : self.print_commands()
        elif c == "i" : self.print_history()
        elif c == "o" : self.enter_order()
        elif c == "p" : self.print_order()
        elif c == "s" : self.send_order()
        elif c == "r" : self.print_addresses()
        elif c == "c" : self.print_contacts()
        elif c == "b" : self.print_banner()
        elif c == "n" : self.network_dialog()
        elif c == "e" : self.settings_dialog()
        elif c == "w" : self.wallet_wizard()
        elif c == "q" : self.done = 1
        else: self.print_commands()

    def updated(self):
        s = self.get_balance()
        if s != self.last_balance:
            print(s)
        self.last_balance = s
        return True

    def print_commands(self):
        self.print_list(self.commands, "Available commands")

    def print_history(self):
        width = [20, 40, 14, 14]
        delta = (80 - sum(width) - 4)/3
        format_str = "%"+"%d"%width[0]+"s"+"%"+"%d"%(width[1]+delta)+"s"+"%" \
        + "%d"%(width[2]+delta)+"s"+"%"+"%d"%(width[3]+delta)+"s"
        messages = []
        domain = self.wallet.get_addresses()
        for hist_item in reversed(self.wallet.adb.get_history(domain)):
            if hist_item.tx_mined_status.conf:
                timestamp = hist_item.tx_mined_status.timestamp
                try:
                    time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = "unknown"
            else:
                time_str = 'unconfirmed'

            label = self.wallet.get_label_for_txid(hist_item.txid)
            messages.append(format_str % (
                time_str, label,
                format_satoshis(hist_item.delta, whitespaces=True),
                format_satoshis(hist_item.balance, whitespaces=True)))

        self.print_list(messages[::-1], format_str%(_("Date"), _("Description"), _("Amount"), _("Balance")))


    def print_balance(self):
        print(self.get_balance())

    def get_balance(self):
        network = self.wallet.network
        if network and network.is_connected():
            if not self.wallet.is_up_to_date():
                msg = _("Synchronizing...")
            else:
                c, u, x =  self.wallet.get_balance()
                msg = _("Balance")+": {}  ".format(Decimal(c) / COIN)
                if u:
                    msg += "  [{} unconfirmed]".format(Decimal(u) / COIN)
                if x:
                    msg += "  [{} unmatured]".format(Decimal(x) / COIN)
        else:
                msg = _("Not connected")

        return msg


    def print_contacts(self):
        messages = map(lambda x: "%20s   %45s "%(x[0], x[1][1]), self.contacts.items())
        self.print_list(messages, "%19s  %25s "%("Key", "Value"))

    def print_addresses(self):
        messages = map(lambda addr: "%30s    %30s       "%(addr, self.wallet.get_label_for_address(addr)), self.wallet.get_addresses())
        self.print_list(messages, "%19s  %25s "%("Address", "Label"))

    def print_order(self):
        print("send order to " + self.str_recipient + ", amount: " + self.str_amount \
              + "\nfee: " + self.str_fee + ", desc: " + self.str_description)

    def enter_order(self):
        self.str_recipient = input("Pay to: ")
        self.str_description = input("Description : ")
        self.str_amount = input("Amount: ")
        self.str_fee = input("Fee: ")

    def send_order(self):
        self.do_send()

    def print_banner(self):
        for i, x in enumerate(self.wallet.network.banner.split('\n')):
            print(x)

    def print_list(self, lst, firstline):
        lst = list(lst)
        self.maxpos = len(lst)
        if not self.maxpos: return
        print(firstline)
        for i in range(self.maxpos):
            msg = lst[i] if i < len(lst) else ""
            print(msg)


    def main(self):
        self.daemon.start_network()
        while self.done == 0:
            self.main_command()

    def do_send(self):
        if not is_address(self.str_recipient):
            print(_('Invalid Bitcoin address'))
            return
        try:
            amount = int(Decimal(self.str_amount) * COIN)
        except Exception:
            print(_('Invalid Amount'))
            return
        try:
            fee = int(Decimal(self.str_fee) * COIN)
        except Exception:
            print(_('Invalid Fee'))
            return

        if self.wallet.has_password():
            password = self.password_dialog()
            if not password:
                return
        else:
            password = None

        c = ""
        while c != "y":
            c = input("ok to send (y/n)?")
            if c == "n": return

        try:
            tx = self.wallet.make_unsigned_transaction(
                outputs=[PartialTxOutput.from_address_and_value(self.str_recipient, amount)],
                fee_policy=FixedFeePolicy(fee),
            )
            self.wallet.sign_transaction(tx, password)
        except Exception as e:
            print(repr(e))
            return

        if self.str_description:
            self.wallet.set_label(tx.txid(), self.str_description)

        print(_("Please wait..."))
        try:
            self.network.run_from_another_thread(self.network.broadcast_transaction(tx))
        except TxBroadcastError as e:
            msg = e.get_message_for_gui()
            print(msg)
        except BestEffortRequestFailed as e:
            msg = repr(e)
            print(msg)
        else:
            print(_('Payment sent.'))
            #self.do_clear()
            #self.update_contacts_tab()

    def network_dialog(self):
        print("use 'electrum setconfig server/proxy' to change your network settings")
        return True


    def settings_dialog(self):
        print("use 'electrum setconfig' to change your settings")
        return True

    def password_dialog(self):
        return getpass.getpass()


    def wallet_wizard(self):
        self._new_wallet = NewWalletWizard(self.daemon)
        self._new_wallet.navmap_merge({
            'wallet_name': { 'gui': 'wizard_wallet_name' },
            'wallet_type': { 'gui': 'wizard_wallet_type' },
            'keystore_type': { 'gui': 'wizard_keystore_type' },
            'create_seed': { 'gui': 'wizard_create_seed',
                'next': self._new_wallet.on_have_or_confirm_seed,
            },
            'wallet_password': { 'gui': 'wizard_password' },
        })
        self.wallet_folder = os.path.dirname(self.daemon.config.get_wallet_path())
        print('Start wallet wizard')
        current = self._new_wallet.start()
        self._wdata = current.wizard_data
        self.call_view(current.view)

    def wizard_submit(self):
        self._new_wallet.log_state(self._wdata)
        if self._new_wallet.is_last_view(self._new_wallet._current.view,  self._wdata):
            self._new_wallet.create_storage(os.path.join(self.wallet_folder, self._wdata['wallet_name']), self._wdata)
            return
        view = self._new_wallet.resolve_next(self._new_wallet._current.view, self._wdata)
        self._wdata = view.wizard_data
        print(f'next view: {view.view}')
        self.call_view(view.view)

    def wizard_wallet_name(self):
        self._wdata['wallet_name'] = input('Wallet Name: ')
        self.wizard_submit()

    def wizard_wallet_type(self):
        print('enter one of standard|2fa|multisig|imported')
        self._wdata['wallet_type'] = input('Wallet Type: ')
        self._wdata['seed_type'] = 'segwit'
        self._wdata['seed_extend'] = False
        self._wdata['seed_extra_words'] = ''
        self.wizard_submit()

    def wizard_keystore_type(self):
        print('[1] create seed')
        print('[2] have seed')
        self._wdata['keystore_type'] = {'1': 'createseed', '2': 'haveseed' }[input('Keystore Type: ')]
        self.wizard_submit()

    def wizard_create_seed(self):
        m = mnemonic.Mnemonic('en').make_seed(seed_type='segwit')
        print(f'Seed: {m}')
        self._wdata['seed'] = m
        self._wdata['seed_variant'] = 'electrum'
        self.wizard_submit()

    def wizard_password(self):
        self._wdata['password'] = input('Enter password: ')
        self._wdata['encrypt'] = self._wdata['password'] != ''
        self.wizard_submit()

    def call_view(self, view):
        getattr(self, self._new_wallet.navmap[view]['gui'])()


#   XXX unused

    def run_receive_tab(self, c):
        #if c == 10:
        #    out = self.run_popup('Address', ["Edit label", "Freeze", "Prioritize"])
        return

    def run_contacts_tab(self, c):
        pass
