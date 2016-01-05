#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


import datetime
import thread, time, ast, sys, re
import socket, traceback
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GObject, cairo
from decimal import Decimal
from electrum.util import print_error, InvalidPassword
from electrum.bitcoin import is_valid, COIN
from electrum.wallet import NotEnoughFunds
from electrum import WalletStorage, Wallet

Gdk.threads_init()
APP_NAME = "Electrum"
import platform
MONOSPACE_FONT = 'Lucida Console' if platform.system() == 'Windows' else 'monospace'

from electrum.util import format_satoshis, parse_URI
from electrum.bitcoin import MIN_RELAY_TX_FEE

def numbify(entry, is_int = False):
    text = entry.get_text().strip()
    chars = '0123456789'
    if not is_int: chars +='.'
    s = ''.join([i for i in text if i in chars])
    if not is_int:
        if '.' in s:
            p = s.find('.')
            s = s.replace('.','')
            s = s[:p] + '.' + s[p:p+8]
        try:
            amount = int(Decimal(s) * COIN)
        except Exception:
            amount = None
    else:
        try:
            amount = int( s )
        except Exception:
            amount = None
    entry.set_text(s)
    return amount




def show_seed_dialog(seed, parent):
    if not seed:
        show_message("No seed")
        return

    dialog = Gtk.MessageDialog(
        parent = parent,
        flags = Gtk.DialogFlags.MODAL,
        buttons = Gtk.ButtonsType.OK,
        message_format = "Your wallet generation seed is:\n\n" + '"' + seed + '"'\
            + "\n\nPlease keep it in a safe place; if you lose it, you will not be able to restore your wallet.\n\n" )
    dialog.set_title("Seed")
    dialog.show()
    dialog.run()
    dialog.destroy()

def restore_create_dialog():

    # ask if the user wants to create a new wallet, or recover from a seed.
    # if he wants to recover, and nothing is found, do not create wallet
    dialog = Gtk.Dialog("electrum", parent=None,
                        flags=Gtk.DialogFlags.MODAL,
                        buttons= ("create", 0, "restore",1, "cancel",2)  )

    label = Gtk.Label("Wallet file not found.\nDo you want to create a new wallet,\n or to restore an existing one?"  )
    label.show()
    dialog.vbox.pack_start(label, True, True, 0)
    dialog.show()
    r = dialog.run()
    dialog.destroy()

    if r==2: return False
    return 'restore' if r==1 else 'create'



def run_recovery_dialog():
    message = "Please enter your wallet seed or the corresponding mnemonic list of words, and the gap limit of your wallet."
    dialog = Gtk.MessageDialog(
        parent = None,
        flags = Gtk.DialogFlags.MODAL,
        buttons = Gtk.ButtonsType.OK_CANCEL,
        message_format = message)

    vbox = dialog.vbox
    dialog.set_default_response(Gtk.ResponseType.OK)

    # ask seed, server and gap in the same dialog
    seed_box = Gtk.HBox()
    seed_label = Gtk.Label(label='Seed or mnemonic:')
    seed_label.set_size_request(150,-1)
    seed_box.pack_start(seed_label, False, False, 10)
    seed_label.show()
    seed_entry = Gtk.Entry()
    seed_entry.show()
    seed_entry.set_size_request(450,-1)
    seed_box.pack_start(seed_entry, False, False, 10)
    add_help_button(seed_box, '.')
    seed_box.show()
    vbox.pack_start(seed_box, False, False, 5)

    dialog.show()
    r = dialog.run()
    seed = seed_entry.get_text()
    dialog.destroy()

    if r==Gtk.ResponseType.CANCEL:
        return False

    if Wallet.is_seed(seed):
        return seed

    show_message("no seed")
    return False



def run_settings_dialog(self):

    message = "Here are the settings of your wallet. For more explanations, click on the question mark buttons next to each input field."

    dialog = Gtk.MessageDialog(
        parent = self.window,
        flags = Gtk.DialogFlags.MODAL,
        buttons = Gtk.ButtonsType.OK_CANCEL,
        message_format = message)

    image = Gtk.Image()
    image.set_from_stock(Gtk.STOCK_PREFERENCES, Gtk.IconSize.DIALOG)
    image.show()
    dialog.set_image(image)
    dialog.set_title("Settings")

    vbox = dialog.vbox
    dialog.set_default_response(Gtk.ResponseType.OK)

    fee = Gtk.HBox()
    fee_entry = Gtk.Entry()
    fee_label = Gtk.Label(label='Transaction fee:')
    fee_label.set_size_request(150,10)
    fee_label.show()
    fee.pack_start(fee_label,False, False, 10)
    fee_entry.set_text(str(Decimal(self.wallet.fee_per_kb) / COIN))
    fee_entry.connect('changed', numbify, False)
    fee_entry.show()
    fee.pack_start(fee_entry,False,False, 10)
    add_help_button(fee, 'Fee per kilobyte of transaction. Recommended value:0.0001')
    fee.show()
    vbox.pack_start(fee, False,False, 5)

    nz = Gtk.HBox()
    nz_entry = Gtk.Entry()
    nz_label = Gtk.Label(label='Display zeros:')
    nz_label.set_size_request(150,10)
    nz_label.show()
    nz.pack_start(nz_label,False, False, 10)
    nz_entry.set_text( str( self.num_zeros ))
    nz_entry.connect('changed', numbify, True)
    nz_entry.show()
    nz.pack_start(nz_entry,False,False, 10)
    add_help_button(nz, "Number of zeros displayed after the decimal point.\nFor example, if this number is 2, then '5.' is displayed as '5.00'")
    nz.show()
    vbox.pack_start(nz, False,False, 5)

    dialog.show()
    r = dialog.run()
    fee = fee_entry.get_text()
    nz = nz_entry.get_text()

    dialog.destroy()
    if r==Gtk.ResponseType.CANCEL:
        return

    try:
        fee = int(COIN * Decimal(fee))
    except Exception:
        show_message("error")
        return
    self.config.set_key('fee_per_kb', fee)

    try:
        nz = int( nz )
        if nz>8: nz = 8
    except Exception:
        show_message("error")
        return

    if self.num_zeros != nz:
        self.num_zeros = nz
        self.config.set_key('num_zeros',nz,True)
        self.update_history_tab()




def run_network_dialog( network, parent ):
    image = Gtk.Image()
    image.set_from_stock(Gtk.STOCK_NETWORK, Gtk.IconSize.DIALOG)
    host, port, protocol, proxy_config, auto_connect = network.get_parameters()
    server = "%s:%s:%s"%(host, port, protocol)
    if parent:
        if network.is_connected():
            status = "Connected to %s\n%d blocks"%(host, network.get_local_height())
        else:
            status = "Not connected"
    else:
        import random
        status = "Please choose a server.\nSelect cancel if you are offline."

    servers = network.get_servers()

    dialog = Gtk.MessageDialog( parent, Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
                                    Gtk.MessageType.QUESTION, Gtk.ButtonsType.OK_CANCEL, status)
    dialog.set_title("Server")
    dialog.set_image(image)
    image.show()

    vbox = dialog.vbox
    host_box = Gtk.HBox()
    host_label = Gtk.Label(label='Connect to:')
    host_label.set_size_request(100,-1)
    host_label.show()
    host_box.pack_start(host_label, False, False, 10)
    host_entry = Gtk.Entry()
    host_entry.set_size_request(200,-1)
    if network.is_connected():
        host_entry.set_text(server)
    else:
        host_entry.set_text("Not Connected")
    host_entry.show()
    host_box.pack_start(host_entry, False, False, 10)
    add_help_button(host_box, 'The name, port number and protocol of your Electrum server, separated by a colon. Example: "ecdsa.org:50002:s". Some servers allow you to connect through http (port 80) or https (port 443)')
    host_box.show()

    p_box = Gtk.HBox(False, 10)
    p_box.show()

    p_label = Gtk.Label(label='Protocol:')
    p_label.set_size_request(100,-1)
    p_label.show()
    p_box.pack_start(p_label, False, False, 10)

    combobox = Gtk.ComboBoxText()
    combobox.show()
    combobox.append_text("TCP")
    combobox.append_text("SSL")
    combobox.append_text("HTTP")
    combobox.append_text("HTTPS")

    p_box.pack_start(combobox, True, True, 0)

    def current_line():
        return unicode(host_entry.get_text()).split(':')

    def set_combobox(protocol):
        combobox.set_active('tshg'.index(protocol))

    def set_protocol(protocol):
        host = current_line()[0]
        pp = servers[host]
        if protocol not in pp.keys():
            protocol = pp.keys()[0]
            set_combobox(protocol)
        port = pp[protocol]
        host_entry.set_text( host + ':' + port + ':' + protocol)

    combobox.connect("changed", lambda x:set_protocol('tshg'[combobox.get_active()]))
    if network.is_connected():
        set_combobox(protocol)

    server_list = Gtk.ListStore(str)
    for host in servers.keys():
        server_list.append([host])

    treeview = Gtk.TreeView(model=server_list)
    treeview.show()

    label = 'Active Servers' if network.is_connected() else 'Default Servers'
    tvcolumn = Gtk.TreeViewColumn(label)
    treeview.append_column(tvcolumn)
    cell = Gtk.CellRendererText()
    tvcolumn.pack_start(cell, False)
    tvcolumn.add_attribute(cell, 'text', 0)

    vbox.pack_start(host_box, False,False, 5)
    vbox.pack_start(p_box, True, True, 0)

    #scroll = Gtk.ScrolledWindow()
    #scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.ALWAYS)
    #scroll.add_with_viewport(treeview)
    #scroll.show()
    #vbox.pack_start(scroll, True)
    vbox.pack_start(treeview, True, True, 0)

    def my_treeview_cb(treeview):
        path, view_column = treeview.get_cursor()
        host = server_list.get_value( server_list.get_iter(path), 0)

        pp = servers[host]
        if 't' in pp.keys():
            protocol = 't'
        else:
            protocol = pp.keys()[0]
        port = pp[protocol]
        host_entry.set_text( host + ':' + port + ':' + protocol)
        set_combobox(protocol)

    treeview.connect('cursor-changed', my_treeview_cb)

    dialog.show_all()
    r = dialog.run()
    server = host_entry.get_text()
    dialog.destroy()

    if r==Gtk.ResponseType.CANCEL:
        return False

    try:
        host, port, protocol = server.split(':')
    except Exception:
        show_message("error:" + server)
        return False

    network.set_parameters(host, port, protocol, proxy_config, auto_connect)





def show_message(message, parent=None):
    dialog = Gtk.MessageDialog(
        parent = parent,
        flags = Gtk.DialogFlags.MODAL,
        buttons = Gtk.ButtonsType.CLOSE,
        message_format = message )
    dialog.show()
    dialog.run()
    dialog.destroy()

def password_line(label):
    password = Gtk.HBox()
    password_label = Gtk.Label(label=label)
    password_label.set_size_request(120,10)
    password_label.show()
    password.pack_start(password_label,False, False, 10)
    password_entry = Gtk.Entry()
    password_entry.set_size_request(300,-1)
    password_entry.set_visibility(False)
    password_entry.show()
    password.pack_start(password_entry,False,False, 10)
    password.show()
    return password, password_entry

def password_dialog(parent):
    dialog = Gtk.MessageDialog( parent, Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
                                Gtk.MessageType.QUESTION, Gtk.ButtonsType.OK_CANCEL,  "Please enter your password.")
    dialog.get_image().set_visible(False)
    current_pw, current_pw_entry = password_line('Password:')
    current_pw_entry.connect("activate", lambda entry, dialog, response: dialog.response(response), dialog, Gtk.ResponseType.OK)
    dialog.vbox.pack_start(current_pw, False, True, 0)
    dialog.show()
    result = dialog.run()
    pw = current_pw_entry.get_text()
    dialog.destroy()
    if result != Gtk.ResponseType.CANCEL: return pw


def change_password_dialog(is_encrypted, parent):

    if parent:
        msg = 'Your wallet is encrypted. Use this dialog to change the password. To disable wallet encryption, enter an empty new password.' if is_encrypted else 'Your wallet keys are not encrypted'
    else:
        msg = "Please choose a password to encrypt your wallet keys"

    dialog = Gtk.MessageDialog( parent, Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT, Gtk.MessageType.QUESTION, Gtk.ButtonsType.OK_CANCEL, msg)
    dialog.set_title("Change password")
    image = Gtk.Image()
    image.set_from_stock(Gtk.STOCK_DIALOG_AUTHENTICATION, Gtk.IconSize.DIALOG)
    image.show()
    dialog.set_image(image)

    if is_encrypted:
        current_pw, current_pw_entry = password_line('Current password:')
        dialog.vbox.pack_start(current_pw, False, True, 0)

    password, password_entry = password_line('New password:')
    dialog.vbox.pack_start(password, False, True, 5)
    password2, password2_entry = password_line('Confirm password:')
    dialog.vbox.pack_start(password2, False, True, 5)

    dialog.show()
    result = dialog.run()
    password = current_pw_entry.get_text() if is_encrypted else None
    new_password = password_entry.get_text()
    new_password2 = password2_entry.get_text()
    dialog.destroy()
    if result == Gtk.ResponseType.CANCEL:
        return

    if new_password != new_password2:
        show_message("passwords do not match")
        return change_password_dialog(is_encrypted, parent)

    if not new_password:
        new_password = None

    return True, password, new_password



def add_help_button(hbox, message):
    button = Gtk.Button('?')
    button.connect("clicked", lambda x: show_message(message))
    button.show()
    hbox.pack_start(button,False, False, 0)


class ElectrumWindow:

    def show_message(self, msg):
        show_message(msg, self.window)

    def on_key(self, w, event):
        if Gdk.ModifierType.CONTROL_MASK & event.state and event.keyval in [113,119]:
            Gtk.main_quit()
        return True

    def __init__(self, wallet, config, network):
        self.config = config
        self.wallet = wallet
        self.network = network
        self.funds_error = False # True if not enough funds
        self.num_zeros = int(self.config.get('num_zeros',0))
        self.window = Gtk.Window(Gtk.WindowType.TOPLEVEL)
        self.window.connect('key-press-event', self.on_key)
        title = 'Electrum ' + self.wallet.electrum_version + '  -  ' + self.config.path
        if not self.wallet.seed: title += ' [seedless]'
        self.window.set_title(title)
        self.window.connect("destroy", Gtk.main_quit)
        self.window.set_border_width(0)
        #self.window.connect('mykeypress', Gtk.main_quit)
        self.window.set_default_size(720, 350)
        self.wallet_updated = False

        from electrum.util import StoreDict
        self.contacts = StoreDict(self.config, 'contacts')

        vbox = Gtk.VBox()

        self.notebook = Gtk.Notebook()
        self.create_history_tab()
        if self.wallet.seed:
            self.create_send_tab()
        self.create_recv_tab()
        self.create_book_tab()
        self.create_about_tab()
        self.notebook.show()
        vbox.pack_start(self.notebook, True, True, 2)

        self.status_bar = Gtk.Statusbar()
        vbox.pack_start(self.status_bar, False, False, 0)

        self.status_image = Gtk.Image()
        self.status_image.set_from_stock(Gtk.STOCK_NO, Gtk.IconSize.MENU)
        self.status_image.set_alignment(True, 0.5  )
        self.status_image.show()

        self.network_button = Gtk.Button()
        self.network_button.connect("clicked", lambda x: run_network_dialog(self.network, self.window) )
        self.network_button.add(self.status_image)
        self.network_button.set_relief(Gtk.ReliefStyle.NONE)
        self.network_button.show()
        self.status_bar.pack_end(self.network_button, False, False, 0)

        if self.wallet.seed:
            def seedb(w, wallet):
                if wallet.use_encryption:
                    password = password_dialog(self.window)
                    if not password: return
                else: password = None
                seed = wallet.get_mnemonic(password)
                show_seed_dialog(seed, self.window)
            button = Gtk.Button('S')
            button.connect("clicked", seedb, self.wallet )
            button.set_relief(Gtk.ReliefStyle.NONE)
            button.show()
            self.status_bar.pack_end(button,False, False, 0)

        settings_icon = Gtk.Image()
        settings_icon.set_from_stock(Gtk.STOCK_PREFERENCES, Gtk.IconSize.MENU)
        settings_icon.set_alignment(0.5, 0.5)
        settings_icon.set_size_request(16,16 )
        settings_icon.show()

        prefs_button = Gtk.Button()
        prefs_button.connect("clicked", lambda x: run_settings_dialog(self) )
        prefs_button.add(settings_icon)
        prefs_button.set_tooltip_text("Settings")
        prefs_button.set_relief(Gtk.ReliefStyle.NONE)
        prefs_button.show()
        self.status_bar.pack_end(prefs_button,False,False, 0)

        self.pw_icon = Gtk.Image()
        self.pw_icon.set_from_stock(Gtk.STOCK_DIALOG_AUTHENTICATION, Gtk.IconSize.MENU)
        self.pw_icon.set_alignment(0.5, 0.5)
        self.pw_icon.set_size_request(16,16 )
        self.pw_icon.show()

        if self.wallet.seed:

            if self.wallet.use_encryption:
                self.pw_icon.set_tooltip_text('Wallet is encrypted')
            else:
                self.pw_icon.set_tooltip_text('Wallet is unencrypted')

            password_button = Gtk.Button()
            password_button.connect("clicked", self.do_update_password, self.wallet)
            password_button.add(self.pw_icon)
            password_button.set_relief(Gtk.ReliefStyle.NONE)
            password_button.show()
            self.status_bar.pack_end(password_button,False,False, 0)

        self.window.add(vbox)
        self.window.show_all()
        #self.fee_box.hide()

        self.context_id = self.status_bar.get_context_id("statusbar")
        self.update_status_bar()

        self.network.register_callback(self.update_callback, ['updated'])


        def update_status_bar_thread():
            while True:
                GObject.idle_add( self.update_status_bar )
                time.sleep(0.5)


        def check_recipient_thread():
            old_r = ''
            while True:
                time.sleep(0.5)
                if self.payto_entry.is_focus():
                    continue
                r = self.payto_entry.get_text()
                if r != old_r:
                    old_r = r
                    r = r.strip()
                    if re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', r):
                        try:
                            to_address = self.wallet.get_alias(r, interactive=False)
                        except Exception:
                            continue
                        if to_address:
                            s = r + ' <' + to_address + '>'
                            GObject.idle_add( lambda: self.payto_entry.set_text(s) )


        thread.start_new_thread(update_status_bar_thread, ())
        if self.wallet.seed:
            thread.start_new_thread(check_recipient_thread, ())
        self.notebook.set_current_page(0)

    def update_callback(self, event):
        self.wallet_updated = True

    def do_update_password(self, button, wallet):
        if not wallet.seed:
            show_message("No seed")
            return

        res = change_password_dialog(wallet.use_encryption, self.window)
        if res:
            _, password, new_password = res

            try:
                wallet.get_seed(password)
            except InvalidPassword:
                show_message("Incorrect password")
                return

            wallet.update_password(password, new_password)

            if wallet.use_encryption:
                self.pw_icon.set_tooltip_text('Wallet is encrypted')
            else:
                self.pw_icon.set_tooltip_text('Wallet is unencrypted')


    def add_tab(self, page, name):
        tab_label = Gtk.Label(label=name)
        tab_label.show()
        self.notebook.append_page(page, tab_label)


    def create_send_tab(self):

        page = vbox = Gtk.VBox()
        page.show()

        payto = Gtk.HBox()
        payto_label = Gtk.Label(label='Pay to:')
        payto_label.set_size_request(100,-1)
        payto.pack_start(payto_label, False, False, 0)
        payto_entry = Gtk.Entry()
        payto_entry.set_size_request(450, 26)
        payto.pack_start(payto_entry, False, False, 0)
        vbox.pack_start(payto, False, False, 5)

        message = Gtk.HBox()
        message_label = Gtk.Label(label='Description:')
        message_label.set_size_request(100,-1)
        message.pack_start(message_label, False, False, 0)
        message_entry = Gtk.Entry()
        message_entry.set_size_request(450, 26)
        message.pack_start(message_entry, False, False, 0)
        vbox.pack_start(message, False, False, 5)

        amount_box = Gtk.HBox()
        amount_label = Gtk.Label(label='Amount:')
        amount_label.set_size_request(100,-1)
        amount_box.pack_start(amount_label, False, False, 0)
        amount_entry = Gtk.Entry()
        amount_entry.set_size_request(120, -1)
        amount_box.pack_start(amount_entry, False, False, 0)
        vbox.pack_start(amount_box, False, False, 5)

        self.fee_box = fee_box = Gtk.HBox()
        fee_label = Gtk.Label(label='Fee:')
        fee_label.set_size_request(100,-1)
        fee_box.pack_start(fee_label, False, False, 0)
        fee_entry = Gtk.Entry()
        fee_entry.set_size_request(60, 26)
        fee_box.pack_start(fee_entry, False, False, 0)
        vbox.pack_start(fee_box, False, False, 5)

        end_box = Gtk.HBox()
        empty_label = Gtk.Label(label='')
        empty_label.set_size_request(100,-1)
        end_box.pack_start(empty_label, False, False, 0)
        send_button = Gtk.Button("Send")
        send_button.show()
        end_box.pack_start(send_button, False, False, 0)
        clear_button = Gtk.Button("Clear")
        clear_button.show()
        end_box.pack_start(clear_button, False, False, 15)
        send_button.connect("clicked", self.do_send, (payto_entry, message_entry, amount_entry, fee_entry))
        clear_button.connect("clicked", self.do_clear, (payto_entry, message_entry, amount_entry, fee_entry))

        vbox.pack_start(end_box, False, False, 5)

        # display this line only if there is a signature
        payto_sig = Gtk.HBox()
        payto_sig_id = Gtk.Label(label='')
        payto_sig.pack_start(payto_sig_id, False, False, 0)
        vbox.pack_start(payto_sig, True, True, 5)


        self.user_fee = False

        def entry_changed( entry, is_fee ):
            amount = numbify(amount_entry)
            fee = numbify(fee_entry)
            if not is_fee: fee = None
            if amount is None:
                return
            coins = self.wallet.get_spendable_coins()
            try:
                tx = self.wallet.make_unsigned_transaction(coins, [('op_return', 'dummy_tx', amount)], self.config, fee)
                self.funds_error = False
            except NotEnoughFunds:
                self.funds_error = True

            if not self.funds_error:
                if not is_fee:
                    fee = tx.get_fee()
                    fee_entry.set_text(str(Decimal(fee) / COIN))
                    self.fee_box.show()
                amount_entry.modify_text(Gtk.StateType.NORMAL, Gdk.color_parse("#000000"))
                fee_entry.modify_text(Gtk.StateType.NORMAL, Gdk.color_parse("#000000"))
                send_button.set_sensitive(True)
            else:
                send_button.set_sensitive(False)
                amount_entry.modify_text(Gtk.StateType.NORMAL, Gdk.color_parse("#cc0000"))
                fee_entry.modify_text(Gtk.StateType.NORMAL, Gdk.color_parse("#cc0000"))

        amount_entry.connect('changed', entry_changed, False)
        fee_entry.connect('changed', entry_changed, True)

        self.payto_entry = payto_entry
        self.payto_fee_entry = fee_entry
        self.payto_sig_id = payto_sig_id
        self.payto_sig = payto_sig
        self.amount_entry = amount_entry
        self.message_entry = message_entry
        self.add_tab(page, 'Send')

    def set_frozen(self,entry,frozen):
        if frozen:
            entry.set_editable(False)
            entry.set_has_frame(False)
            entry.modify_base(Gtk.StateType.NORMAL, Gdk.color_parse("#eeeeee"))
        else:
            entry.set_editable(True)
            entry.set_has_frame(True)
            entry.modify_base(Gtk.StateType.NORMAL, Gdk.color_parse("#ffffff"))

    def set_url(self, url):
        out = parse_URI(url)
        address = out.get('address')
        message = out.get('message')
        amount = out.get('amount')
        self.notebook.set_current_page(1)
        self.payto_entry.set_text(address)
        self.message_entry.set_text(message)
        self.amount_entry.set_text(amount)
        self.payto_sig.set_visible(False)

    def create_about_tab(self):
        from gi.repository import Pango
        page = Gtk.VBox()
        page.show()
        tv = Gtk.TextView()
        tv.set_editable(False)
        tv.set_cursor_visible(False)
        tv.modify_font(Pango.FontDescription(MONOSPACE_FONT))
        scroll = Gtk.ScrolledWindow()
        scroll.add(tv)
        page.pack_start(scroll, True, True, 0)
        self.info = tv.get_buffer()
        self.add_tab(page, 'Wall')

    def do_clear(self, w, data):
        self.payto_sig.set_visible(False)
        self.payto_fee_entry.set_text('')
        for entry in [self.payto_entry,self.amount_entry,self.message_entry]:
            self.set_frozen(entry,False)
            entry.set_text('')

    def question(self,msg):
        dialog = Gtk.MessageDialog( self.window, Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT, Gtk.MessageType.QUESTION, Gtk.ButtonsType.OK_CANCEL, msg)
        dialog.show()
        result = dialog.run()
        dialog.destroy()
        return result == Gtk.ResponseType.OK

    def do_send(self, w, data):
        payto_entry, label_entry, amount_entry, fee_entry = data
        label = label_entry.get_text()
        r = payto_entry.get_text()
        r = r.strip()

        m1 = re.match('^(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+)$', r)
        m2 = re.match('(|([\w\-\.]+)@)((\w[\w\-]+\.)+[\w\-]+) \<([1-9A-HJ-NP-Za-km-z]{26,})\>', r)

        if m1:
            to_address = self.wallet.get_alias(r, True, self.show_message, self.question)
            if not to_address:
                return
            else:
                self.update_sending_tab()

        elif m2:
            to_address = m2.group(5)
        else:
            to_address = r

        if not is_valid(to_address):
            self.show_message( "invalid bitcoin address:\n"+to_address)
            return

        try:
            amount = int(Decimal(amount_entry.get_text()) * COIN)
        except Exception:
            self.show_message( "invalid amount")
            return
        try:
            fee = int(Decimal(fee_entry.get_text()) * COIN)
        except Exception:
            self.show_message( "invalid fee")
            return

        if self.wallet.use_encryption:
            password = password_dialog(self.window)
            if not password:
                return
        else:
            password = None

        try:
            tx = self.wallet.mktx( [(to_address, amount)], password, self.config, fee)
        except Exception as e:
            self.show_message(str(e))
            return

        if tx.requires_fee(self.wallet) and fee < MIN_RELAY_TX_FEE:
            self.show_message( "This transaction requires a higher fee, or it will not be propagated by the network." )
            return


        if label:
            self.wallet.labels[tx.hash()] = label

        status, msg = self.wallet.sendtx( tx )
        if status:
            self.show_message( "payment sent.\n" + msg )
            payto_entry.set_text("")
            label_entry.set_text("")
            amount_entry.set_text("")
            fee_entry.set_text("")
            #self.fee_box.hide()
            self.update_sending_tab()
        else:
            self.show_message( msg )


    def treeview_button_press(self, treeview, event):
        if event.type == Gdk.EventType.DOUBLE_BUTTON_PRESS:
            c = treeview.get_cursor()[0]
            if treeview == self.history_treeview:
                tx_details = self.history_list.get_value( self.history_list.get_iter(c), 8)
                self.show_message(tx_details)
            elif treeview == self.contacts_treeview:
                m = self.addressbook_list.get_value( self.addressbook_list.get_iter(c), 0)
                #a = self.wallet.aliases.get(m)
                #if a:
                #    if a[0] in self.wallet.authorities.keys():
                #        s = self.wallet.authorities.get(a[0])
                #    else:
                #        s = "self-signed"
                #    msg = 'Alias: '+ m + '\nTarget address: '+ a[1] + '\n\nSigned by: ' + s + '\nSigning address:' + a[0]
                #    self.show_message(msg)


    def treeview_key_press(self, treeview, event):
        c = treeview.get_cursor()[0]
        if event.keyval == Gdk.KEY_Up:
            if c and c[0] == 0:
                treeview.parent.grab_focus()
                treeview.set_cursor((0,))
        elif event.keyval == Gdk.KEY_Return:
            if treeview == self.history_treeview:
                tx_details = self.history_list.get_value( self.history_list.get_iter(c), 8)
                self.show_message(tx_details)
            elif treeview == self.contacts_treeview:
                m = self.addressbook_list.get_value( self.addressbook_list.get_iter(c), 0)
                #a = self.wallet.aliases.get(m)
                #if a:
                #    if a[0] in self.wallet.authorities.keys():
                #        s = self.wallet.authorities.get(a[0])
                #    else:
                #        s = "self"
                #    msg = 'Alias:'+ m + '\n\nTarget: '+ a[1] + '\nSigned by: ' + s + '\nSigning address:' + a[0]
                #    self.show_message(msg)

        return False

    def create_history_tab(self):

        self.history_list = Gtk.ListStore(str, str, str, str, 'gboolean',  str, str, str, str)
        treeview = Gtk.TreeView(model=self.history_list)
        self.history_treeview = treeview
        treeview.set_tooltip_column(7)
        treeview.show()
        treeview.connect('key-press-event', self.treeview_key_press)
        treeview.connect('button-press-event', self.treeview_button_press)

        tvcolumn = Gtk.TreeViewColumn('')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererPixbuf()
        tvcolumn.pack_start(cell, False)
        tvcolumn.set_attributes(cell, stock_id=1)

        tvcolumn = Gtk.TreeViewColumn('Date')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 2)

        tvcolumn = Gtk.TreeViewColumn('Description')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        cell.set_property('foreground', 'grey')
        cell.set_property('family', MONOSPACE_FONT)
        cell.set_property('editable', True)
        def edited_cb(cell, path, new_text, h_list):
            tx = h_list.get_value( h_list.get_iter(path), 0)
            self.wallet.set_label(tx,new_text)
            self.update_history_tab()
        cell.connect('edited', edited_cb, self.history_list)
        def editing_started(cell, entry, path, h_list):
            tx = h_list.get_value( h_list.get_iter(path), 0)
            if not self.wallet.labels.get(tx): entry.set_text('')
        cell.connect('editing-started', editing_started, self.history_list)
        tvcolumn.set_expand(True)
        tvcolumn.pack_start(cell, True)
        tvcolumn.set_attributes(cell, text=3, foreground_set = 4)

        tvcolumn = Gtk.TreeViewColumn('Amount')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        cell.set_alignment(1, 0.5)
        cell.set_property('family', MONOSPACE_FONT)
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 5)

        tvcolumn = Gtk.TreeViewColumn('Balance')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        cell.set_alignment(1, 0.5)
        cell.set_property('family', MONOSPACE_FONT)
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 6)

        tvcolumn = Gtk.TreeViewColumn('Tooltip')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 7)
        tvcolumn.set_visible(False)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(treeview)

        self.add_tab(scroll, 'History')
        self.update_history_tab()


    def create_recv_tab(self):
        self.recv_list = Gtk.ListStore(str, str, str, str, str)
        self.add_tab( self.make_address_list(True), 'Receive')
        self.update_receiving_tab()

    def create_book_tab(self):
        self.addressbook_list = Gtk.ListStore(str, str, str)
        self.add_tab( self.make_address_list(False), 'Contacts')
        self.update_sending_tab()

    def make_address_list(self, is_recv):
        liststore = self.recv_list if is_recv else self.addressbook_list
        treeview = Gtk.TreeView(model= liststore)
        treeview.connect('key-press-event', self.treeview_key_press)
        treeview.connect('button-press-event', self.treeview_button_press)
        treeview.show()
        if not is_recv:
            self.contacts_treeview = treeview

        tvcolumn = Gtk.TreeViewColumn('Address')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        cell.set_property('family', MONOSPACE_FONT)
        tvcolumn.pack_start(cell, True)
        tvcolumn.add_attribute(cell, 'text', 0)

        tvcolumn = Gtk.TreeViewColumn('Label')
        tvcolumn.set_expand(True)
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        cell.set_property('editable', True)
        def edited_cb2(cell, path, new_text, liststore):
            address = liststore.get_value( liststore.get_iter(path), 0)
            self.wallet.set_label(address, new_text)
            self.update_receiving_tab()
            self.update_sending_tab()
            self.update_history_tab()
        cell.connect('edited', edited_cb2, liststore)
        tvcolumn.pack_start(cell, True)
        tvcolumn.add_attribute(cell, 'text', 1)

        tvcolumn = Gtk.TreeViewColumn('Tx')
        treeview.append_column(tvcolumn)
        cell = Gtk.CellRendererText()
        tvcolumn.pack_start(cell, True)
        tvcolumn.add_attribute(cell, 'text', 2)

        if is_recv:
            tvcolumn = Gtk.TreeViewColumn('Balance')
            treeview.append_column(tvcolumn)
            cell = Gtk.CellRendererText()
            tvcolumn.pack_start(cell, True)
            tvcolumn.add_attribute(cell, 'text', 3)
            tvcolumn = Gtk.TreeViewColumn('Type')
            treeview.append_column(tvcolumn)
            cell = Gtk.CellRendererText()
            tvcolumn.pack_start(cell, True)
            tvcolumn.add_attribute(cell, 'text', 4)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.add(treeview)

        hbox = Gtk.HBox()
        if not is_recv:
            button = Gtk.Button("New")
            button.connect("clicked", self.newaddress_dialog)
            button.show()
            hbox.pack_start(button,False, False, 0)

        def showqrcode(w, treeview, liststore):
            import qrcode
            path, col = treeview.get_cursor()
            if not path: return
            address = liststore.get_value(liststore.get_iter(path), 0)
            qr = qrcode.QRCode()
            qr.add_data(address)
            boxsize = 7
            matrix = qr.get_matrix()
            boxcount_row = len(matrix)
            size = (boxcount_row + 4) * boxsize
            def area_expose_cb(area, cr):
                style = area.get_style()
                Gdk.cairo_set_source_color(cr, style.white)
                cr.rectangle(0, 0, size, size)
                cr.fill()
                Gdk.cairo_set_source_color(cr, style.black)
                for r in range(boxcount_row):
                    for c in range(boxcount_row):
                        if matrix[r][c]:
                            cr.rectangle((c + 2) * boxsize, (r + 2) * boxsize, boxsize, boxsize)
                            cr.fill()
            area = Gtk.DrawingArea()
            area.set_size_request(size, size)
            area.connect("draw", area_expose_cb)
            area.show()
            dialog = Gtk.Dialog(address, parent=self.window, flags=Gtk.DialogFlags.MODAL, buttons = ("ok",1))
            dialog.vbox.add(area)
            dialog.run()
            dialog.destroy()

        button = Gtk.Button("QR")
        button.connect("clicked", showqrcode, treeview, liststore)
        button.show()
        hbox.pack_start(button,False, False, 0)

        button = Gtk.Button("Copy to clipboard")
        def copy2clipboard(w, treeview, liststore):
            import platform
            path, col =  treeview.get_cursor()
            if path:
                address =  liststore.get_value( liststore.get_iter(path), 0)
                if platform.system() == 'Windows':
                    from Tkinter import Tk
                    r = Tk()
                    r.withdraw()
                    r.clipboard_clear()
                    r.clipboard_append( address )
                    r.destroy()
                else:
                    atom = Gdk.atom_intern('CLIPBOARD', True)
                    c = Gtk.Clipboard.get(atom)
                    c.set_text( address, len(address) )
        button.connect("clicked", copy2clipboard, treeview, liststore)
        button.show()
        hbox.pack_start(button,False, False, 0)

        if is_recv:
            button = Gtk.Button("Freeze")
            def freeze_address(w, treeview, liststore, wallet):
                path, col = treeview.get_cursor()
                if path:
                    address = liststore.get_value( liststore.get_iter(path), 0)
                    wallet.set_frozen_state([address], not wallet.is_frozen(address))
                    self.update_receiving_tab()
            button.connect("clicked", freeze_address, treeview, liststore, self.wallet)
            button.show()
            hbox.pack_start(button,False, False, 0)

        if not is_recv:
            button = Gtk.Button("Pay to")
            def payto(w, treeview, liststore):
                path, col =  treeview.get_cursor()
                if path:
                    address =  liststore.get_value( liststore.get_iter(path), 0)
                    self.payto_entry.set_text( address )
                    self.notebook.set_current_page(1)
                    self.amount_entry.grab_focus()

            button.connect("clicked", payto, treeview, liststore)
            button.show()
            hbox.pack_start(button,False, False, 0)

        vbox = Gtk.VBox()
        vbox.pack_start(scroll,True, True, 0)
        vbox.pack_start(hbox, False, False, 0)
        return vbox

    def update_status_bar(self):

        if self.funds_error:
            text = "Not enough funds"
        elif self.network.is_connected():
            host, port, _,_,_ = self.network.get_parameters()
            port = int(port)
            height = self.network.get_local_height()
            self.network_button.set_tooltip_text("Connected to %s:%d.\n%d blocks"%(host, port, height))
            if not self.wallet.up_to_date:
                self.status_image.set_from_stock(Gtk.STOCK_REFRESH, Gtk.IconSize.MENU)
                text = "Synchronizing..."
            else:
                self.status_image.set_from_stock(Gtk.STOCK_YES, Gtk.IconSize.MENU)
                c, u, x = self.wallet.get_balance()
                text = "Balance: %s "%(format_satoshis(c, False, self.num_zeros))
                if u:
                    text += "[%s unconfirmed]"%(format_satoshis(u, True, self.num_zeros).strip())
                if x:
                    text += "[%s unmatured]"%(format_satoshis(x, True, self.num_zeros).strip())
        else:
            self.status_image.set_from_stock(Gtk.STOCK_NO, Gtk.IconSize.MENU)
            self.network_button.set_tooltip_text("Not connected.")
            text = "Not connected"

        self.status_bar.pop(self.context_id)
        self.status_bar.push(self.context_id, text)

        if self.wallet.up_to_date and self.wallet_updated:
            self.update_history_tab()
            self.update_receiving_tab()
            # addressbook too...
            self.info.set_text( self.network.banner )
            self.wallet_updated = False

    def update_receiving_tab(self):
        self.recv_list.clear()
        for address in self.wallet.addresses(True):
            Type = "R"
            c = u = 0
            if self.wallet.is_change(address): Type = "C"
            if address in self.wallet.imported_keys.keys():
                Type = "I"
            c, u, x = self.wallet.get_addr_balance(address)
            if self.wallet.is_frozen(address): Type = Type + "F"
            label = self.wallet.labels.get(address)
            h = self.wallet.history.get(address,[])
            n = len(h)
            tx = "0" if n==0 else "%d"%n
            self.recv_list.append((address, label, tx, format_satoshis(c+u+x, False, self.num_zeros), Type ))

    def update_sending_tab(self):
        self.addressbook_list.clear()
        for k, v in self.contacts.items():
            t, v = v
            self.addressbook_list.append((k, v, t))

    def update_history_tab(self):
        cursor = self.history_treeview.get_cursor()[0]
        self.history_list.clear()

        for item in self.wallet.get_history():
            tx_hash, conf, value, timestamp, balance = item
            if conf > 0:
                try:
                    time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
                except Exception:
                    time_str = "------"
                conf_icon = Gtk.STOCK_APPLY
            elif conf == -1:
                time_str = 'unverified'
                conf_icon = None
            else:
                time_str = 'pending'
                conf_icon = Gtk.STOCK_EXECUTE

            label = self.wallet.get_label(tx_hash)
            tooltip = tx_hash + "\n%d confirmations"%conf if tx_hash else ''
            details = self.get_tx_details(tx_hash)

            self.history_list.prepend( [tx_hash, conf_icon, time_str, label, False,
                                        format_satoshis(value,True,self.num_zeros, whitespaces=True),
                                        format_satoshis(balance,False,self.num_zeros, whitespaces=True), tooltip, details] )
        if cursor: self.history_treeview.set_cursor( cursor )


    def get_tx_details(self, tx_hash):
        import datetime
        if not tx_hash: return ''
        tx = self.wallet.transactions.get(tx_hash)
        tx.deserialize()
        is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        conf, timestamp = self.wallet.get_confirmations(tx_hash)

        if timestamp:
            time_str = datetime.datetime.fromtimestamp(timestamp).isoformat(' ')[:-3]
        else:
            time_str = 'pending'

        inputs = map(lambda x: x.get('address'), tx.inputs)
        outputs = map(lambda x: x[0], tx.get_outputs())
        tx_details = "Transaction Details" +"\n\n" \
            + "Transaction ID:\n" + tx_hash + "\n\n" \
            + "Status: %d confirmations\n"%conf
        if is_mine:
            if fee:
                tx_details += "Amount sent: %s\n"% format_satoshis(v-fee, False) \
                              + "Transaction fee: %s\n"% format_satoshis(fee, False)
            else:
                tx_details += "Amount sent: %s\n"% format_satoshis(v, False) \
                              + "Transaction fee: unknown\n"
        else:
            tx_details += "Amount received: %s\n"% format_satoshis(v, False) \

        tx_details += "Date: %s\n\n"%time_str \
            + "Inputs:\n-"+ '\n-'.join(inputs) + "\n\n" \
            + "Outputs:\n-"+ '\n-'.join(outputs)

        return tx_details



    def newaddress_dialog(self, w):

        title = "New Contact"
        dialog = Gtk.Dialog(title, parent=self.window,
                            flags=Gtk.DialogFlags.MODAL,
                            buttons= ("cancel", 0, "ok",1)  )
        dialog.show()

        label = Gtk.HBox()
        label_label = Gtk.Label(label='Label:')
        label_label.set_size_request(120,10)
        label_label.show()
        label.pack_start(label_label, True, True, 0)
        label_entry = Gtk.Entry()
        label_entry.show()
        label.pack_start(label_entry, True, True, 0)
        label.show()
        dialog.vbox.pack_start(label, False, True, 5)

        address = Gtk.HBox()
        address_label = Gtk.Label(label='Address:')
        address_label.set_size_request(120,10)
        address_label.show()
        address.pack_start(address_label, True, True, 0)
        address_entry = Gtk.Entry()
        address_entry.show()
        address.pack_start(address_entry, True, True, 0)
        address.show()
        dialog.vbox.pack_start(address, False, True, 5)

        result = dialog.run()
        address = address_entry.get_text()
        label = label_entry.get_text()
        dialog.destroy()

        if result == 1:
            if is_valid(address):
                self.contacts[label] = address
                self.update_sending_tab()
            else:
                errorDialog = Gtk.MessageDialog(
                    parent=self.window,
                    flags=Gtk.DialogFlags.MODAL,
                    buttons= Gtk.ButtonsType.CLOSE,
                    message_format = "Invalid address")
                errorDialog.show()
                errorDialog.run()
                errorDialog.destroy()



class ElectrumGui():

    def __init__(self, config, network, daemon, plugins):
        self.network = network
        self.config = config


    def main(self):

        storage = WalletStorage(self.config.get_wallet_path())
        if not storage.file_exists:
            action = self.restore_or_create()
            if not action:
                exit()
            self.wallet = wallet = Wallet(storage)
            gap = self.config.get('gap_limit', 5)
            if gap != 5:
                wallet.gap_limit = gap
                wallet.storage.put('gap_limit', gap)

            if action == 'create':
                seed = wallet.make_seed()
                show_seed_dialog(seed, None)
                r = change_password_dialog(False, None)
                password = r[2] if r else None
                wallet.add_seed(seed, password)
                wallet.create_master_keys(password)
                wallet.create_main_account(password)
                wallet.synchronize()  # generate first addresses offline

            elif action == 'restore':
                seed = self.seed_dialog()
                if not seed:
                    exit()
                r = change_password_dialog(False, None)
                password = r[2] if r else None
                wallet.add_seed(seed, password)
                wallet.create_master_keys(password)
                wallet.create_main_account(password)

            else:
                exit()
        else:
            self.wallet = Wallet(storage)
            action = None

        self.wallet.start_threads(self.network)

        if action == 'restore':
            self.restore_wallet(wallet)

        w = ElectrumWindow(self.wallet, self.config, self.network)
        #if url: w.set_url(url)
        Gtk.main()

    def restore_or_create(self):
        return restore_create_dialog()

    def seed_dialog(self):
        return run_recovery_dialog()

    def network_dialog(self):
        return run_network_dialog( self.network, parent=None )


    def restore_wallet(self, wallet):

        dialog = Gtk.MessageDialog(
            parent = None,
            flags = Gtk.DialogFlags.MODAL,
            buttons = Gtk.ButtonsType.CANCEL,
            message_format = "Please wait..."  )
        dialog.show()

        def recover_thread( wallet, dialog ):
            wallet.wait_until_synchronized()
            GObject.idle_add(dialog.destroy)

        thread.start_new_thread( recover_thread, ( wallet, dialog ) )
        r = dialog.run()
        dialog.destroy()
        if r==Gtk.ResponseType.CANCEL: return False
        if not wallet.is_found():
            show_message("No transactions found for this seed")

        return True
