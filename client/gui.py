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
import thread, time, ast, sys
import socket, traceback
import pygtk
pygtk.require('2.0')
import gtk, gobject
import pyqrnative

gtk.gdk.threads_init()
APP_NAME = "Electrum"

def format_satoshis(x):
    xx = ("%f"%(x*1e-8)).rstrip('0')
    if xx[-1] =='.': xx+="00"
    if xx[-2] =='.': xx+="0"
    return xx

def numbify(entry, is_int = False):
    text = entry.get_text().strip()
    s = ''.join([i for i in text if i in '0123456789.'])
    entry.set_text(s)


def show_seed_dialog(wallet, password):
    import mnemonic
    try:
        seed = wallet.pw_decode( wallet.seed, password)
        private_keys = ast.literal_eval( wallet.pw_decode( wallet.private_keys, password) )
    except:
        show_message("Incorrect password")
        return
    dialog = gtk.MessageDialog(
        parent = None,
        flags = gtk.DIALOG_MODAL, 
        buttons = gtk.BUTTONS_OK, 
        message_format = "Your wallet generation seed is:\n\n" + seed \
            + "\n\nPlease keep it in a safe place; if you lose it, you will not be able to restore your wallet.\n\n" \
            + "Equivalently, your wallet seed can be stored and recovered with the following mnemonic code:\n\n\"" + ' '.join(mnemonic.mn_encode(seed)) + "\"" )
    dialog.show()
    dialog.run()
    dialog.destroy()

def init_wallet(wallet):

    if not wallet.read():

        # ask if the user wants to create a new wallet, or recover from a seed. 
        # if he wants to recover, and nothing is found, do not create wallet
        dialog = gtk.Dialog("electrum", parent=None, 
                            flags=gtk.DIALOG_MODAL|gtk.DIALOG_NO_SEPARATOR, 
                            buttons= ("create", 0, "restore",1, "cancel",2)  )

        label = gtk.Label("Wallet file not found.\nDo you want to create a new wallet,\n or to restore an existing one?"  )
        label.show()
        dialog.vbox.pack_start(label)
        dialog.show()
        r = dialog.run()
        dialog.destroy()
        if r==2:
            sys.exit(1)
        
        is_recovery = (r==1)

        if not is_recovery:

            wallet.new_seed(None)

            # ask for the server.
            run_settings_dialog(wallet, is_create=True, is_recovery=False)

            # generate first key
            wallet.create_new_address(False, None)

            # run a dialog indicating the seed, ask the user to remember it
            show_seed_dialog(wallet, None)
            
            #ask for password
            change_password_dialog(wallet, None)

        else:
            # ask for the server, seed and gap.
            run_settings_dialog(wallet, is_create=True, is_recovery=True)

            dialog = gtk.MessageDialog(
                parent = None,
                flags = gtk.DIALOG_MODAL, 
                buttons = gtk.BUTTONS_CANCEL, 
                message_format = "Please wait..."  )
            dialog.show()

            def recover_thread( wallet, dialog, password ):
                wallet.is_found = wallet.recover( password )
                if wallet.is_found:
                    wallet.save()
                gobject.idle_add( dialog.destroy )

            thread.start_new_thread( recover_thread, ( wallet, dialog, None ) ) # no password
            r = dialog.run()
            dialog.destroy()
            if r==gtk.RESPONSE_CANCEL: sys.exit(1)
            if not wallet.is_found:
                show_message("No transactions found for this seed")


def settings_dialog(wallet, is_create,  is_recovery):

    if is_create:
        dialog = gtk.MessageDialog(
            parent = None,
            flags = gtk.DIALOG_MODAL, 
            buttons = gtk.BUTTONS_OK_CANCEL, 
            message_format = "Please indicate the server and port number" if not is_recovery else 'Please enter your wallet seed or the corresponding mnemonic list of words, the server and the gap limit')
    else:
        dialog = gtk.MessageDialog( None, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                                    gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL,  None)
        dialog.get_image().set_visible(False)
        dialog.set_title("Settings")

    vbox = dialog.vbox
    dialog.set_default_response(gtk.RESPONSE_OK)

    if is_recovery:
        # ask seed, server and gap in the same dialog
        seed_box = gtk.HBox()
        seed_label = gtk.Label('Seed or mnemonic:')
        seed_label.set_size_request(150,-1)
        seed_box.pack_start(seed_label, False, False, 10)
        seed_label.show()
        seed_entry = gtk.Entry()
        seed_entry.show()
        seed_entry.set_size_request(450,-1)
        seed_box.pack_start(seed_entry, False, False, 10)
        add_help_button(seed_box, '.')
        seed_box.show()
        vbox.pack_start(seed_box, False, False, 5)    

    if is_recovery or (not is_create):
        gap = gtk.HBox()
        gap_label = gtk.Label('Gap limit:')
        gap_label.set_size_request(150,10)
        gap_label.show()
        gap.pack_start(gap_label,False, False, 10)
        gap_entry = gtk.Entry()
        gap_entry.set_text("%d"%wallet.gap_limit)
        gap_entry.connect('changed', numbify, True)
        gap_entry.show()
        gap.pack_start(gap_entry,False,False, 10)
        add_help_button(gap, 'The maximum gap that is allowed between unused addresses in your wallet. During wallet recovery, this parameter is used to decide when to stop the recovery process. If you increase this value, you will need to remember it in order to be able to recover your wallet from seed.')
        gap.show()
        vbox.pack_start(gap, False,False, 5)

    if is_recovery or is_create:
        host = gtk.HBox()
        host_label = gtk.Label('Server:')
        host_label.set_size_request(150,-1)
        host_label.show()
        host.pack_start(host_label,False, False, 10)
        host_entry = gtk.Entry()
        host_entry.set_text(wallet.host+":%d"%wallet.port)
        host_entry.show()
        host.pack_start(host_entry,False,False, 10)
        add_help_button(host, 'The name and port number of your Electrum server, separated by a colon. Example: "ecdsa.org:50000". If no port number is provided, the http port 80 will be tried.')
        host.show()
        vbox.pack_start(host, False,False, 5)

    if not is_create:
        fee = gtk.HBox()
        fee_entry = gtk.Entry()
        fee_label = gtk.Label('Tx. fee:')
        fee_label.set_size_request(150,10)
        fee_label.show()
        fee.pack_start(fee_label,False, False, 10)
        fee_entry.set_text("%f"%(wallet.fee))
        fee_entry.connect('changed', numbify, False)
        fee_entry.show()
        fee.pack_start(fee_entry,False,False, 10)
        add_help_button(fee, 'Transaction fee. Recommended value:0.005')
        fee.show()
        vbox.pack_start(fee, False,False, 5)
            
    if not is_create:
        return dialog, fee_entry, gap_entry
    elif is_recovery:
        return dialog, seed_entry, gap_entry, host_entry
    else:
        return dialog, host_entry


def run_settings_dialog( wallet, is_create, is_recovery):

    if not is_create:
        dialog, fee_entry, gap_entry = settings_dialog(wallet, is_create, is_recovery)
    elif is_recovery:
        dialog, seed_entry, gap_entry, host_entry = settings_dialog(wallet, is_create, is_recovery)
    else:
        dialog, host_entry, = settings_dialog(wallet, is_create, is_recovery)

    dialog.show()
    r = dialog.run()
    if is_create:
        hh = host_entry.get_text()
    if is_recovery:
        gap = gap_entry.get_text()
        seed = seed_entry.get_text()
        try:
            seed.decode('hex')
        except:
            import mnemonic
            print "not hex, trying decode"
            seed = mnemonic.mn_decode( seed.split(' ') )
    dialog.destroy()
    if r==gtk.RESPONSE_CANCEL:
        if is_create: sys.exit(1)
        else: return

    try:
        if is_create:
            if ':' in hh:
                host, port = hh.split(':')
                port = int(port)
            else:
                host = hh
                port = 80
        if is_recovery: gap = int(gap)
    except:
        show_message("error")
        return

    wallet.host = host
    wallet.port = port
    if is_recovery:
        wallet.seed = seed
        wallet.gap_limit = gap
    wallet.save()




def show_message(message):
    dialog = gtk.MessageDialog(
        parent = None,
        flags = gtk.DIALOG_MODAL, 
        buttons = gtk.BUTTONS_CLOSE, 
        message_format = message )
    dialog.show()
    dialog.run()
    dialog.destroy()

def password_line(label):
    password = gtk.HBox()
    password_label = gtk.Label(label)
    password_label.set_size_request(120,10)
    password_label.show()
    password.pack_start(password_label,False, False, 10)
    password_entry = gtk.Entry()
    password_entry.set_size_request(300,-1)
    password_entry.set_visibility(False)
    password_entry.show()
    password.pack_start(password_entry,False,False, 10)
    password.show()
    return password, password_entry

def password_dialog():
    dialog = gtk.MessageDialog( None, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                                gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL,  "Please enter your password.")
    dialog.get_image().set_visible(False)
    current_pw, current_pw_entry = password_line('Password:')
    current_pw_entry.connect("activate", lambda entry, dialog, response: dialog.response(response), dialog, gtk.RESPONSE_OK)
    dialog.vbox.pack_start(current_pw, False, True, 0)
    dialog.show()
    result = dialog.run()
    pw = current_pw_entry.get_text()
    dialog.destroy()
    if result: return pw

def change_password_dialog(wallet, icon):
    if icon:
        msg = 'Your wallet is encrypted. Use this dialog to change the password. To disable wallet encryption, enter an empty new password.' if wallet.use_encryption else 'Your wallet keys are not encrypted'
    else:
        msg = "Please choose a password to encrypt your wallet keys"

    dialog = gtk.MessageDialog( None, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, msg)
    dialog.set_title("Change password")

    if wallet.use_encryption:
        current_pw, current_pw_entry = password_line('Current password:')
        dialog.vbox.pack_start(current_pw, False, True, 0)

    password, password_entry = password_line('New password:')
    dialog.vbox.pack_start(password, False, True, 5)
    password2, password2_entry = password_line('Confirm password:')
    dialog.vbox.pack_start(password2, False, True, 5)

    dialog.show()
    result = dialog.run()
    password = current_pw_entry.get_text() if wallet.use_encryption else None
    new_password = password_entry.get_text()
    new_password2 = password2_entry.get_text()
    dialog.destroy()
    if result == gtk.RESPONSE_CANCEL: 
        return

    try:
        seed = wallet.pw_decode( wallet.seed, password)
        private_keys = ast.literal_eval( wallet.pw_decode( wallet.private_keys, password) )
    except:
        show_message("Incorrect password")
        return

    if new_password != new_password2:
        show_message("passwords do not match")
        return

    wallet.use_encryption = (new_password != '')
    wallet.seed = wallet.pw_encode( seed, new_password)
    wallet.private_keys = wallet.pw_encode( repr( private_keys ), new_password)
    wallet.save()

    if icon:
        if wallet.use_encryption:
            icon.set_tooltip_text('wallet is encrypted')
        else:
            icon.set_tooltip_text('wallet is unencrypted')


def add_help_button(hbox, message):
    button = gtk.Button('?')
    button.connect("clicked", lambda x: show_message(message))
    button.show()
    hbox.pack_start(button,False, False)


class MyWindow(gtk.Window): __gsignals__ = dict( mykeypress = (gobject.SIGNAL_RUN_LAST | gobject.SIGNAL_ACTION, None, (str,)) )

gobject.type_register(MyWindow)
gtk.binding_entry_add_signal(MyWindow, gtk.keysyms.W, gtk.gdk.CONTROL_MASK, 'mykeypress', str, 'ctrl+W')
gtk.binding_entry_add_signal(MyWindow, gtk.keysyms.Q, gtk.gdk.CONTROL_MASK, 'mykeypress', str, 'ctrl+Q')


class BitcoinGUI:

    def __init__(self, wallet):
        self.error = ''
        self.is_connected = False
        self.wallet = wallet
        self.period = 5

        self.window = MyWindow(gtk.WINDOW_TOPLEVEL)
        self.window.set_title(APP_NAME)
        self.window.connect("destroy", gtk.main_quit)
        self.window.set_border_width(0)
        self.window.connect('mykeypress', gtk.main_quit)
        self.window.set_default_size(670, 350)

        vbox = gtk.VBox()

        self.notebook = gtk.Notebook()
        self.create_history_tab()
        self.create_send_tab()
        self.create_recv_tab()
        self.create_book_tab()
        self.create_about_tab()
        self.notebook.show()
        vbox.pack_start(self.notebook, True, True, 2)
        
        self.status_bar = gtk.Statusbar()
        vbox.pack_start(self.status_bar, False, False, 0)

        self.status_image = gtk.Image()
        self.status_image.set_from_stock(gtk.STOCK_YES, gtk.ICON_SIZE_MENU)
        self.status_image.set_alignment(True, 0.5  )
        self.status_image.show()

        self.network_button = gtk.Button()
        self.network_button.connect("clicked", self.network_dialog )
        self.network_button.add(self.status_image)
        self.network_button.set_relief(gtk.RELIEF_NONE)
        self.network_button.show()
        self.status_bar.pack_end(self.network_button, False, False)

        def seedb(w, wallet):
            if wallet.use_encryption:
                password = password_dialog()
                if not password: return
            else: password = None
            show_seed_dialog(wallet, password)
        button = gtk.Button('S')
        button.connect("clicked", seedb, wallet )
        button.set_relief(gtk.RELIEF_NONE)
        button.show()
        self.status_bar.pack_end(button,False, False)

        settings_icon = gtk.Image()
        settings_icon.set_from_stock(gtk.STOCK_PREFERENCES, gtk.ICON_SIZE_MENU)
        settings_icon.set_alignment(0.5, 0.5)
        settings_icon.set_size_request(16,16 )
        settings_icon.show()

        prefs_button = gtk.Button()
        prefs_button.connect("clicked", lambda x: run_settings_dialog(self.wallet, False, False) )
        prefs_button.add(settings_icon)
        prefs_button.set_tooltip_text("Settings")
        prefs_button.set_relief(gtk.RELIEF_NONE)
        prefs_button.show()
        self.status_bar.pack_end(prefs_button,False,False)

        pw_icon = gtk.Image()
        pw_icon.set_from_stock(gtk.STOCK_DIALOG_AUTHENTICATION, gtk.ICON_SIZE_MENU)
        pw_icon.set_alignment(0.5, 0.5)
        pw_icon.set_size_request(16,16 )
        pw_icon.show()

        password_button = gtk.Button()
        password_button.connect("clicked", lambda x: change_password_dialog(self.wallet, pw_icon))
        password_button.add(pw_icon)
        password_button.set_relief(gtk.RELIEF_NONE)
        password_button.show()
        self.status_bar.pack_end(password_button,False,False)

        self.window.add(vbox)
        self.window.show_all()

        self.context_id = self.status_bar.get_context_id("statusbar")
        self.update_status_bar()

        def update_status_bar_thread():
            while True:
                gobject.idle_add( self.update_status_bar )
                time.sleep(0.5)

        def update_wallet_thread():
            while True:
                try:
                    self.wallet.new_session()
                    self.is_connected = True
                except:
                    self.is_connected = False
                    traceback.print_exc(file=sys.stdout)
                    time.sleep(self.period)
                    continue

                wallet.get_servers()
                self.info.set_text( self.wallet.message)

                while True:
                    self.period = 15 if self.wallet.use_http() else 5
                    try:
                        u = self.wallet.update()
                        self.is_connected = True
                    except BaseException:
                        print "starting new session"
                        break
                    except socket.gaierror:
                        self.is_connected = False
                        break
                    except:
                        self.is_connected = False
                        print "error"
                        traceback.print_exc(file=sys.stdout)
                        break
                    self.error = '' if self.is_connected else "Not connected"
                    if u:
                        self.wallet.save()
                        gobject.idle_add( self.update_history_tab )
                    time.sleep(self.period)
                    
        thread.start_new_thread(update_wallet_thread, ())
        thread.start_new_thread(update_status_bar_thread, ())
        self.notebook.set_current_page(0)


    def add_tab(self, page, name):
        tab_label = gtk.Label(name)
        tab_label.show()
        self.notebook.append_page(page, tab_label)


    def create_send_tab(self):

        page = vbox = gtk.VBox()
        page.show()

        payto = gtk.HBox()
        payto_label = gtk.Label('Pay to:')
        payto_label.set_size_request(100,10)
        payto_label.show()
        payto.pack_start(payto_label, False)
        payto_entry = gtk.Entry()
        payto_entry.set_size_request(350, 26)
        payto_entry.show()
        payto.pack_start(payto_entry, False)
        vbox.pack_start(payto, False, False, 5)
        
        label = gtk.HBox()
        label_label = gtk.Label('Label:')
        label_label.set_size_request(100,10)
        label_label.show()
        label.pack_start(label_label, False)
        label_entry = gtk.Entry()
        label_entry.set_size_request(350, 26)
        label_entry.show()
        label.pack_start(label_entry, False)
        vbox.pack_start(label, False, False, 5)

        amount = gtk.HBox()
        amount_label = gtk.Label('Amount:')
        amount_label.set_size_request(100,10)
        amount_label.show()
        amount.pack_start(amount_label, False)
        amount_entry = gtk.Entry()
        amount_entry.set_size_request(100, 26) 
        amount_entry.connect('changed', numbify)
        amount_entry.show()
        amount.pack_start(amount_entry, False)
        vbox.pack_start(amount, False, False, 5)

        button = gtk.Button("Send")
        button.connect("clicked", self.do_send, (payto_entry, label_entry, amount_entry))
        button.show()
        amount.pack_start(button, False, False, 5)

        self.payto_entry = payto_entry
        self.payto_amount_entry = amount_entry
        self.payto_label_entry = label_entry
        self.add_tab(page, 'Send')

    def create_about_tab(self):
        page = gtk.VBox()
        page.show()
        self.info = gtk.Label('')  
        self.info.set_selectable(True)
        page.pack_start(self.info)
        #tv = gtk.TextView()
        #tv.set_editable(False)
        #tv.set_cursor_visible(False)
        #page.pack_start(tv)
        #self.info = tv.get_buffer()
        self.add_tab(page, 'Wall')

    def do_send(self, w, data):
        payto_entry, label_entry, amount_entry = data
        
        label = label_entry.get_text()

        to_address = payto_entry.get_text()
        if not self.wallet.is_valid(to_address):
            show_message( "invalid bitcoin address" )
            return

        try:
            amount = float(amount_entry.get_text())
        except:
            show_message( "invalid amount" )
            return

        password = password_dialog() if self.wallet.use_encryption else None

        status, tx = self.wallet.mktx( to_address, amount, label, password )
        self.wallet.new_session() # we created a new change address
        if not status:
            show_message(tx)
            return

        status, msg = self.wallet.sendtx( tx )
        if status:
            show_message( "payment sent.\n" + msg )
            payto_entry.set_text("")
            label_entry.set_text("")
            amount_entry.set_text("")
            self.update_sending_tab()
        else:
            show_message( msg )


    def treeview_key_press(self, treeview, event):
        c = treeview.get_cursor()[0]
        if event.keyval == gtk.keysyms.Up:
            if c and c[0] == 0:
                treeview.parent.grab_focus()
                treeview.set_cursor((0,))
        elif event.keyval == gtk.keysyms.Return and treeview == self.history_treeview:
            tx_details = self.history_list.get_value( self.history_list.get_iter(c), 8)
            show_message(tx_details)
        return False

    def create_history_tab(self):

        self.history_list = gtk.ListStore(str, str, str, str, 'gboolean',  str, str, str, str)
        treeview = gtk.TreeView(model=self.history_list)
        self.history_treeview = treeview
        treeview.set_tooltip_column(7)
        treeview.show()
        treeview.connect('key-press-event', self.treeview_key_press)

        tvcolumn = gtk.TreeViewColumn('')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererPixbuf()
        tvcolumn.pack_start(cell, False)
        tvcolumn.set_attributes(cell, stock_id=1)

        tvcolumn = gtk.TreeViewColumn('Date')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 2)

        tvcolumn = gtk.TreeViewColumn('Label')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_property('foreground', 'grey')
        cell.set_property('family', 'monospace')
        cell.set_property('editable', True)
        def edited_cb(cell, path, new_text, h_list):
            tx = h_list.get_value( h_list.get_iter(path), 0)
            self.wallet.labels[tx] = new_text
            self.wallet.save() 
            self.update_history_tab()
        cell.connect('edited', edited_cb, self.history_list)
        def editing_started(cell, entry, path, h_list):
            tx = h_list.get_value( h_list.get_iter(path), 0)
            if not self.wallet.labels.get(tx): entry.set_text('')
        cell.connect('editing-started', editing_started, self.history_list)
        tvcolumn.set_expand(True)
        tvcolumn.pack_start(cell, True)
        tvcolumn.set_attributes(cell, text=3, foreground_set = 4)

        tvcolumn = gtk.TreeViewColumn('Amount')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_alignment(1, 0.5)
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 5)

        tvcolumn = gtk.TreeViewColumn('Balance')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_alignment(1, 0.5)
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 6)

        tvcolumn = gtk.TreeViewColumn('Tooltip')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 7)
        tvcolumn.set_visible(False)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scroll.add(treeview)

        self.add_tab(scroll, 'History')
        self.update_history_tab()


    def create_recv_tab(self):
        self.recv_list = gtk.ListStore(str, str, str)
        self.add_tab( self.make_address_list(True), 'Receive')
        self.update_receiving_tab()

    def create_book_tab(self):
        self.addressbook_list = gtk.ListStore(str, str, str)
        self.add_tab( self.make_address_list(False), 'Contacts')
        self.update_sending_tab()

    def make_address_list(self, is_recv):
        liststore = self.recv_list if is_recv else self.addressbook_list
        treeview = gtk.TreeView(model= liststore)
        treeview.connect('key-press-event', self.treeview_key_press)
        treeview.show()

        tvcolumn = gtk.TreeViewColumn('Address')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_property('family', 'monospace')
        tvcolumn.pack_start(cell, True)
        tvcolumn.add_attribute(cell, 'text', 0)

        tvcolumn = gtk.TreeViewColumn('Label')
        tvcolumn.set_expand(True)
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        cell.set_property('editable', True)
        def edited_cb2(cell, path, new_text, liststore):
            address = liststore.get_value( liststore.get_iter(path), 0)
            self.wallet.labels[address] = new_text
            self.wallet.save() 
            self.wallet.update_tx_labels()
            self.update_receiving_tab()
            self.update_sending_tab()
            self.update_history_tab()
        cell.connect('edited', edited_cb2, liststore)
        tvcolumn.pack_start(cell, True)
        tvcolumn.add_attribute(cell, 'text', 1)

        tvcolumn = gtk.TreeViewColumn('Tx')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, True)
        tvcolumn.add_attribute(cell, 'text', 2)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scroll.add(treeview)

        hbox = gtk.HBox()
        button = gtk.Button("New address")
        button.connect("clicked", self.newaddress_dialog, is_recv)
        button.show()
        hbox.pack_start(button,False)

        def showqrcode(w, treeview, liststore):
            path, col = treeview.get_cursor()
            if not path: return
            address = liststore.get_value(liststore.get_iter(path), 0)
            qr = pyqrnative.QRCode(4, pyqrnative.QRErrorCorrectLevel.H)
            qr.addData(address)
            qr.make()
            boxsize = 7
            size = qr.getModuleCount()*boxsize
            def area_expose_cb(area, event):
                style = area.get_style()
                k = qr.getModuleCount()
                for r in range(k):
                    for c in range(k):
                        gc = style.black_gc if qr.isDark(r, c) else style.white_gc
                        area.window.draw_rectangle(gc, True, c*boxsize, r*boxsize, boxsize, boxsize)
            area = gtk.DrawingArea()
            area.set_size_request(size, size)
            area.connect("expose-event", area_expose_cb)
            area.show()
            dialog = gtk.Dialog(address, parent=self.window, flags=gtk.DIALOG_MODAL|gtk.DIALOG_NO_SEPARATOR, buttons = ("ok",1))
            dialog.vbox.add(area)
            dialog.run()
            dialog.destroy()

        button = gtk.Button("QR")
        button.connect("clicked", showqrcode, treeview, liststore)
        button.show()
        hbox.pack_start(button,False)

        button = gtk.Button("Copy to clipboard")
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
                    c = gtk.clipboard_get()
                    c.set_text( address )
        button.connect("clicked", copy2clipboard, treeview, liststore)
        button.show()
        hbox.pack_start(button,False)

        if not is_recv:
            button = gtk.Button("Pay to")
            def payto(w, treeview, liststore):
                path, col =  treeview.get_cursor()
                if path:
                    address =  liststore.get_value( liststore.get_iter(path), 0)
                    self.payto_entry.set_text( address )
                    self.notebook.set_current_page(1)
                    self.payto_amount_entry.grab_focus()

            button.connect("clicked", payto, treeview, liststore)
            button.show()
            hbox.pack_start(button,False)

        vbox = gtk.VBox()
        vbox.pack_start(scroll,True)
        vbox.pack_start(hbox, False)
        return vbox

    def update_status_bar(self):
        c, u = self.wallet.get_balance()
        if self.is_connected:
            self.status_image.set_from_stock(gtk.STOCK_YES, gtk.ICON_SIZE_MENU)
            self.network_button.set_tooltip_text("Connected to %s.\n%d blocks\nresponse time: %f"%(self.wallet.host, self.wallet.blocks, self.wallet.rtime))
        else:
            self.status_image.set_from_stock(gtk.STOCK_NO, gtk.ICON_SIZE_MENU)
            self.network_button.set_tooltip_text("Trying to contact %s.\n%d blocks"%(self.wallet.host, self.wallet.blocks))
        text =  "Balance: %s "%( format_satoshis(c) )
        if u: text +=  "[+ %s unconfirmed]"%( format_satoshis(u) )
        if self.error: text = self.error
        self.status_bar.pop(self.context_id) 
        self.status_bar.push(self.context_id, text) 

    def update_receiving_tab(self):
        self.recv_list.clear()
        for address in self.wallet.addresses:
            if self.wallet.is_change(address):continue
            label = self.wallet.labels.get(address)
            n = 0 
            h = self.wallet.history.get(address)
            if h:
                for item in h:
                    if not item['is_in'] : n=n+1
            tx = "None" if n==0 else "%d"%n
            self.recv_list.prepend((address, label, tx ))

    def update_sending_tab(self):
        # detect addresses that are not mine in history, add them here...
        self.addressbook_list.clear()
        for address in self.wallet.addressbook:
            label = self.wallet.labels.get(address)
            n = 0 
            for item in self.wallet.tx_history.values():
                if address in item['outputs'] : n=n+1
            tx = "None" if n==0 else "%d"%n
            self.addressbook_list.append((address, label, tx))

    def update_history_tab(self):
        cursor = self.history_treeview.get_cursor()[0]
        self.history_list.clear()
        balance = 0 
        for tx in self.wallet.get_tx_history():
            tx_hash = tx['tx_hash']
            if tx['height']:
                conf = self.wallet.blocks - tx['height'] + 1
                time_str = datetime.datetime.fromtimestamp( tx['nTime']).isoformat(' ')[:-3]
                conf_icon = gtk.STOCK_APPLY
            else:
                conf = 0
                time_str = 'pending'
                conf_icon = gtk.STOCK_EXECUTE
            v = tx['value']
            balance += v 
            label = self.wallet.labels.get(tx_hash)
            is_default_label = (label == '') or (label is None)
            if is_default_label: label = tx['default_label']
            tooltip = tx_hash + "\n%d confirmations"%conf 

            tx = self.wallet.tx_history.get(tx_hash)
            details = "Transaction Details:\n\n"
            details+= "Transaction ID:\n" + tx_hash + "\n\n"
            details+= "Status: %d confirmations\n\n"%conf
            details+= "Date: %s\n\n"%time_str
            details+= "Inputs:\n-"+ '\n-'.join(tx['inputs']) + "\n\n"
            details+= "Outputs:\n-"+ '\n-'.join(tx['outputs'])

            self.history_list.prepend( [tx_hash, conf_icon, time_str, label, is_default_label,
                                        ('+' if v>0 else '') + format_satoshis(v), format_satoshis(balance), tooltip, details] )
        if cursor: self.history_treeview.set_cursor( cursor )



    def newaddress_dialog(self, w, is_recv):

        if not is_recv:

            title = "New sending address" 
            dialog = gtk.Dialog(title, parent=self.window, 
                                flags=gtk.DIALOG_MODAL|gtk.DIALOG_NO_SEPARATOR, 
                                buttons= ("cancel", 0, "ok",1)  )
            dialog.show()

            label = gtk.HBox()
            label_label = gtk.Label('Label:')
            label_label.set_size_request(120,10)
            label_label.show()
            label.pack_start(label_label)
            label_entry = gtk.Entry()
            label_entry.show()
            label.pack_start(label_entry)
            label.show()
            dialog.vbox.pack_start(label, False, True, 5)

            address = gtk.HBox()
            address_label = gtk.Label('Address:')
            address_label.set_size_request(120,10)
            address_label.show()
            address.pack_start(address_label)
            address_entry = gtk.Entry()
            address_entry.show()
            address.pack_start(address_entry)
            address.show()
            dialog.vbox.pack_start(address, False, True, 5)

            result = dialog.run()
            address = address_entry.get_text()
            label = label_entry.get_text()
            dialog.destroy()

            if result == 1:
                if self.wallet.is_valid(address):
                    self.wallet.addressbook.append(address)
                    if label:  self.wallet.labels[address] = label
                    self.wallet.save()
                    self.update_sending_tab()
                else:
                    errorDialog = gtk.MessageDialog(
                        parent=self.window,
                        flags=gtk.DIALOG_MODAL, 
                        buttons= gtk.BUTTONS_CLOSE, 
                        message_format = "Invalid address")
                    errorDialog.show()
                    errorDialog.run()
                    errorDialog.destroy()
        else:
                password = password_dialog() if self.wallet.use_encryption else None
                success, ret = self.wallet.get_new_address(password)
                self.wallet.new_session() # we created a new address
                if success:
                    address = ret
                    #if label:  self.wallet.labels[address] = label
                    self.wallet.save()
                    self.update_receiving_tab()
                else:
                    msg = ret
                    errorDialog = gtk.MessageDialog(
                        parent=self.window,
                        flags=gtk.DIALOG_MODAL, 
                        buttons= gtk.BUTTONS_CLOSE, 
                        message_format = msg)
                    errorDialog.show()
                    errorDialog.run()
                    errorDialog.destroy()
    
    def network_dialog( self, w ):
        wallet = self.wallet
        image = gtk.Image()
        if self.is_connected:
            image.set_from_stock(gtk.STOCK_YES, gtk.ICON_SIZE_MENU)
            status = "Connected to %s.\n%d blocks\nresponse time: %f"%(wallet.host, wallet.blocks, wallet.rtime)
        else:
            image.set_from_stock(gtk.STOCK_FALSE, gtk.ICON_SIZE_MENU)
            status = "Not connected"

        dialog = gtk.MessageDialog( self.window, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                                    gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL, status)
        dialog.set_title("Server")
        dialog.set_image(image)
        image.show()
        dialog.set_default_response(gtk.RESPONSE_OK)
    
        vbox = dialog.vbox
        host = gtk.HBox()
        host_label = gtk.Label('Connect to:')
        host_label.set_size_request(100,-1)
        host_label.show()
        host.pack_start(host_label, False, False, 10)
        host_entry = gtk.Entry()
        host_entry.set_size_request(200,-1)
        host_entry.set_text(wallet.host+":%d"%wallet.port)
        host_entry.show()
        host.pack_start(host_entry, False, False, 10)
        add_help_button(host, 'The name and port number of your Electrum server, separated by a colon. Example: "ecdsa.org:50000". If no port number is provided, the http port 80 will be tried.')
        host.show()
        
        server_list = gtk.ListStore(str)
        for item in wallet.servers:
            server_list.append([item])
    
        treeview = gtk.TreeView(model=server_list)
        treeview.show()

        tvcolumn = gtk.TreeViewColumn('Active servers')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 0)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scroll.add(treeview)
        scroll.show()

        vbox.pack_start(host, False,False, 5)
        vbox.pack_start(scroll)

        def my_treeview_cb(treeview, path, view_column):
            host = server_list.get_value( server_list.get_iter(path), 0)
            host_entry.set_text(host+":50000")
        treeview.connect('row-activated', my_treeview_cb)

        dialog.show()
        r = dialog.run()
        hh = host_entry.get_text()
        dialog.destroy()
        if r==gtk.RESPONSE_CANCEL:
            return
        print hh
        try:
            if ':' in hh:
                host, port = hh.split(':')
                port = int(port)
            else:
                host = hh
                port = 50000
        except:
            show_message("error")
            return

        wallet.host = host
        wallet.port = port
        wallet.save()


    def main(self):
        gtk.main()

