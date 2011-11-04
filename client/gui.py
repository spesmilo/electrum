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
import thread, time, ast
import pygtk
pygtk.require('2.0')
import gtk, gobject

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

def init_wallet(wallet):

    if not wallet.read():
        passphrase = None
        while not passphrase:
            dialog = gtk.MessageDialog(
                parent = None,
                flags = gtk.DIALOG_MODAL, 
                buttons = gtk.BUTTONS_OK_CANCEL, 
                message_format = "Wallet not found. Please enter a passphrase to create or recover your wallet. Minimum length: 20 characters"  )
            
            p_box = gtk.HBox()
            p_label = gtk.Label('Passphrase:')
            p_label.show()
            p_box.pack_start(p_label)
            p_entry = gtk.Entry()
            p_entry.show()
            p_box.pack_start(p_entry)
            p_box.show()
            dialog.vbox.pack_start(p_box, False, True, 0)
            
            dialog.show()
            r = dialog.run()
            passphrase = p_entry.get_text()
            dialog.destroy()
            if r==-6: exit(1)
            if len(passphrase) < 20:
                print len(passphrase)
                passphrase = None

        # disable password during recovery
        # change_password_dialog(None, wallet)

        wallet.passphrase = passphrase

        run_settings_dialog( None, wallet, True)

        dialog = gtk.MessageDialog(
            parent = None,
            flags = gtk.DIALOG_MODAL, 
            buttons = gtk.BUTTONS_CANCEL, 
            message_format = "Please wait..."  )
        dialog.show()

        def recover_thread( wallet, dialog, password ):
            wallet.recover( password )
            wallet.save()
            gobject.idle_add( dialog.destroy )

        thread.start_new_thread( recover_thread, ( wallet, dialog, None ) ) # no password
        r = dialog.run()
        dialog.destroy()
        if r==-6: exit(1)

def settings_dialog(wallet, is_recover):

    dialog = gtk.MessageDialog(
        parent = None,
        flags = gtk.DIALOG_MODAL, 
        buttons = gtk.BUTTONS_OK_CANCEL, 
        message_format = "Please indicate the server, and the gap limit if you are recovering a lost wallet." if is_recover else '' )

    if not is_recover:
        dialog.get_image().hide()
        dialog.set_title("settings")

    pw = gtk.HBox()
    if not is_recover:
        pw_label = gtk.Label('Encryption: ')
        pw_label.set_size_request(100,10)
        pw_label.show()
        pw.pack_start(pw_label,False, False, 10)
        pw_button = gtk.Button( ('Yes' if wallet.use_encryption else 'No'))
        pw_button.connect("clicked", change_password_dialog, wallet)
        pw_button.show()
        pw.pack_start(pw_button,False, False, 10)
        pw.show()

    gap = gtk.HBox()
    gap_label = gtk.Label('Max. gap:')
    gap_label.set_size_request(100,10)
    gap_label.show()
    gap.pack_start(gap_label,False, False, 10)
    gap_entry = gtk.Entry()
    gap_entry.set_text("%d"%wallet.gap_limit)
    gap_entry.connect('changed', numbify, True)
    gap_entry.show()
    gap.pack_start(gap_entry,False,False, 10)
    add_help_button(gap, 'The maximum gap that is allowed between unused addresses in your wallet. During wallet recovery, this parameter is used to decide when to stop the recovery process. If you increase this value, you will need to remember it in order to be able to recover your wallet from passphrase.')
    gap.show()

    host = gtk.HBox()
    host_label = gtk.Label('Server:')
    host_label.set_size_request(100,10)
    host_label.show()
    host.pack_start(host_label,False, False, 10)
    host_entry = gtk.Entry()
    host_entry.set_text(wallet.host+":%d"%wallet.port)
    host_entry.show()
    host.pack_start(host_entry,False,False, 10)
    add_help_button(host, 'The name and port number of your Bitcoin server, separated by a colon. Example: ecdsa.org:50000')
    host.show()

    fee = gtk.HBox()
    fee_entry = gtk.Entry()
    if not is_recover:
        fee_label = gtk.Label('Tx. fee:')
        fee_label.set_size_request(100,10)
        fee_label.show()
        fee.pack_start(fee_label,False, False, 10)
        fee_entry.set_text("%f"%(wallet.fee))
        fee_entry.connect('changed', numbify, False)
        fee_entry.show()
        fee.pack_start(fee_entry,False,False, 10)
        add_help_button(fee, 'Transaction fee. Recommended value:0.005')
        fee.show()

    vbox = dialog.vbox
    vbox.pack_start(pw, False, False, 5)
    vbox.pack_start(host, False,False, 5)
    vbox.pack_start(gap, False,False, 5)
    vbox.pack_start(fee, False, False, 5)    
    return dialog, gap_entry, host_entry, fee_entry


def run_settings_dialog( widget, wallet, is_recovery):
    dialog, gap_entry, host_entry, fee_entry = settings_dialog(wallet, is_recovery)
    dialog.show()
    r = dialog.run()
    gap = gap_entry.get_text()
    hh = host_entry.get_text()
    fee = fee_entry.get_text()
    dialog.destroy()
    if r==-6:
        if is_recovery: 
            exit(1)
        else:
            return
    try:
        a, b = hh.split(':')
        wallet.gap_limit = int(gap)
        wallet.host = a
        wallet.port = int(b)
        wallet.fee = float(fee)
    except:
        pass


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
    password_entry.set_visibility(False)
    password_entry.show()
    password.pack_start(password_entry,False,False, 10)
    password.show()
    return password, password_entry

def password_dialog():
    dialog = gtk.MessageDialog( None, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                                gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL,  "Your wallet is encrypted.")
    dialog.get_image().set_visible(False)
    current_pw, current_pw_entry = password_line('Password:')
    current_pw_entry.connect("activate", lambda entry, dialog, response: dialog.response(response), dialog, gtk.RESPONSE_OK)
    dialog.vbox.pack_start(current_pw, False, True, 0)
    dialog.show()
    result = dialog.run()
    pw = current_pw_entry.get_text()
    dialog.destroy()
    if result: return pw

def change_password_dialog(button, wallet):
    dialog = gtk.MessageDialog( None, gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                                gtk.MESSAGE_QUESTION, gtk.BUTTONS_OK_CANCEL,  'Change password')
    if wallet.use_encryption:
        current_pw, current_pw_entry = password_line('Old password:')
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
    if result == 0: 
        return

    try:
        passphrase = wallet.pw_decode( wallet.passphrase, password)
        private_keys = ast.literal_eval( wallet.pw_decode( wallet.private_keys, password) )
    except:
        show_message("sorry")
        return

    if new_password != new_password2:
        show_message("passwords do not match")
        return

    wallet.use_encryption = (new_password != '')
    wallet.passphrase = wallet.pw_encode( passphrase, new_password)
    wallet.private_keys = wallet.pw_encode( repr( private_keys ), new_password)
    wallet.save()
    if button:
        button.set_label('Yes' if wallet.use_encryption else 'No')


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
        self.wallet = wallet

        self.update_time = 0 
        self.window = MyWindow(gtk.WINDOW_TOPLEVEL)
        self.window.set_title(APP_NAME)
        self.window.connect("destroy", gtk.main_quit)
        self.window.set_border_width(0)
        self.window.connect('mykeypress', gtk.main_quit)
        self.window.set_default_size(650, 350)

        vbox = gtk.VBox()

        self.notebook = gtk.Notebook()
        self.create_history_tab()
        self.create_send_tab()
        self.create_recv_tab()
        self.create_book_tab()

        #self.add_tab( make_settings_box( self.wallet, False), 'Preferences')
        self.create_about_tab()

        self.notebook.show()
        vbox.pack_start(self.notebook, True, True, 2)
        
        # status bar for balance, connection, blocks
        self.status_bar = gtk.Statusbar()
        vbox.pack_start(self.status_bar, False, False, 0)

        self.status_image = gtk.Image()
        self.status_image.set_from_stock(gtk.STOCK_YES, gtk.ICON_SIZE_MENU)
        self.status_image.set_alignment(True, 0.5  )
        self.status_image.show()
        self.status_bar.pack_end(self.status_image,False,False)

        settings_icon = gtk.Image()
        settings_icon.set_from_stock(gtk.STOCK_PREFERENCES, gtk.ICON_SIZE_MENU)
        settings_icon.set_alignment(True, False)
        settings_icon.set_size_request(30,9 )
        settings_icon.show()

        prefs_button = gtk.Button()
        prefs_button.connect("clicked", run_settings_dialog, self.wallet, False)
        prefs_button.add(settings_icon)
        prefs_button.set_tooltip_text("Settings")
        prefs_button.show()
        self.status_bar.pack_end(prefs_button,False,False)

        self.window.add(vbox)
        self.window.show_all()

        self.context_id = self.status_bar.get_context_id("statusbar")
        self.update_status_bar()

        def update_status_bar_thread():
            while True:
                gobject.idle_add( self.update_status_bar )
                time.sleep(0.5)

        def update_wallet_thread():
            import socket, traceback, sys
            while True:
                try:
                    self.wallet.new_session()
                except:
                    self.error = "Not connected"
                    time.sleep(5)
                    continue
                self.info.set_text( self.wallet.message)

                while True:
                    try:
                        u = self.wallet.update()
                    except:
                        self.error = "Not connected"
                        print "error"
                        traceback.print_exc(file=sys.stdout)
                        break
                    self.update_time = time.time()
                    self.error = ''
                    if u:
                        self.wallet.save()
                        gobject.idle_add( self.update_history_tab )
                    time.sleep(5)
                    
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
        self.add_tab(page, 'Board')

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

        status, msg = self.wallet.send( to_address, amount, label, password )
        if status:
            show_message( "payment sent.\n" + msg )
            payto_entry.set_text("")
            label_entry.set_text("")
            amount_entry.set_text("")
        else:
            show_message( msg )


    def treeview_key_press(self, treeview, event):
        c = treeview.get_cursor()[0]
        if event.keyval == gtk.keysyms.Up:
            if c and c[0] == 0:
                treeview.parent.grab_focus()
                treeview.set_cursor((0,))
        elif event.keyval == gtk.keysyms.Return and treeview == self.history_treeview:
            tx_hash = self.history_list.get_value( self.history_list.get_iter(c), 0)
            tx = self.wallet.tx_history.get(tx_hash)
            # print "tx details:\n"+repr(tx)
            inputs = '\n-'.join(tx['inputs'])
            outputs = '\n-'.join(tx['outputs'])
            msg = tx_hash + "\n\ninputs:\n-"+ inputs + "\noutputs:\n-"+ outputs + "\n"
            show_message(msg)
        return False

    def create_history_tab(self):

        self.history_list = gtk.ListStore(str, str, str, str, 'gboolean',  str, str,str)
        treeview = gtk.TreeView(model=self.history_list)
        self.history_treeview = treeview
        treeview.set_tooltip_column(7)
        treeview.show()
        treeview.connect('key-press-event', self.treeview_key_press)

        tvcolumn = gtk.TreeViewColumn('tx_id')
        treeview.append_column(tvcolumn)
        cell = gtk.CellRendererText()
        tvcolumn.pack_start(cell, False)
        tvcolumn.add_attribute(cell, 'text', 0)
        tvcolumn.set_visible(False)

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

        button = gtk.Button("Copy to clipboard")
        def copy2clipboard(w, treeview, liststore):
            path, col =  treeview.get_cursor()
            if path:
                address =  liststore.get_value( liststore.get_iter(path), 0)
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
        dt = time.time() - self.update_time
        if dt < 15:
            self.status_image.set_from_stock(gtk.STOCK_YES, gtk.ICON_SIZE_MENU)
            self.status_image.set_tooltip_text("Connected to %s.\n%d blocks"%(self.wallet.host, self.wallet.blocks))
        else:
            self.status_image.set_from_stock(gtk.STOCK_NO, gtk.ICON_SIZE_MENU)
            self.status_image.set_tooltip_text("Trying to contact %s.\n%d blocks"%(self.wallet.host, self.wallet.blocks))
        text =  "Balance: %s "%( format_satoshis(c) )
        if u: text +=  "[+ %s unconfirmed]"%( format_satoshis(u) )
        if self.error: text = self.error
        self.status_bar.pop(self.context_id) 
        self.status_bar.push(self.context_id, text) 

    def update_receiving_tab(self):
        self.recv_list.clear()
        for address in self.wallet.addresses:
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
            self.history_list.prepend( [tx_hash, conf_icon, time_str, label, is_default_label, 
                                        ('+' if v>0 else '') + format_satoshis(v), format_satoshis(balance), tooltip] )
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
    
    def main(self):
        gtk.main()

