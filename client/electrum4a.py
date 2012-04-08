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




import android
from interface import WalletSynchronizer
from wallet import Wallet
from wallet import format_satoshis
from decimal import Decimal
import mnemonic

import datetime



def modal_dialog(title, msg = ''):
    droid.dialogCreateAlert(title,msg)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogShow()
    droid.dialogGetResponse()
    droid.dialogDismiss()

def modal_question(q,msg):
    droid.dialogCreateAlert(q, msg)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    droid.dialogDismiss()
    return response.get('which') == 'positive'

def edit_label(addr):
    droid.dialogCreateInput('Edit label',None,wallet.labels.get(addr))
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    droid.dialogDismiss()
    if response.get('which') == 'positive':
        wallet.labels[addr] = response.get('value')
        wallet.update_tx_history()
        wallet.save()
        droid.fullSetProperty("labelTextView", "text", wallet.labels.get(addr))

def select_from_contacts():
    title = 'Contacts:'
    droid.dialogCreateAlert(title)
    droid.dialogSetPositiveButtonText('New contact')
    droid.dialogSetItems(wallet.addressbook)
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    droid.dialogDismiss()

    if response.get('which') == 'positive':
        return 'newcontact'

    result = response.get('item')
    print result
    if result is not None:
        addr = wallet.addressbook[result]
        return addr


def select_from_addresses():
    droid.dialogCreateAlert("Addresses:")
    l = []
    for i in range(len(wallet.addresses)):
        addr = wallet.addresses[i]
        l.append( wallet.labels.get(addr,'') + ' ' + addr)

    droid.dialogSetItems(l)
    droid.dialogShow()
    response = droid.dialogGetResponse()
    result = response.result.get('item')
    droid.dialogDismiss()
    if result is not None:
        addr = wallet.addresses[result]
        return addr


def protocol_dialog(host, z):
    droid.dialogCreateAlert('Protocol',host)
    protocols = z.keys()
    l = []
    for p in protocols:
        if p == 't': l.append('TCP/stratum')
        if p == 'h': l.append('HTTP/Stratum')
        if p == 'n': l.append('TCP/native')
    droid.dialogSetSingleChoiceItems(l)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    if response.get('which') == 'positive':
        response = droid.dialogGetSelectedItems().result[0]
        droid.dialogDismiss()
        p = protocols[response]
        port = z[p]
        return host + ':' + port + ':' + p



def make_layout(s, scrollable = False):
    content = """
     <ImageView
        android:id="@+id/imageView1"
        android:layout_width="match_parent"
        android:gravity="center"
        android:layout_height="wrap_content"
        android:src="file:///sdcard/sl4a/electrum_text_320.png" />

        %s   """%s

    if scrollable:
        content = """
      <ScrollView 
        android:id="@+id/scrollview"
        android:layout_width="match_parent"
        android:layout_height="match_parent" >

      <LinearLayout
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="wrap_content" >

      %s

      </LinearLayout>
      </ScrollView>
      """%content


    return """<?xml version="1.0" encoding="utf-8"?>
      <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:id="@+id/background"
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="match_parent" 
        android:background="#ff000022">

      %s 
      </LinearLayout>"""%content




def main_layout():
    return make_layout("""
        <TextView android:id="@+id/balanceTextView" 
                android:layout_width="match_parent"
                android:layout_height="70" 
                android:text=""
                android:textColor="#ffffffff"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:padding="10"
                android:textSize="6pt"
                android:gravity="center_vertical|center_horizontal|left">
        </TextView>

        <TextView android:id="@+id/historyTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Recent transactions"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
        </TextView>

        %s """%get_history_layout(15),True)



def qr_layout(addr):
    return make_layout("""

     <TextView android:id="@+id/addrTextView" 
                android:layout_width="match_parent"
                android:layout_height="50" 
                android:text="%s"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
     </TextView>

     <ImageView
        android:id="@+id/qrView"
        android:gravity="center"
        android:layout_width="match_parent"
        android:layout_height="350"
        android:antialias="false"
        android:src="file:///sdcard/sl4a/qrcode.bmp" /> 

     <TextView android:id="@+id/labelTextView" 
                android:layout_width="match_parent"
                android:layout_height="50" 
                android:text="%s"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
     </TextView>

     """%(addr,wallet.labels.get(addr,'')), True)

payto_layout = make_layout("""

        <TextView android:id="@+id/recipientTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Pay to:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>


        <EditText android:id="@+id/recipient"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" android:inputType="text">
        </EditText>

        <LinearLayout android:id="@+id/linearLayout1"
                android:layout_width="match_parent"
                android:layout_height="wrap_content">
                <Button android:id="@+id/buttonQR" android:layout_width="wrap_content"
                        android:layout_height="wrap_content" android:text="From QR code"></Button>
                <Button android:id="@+id/buttonContacts" android:layout_width="wrap_content"
                        android:layout_height="wrap_content" android:text="From Contacts"></Button>
        </LinearLayout>


        <TextView android:id="@+id/labelTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Description:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>

        <EditText android:id="@+id/label"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" android:inputType="text">
        </EditText>

        <TextView android:id="@+id/amountLabelTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Amount:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>

        <EditText android:id="@+id/amount"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" android:inputType="numberDecimal">
        </EditText>

        <LinearLayout android:layout_width="match_parent"
                android:layout_height="wrap_content" android:id="@+id/linearLayout1">
                <Button android:id="@+id/buttonPay" android:layout_width="wrap_content"
                        android:layout_height="wrap_content" android:text="Send"></Button>
        </LinearLayout>""",False)



settings_layout = make_layout("""

        <TextView android:id="@+id/serverTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Server:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>

        <EditText android:id="@+id/server"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" 
                android:inputType="text">
        </EditText>

        <LinearLayout android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:id="@+id/linearLayout1">

           <Button android:id="@+id/buttonServer" 
                android:layout_width="wrap_content"
                android:layout_height="wrap_content" 
                android:text="Public servers">
           </Button>
           <Button android:id="@+id/buttonProtocol" 
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="Protocol">
           </Button>

        </LinearLayout>

        <TextView android:id="@+id/feeTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text="Fee:"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left">
        </TextView>

        <EditText android:id="@+id/fee"
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:tag="Tag Me" 
                android:inputType="numberDecimal">
        </EditText>

        <Button android:id="@+id/buttonSave" android:layout_width="wrap_content"
                android:layout_height="wrap_content" android:text="Save"></Button>

""",False)



def get_history_values(n):
    values = []
    h = wallet.get_tx_history()
    for i in range(n):
        line = h[-i-1]
        v = line['value']
        try:
            dt = datetime.datetime.fromtimestamp( line['timestamp'] )
            if dt.date() == dt.today().date():
                time_str = str( dt.time() )
            else:
                time_str = str( dt.date() )
            conf = 'v'

        except:
            print line['timestamp']
            time_str = 'pending'
            conf = 'o'

        tx_hash = line['tx_hash']
        label = wallet.labels.get(tx_hash)
        is_default_label = (label == '') or (label is None)
        if is_default_label: label = line['default_label']
        values.append((conf, '  ' + time_str, '  ' + format_satoshis(v,True), '  ' + label ))

    return values


def get_history_layout(n):
    rows = ""
    i = 0
    values = get_history_values(n)
    for v in values:
        a,b,c,d = v
        color = "#ff00ff00" if a == 'v' else "#ffff0000"
        rows += """
        <TableRow>
          <TextView
            android:id="@+id/hl_%d_col1" 
            android:layout_column="0"
            android:text="%s"
            android:textColor="%s"
            android:padding="3" />
          <TextView
            android:id="@+id/hl_%d_col2" 
            android:layout_column="1"
            android:text="%s"
            android:padding="3" />
          <TextView
            android:id="@+id/hl_%d_col3" 
            android:layout_column="2"
            android:text="%s"
            android:padding="3" />
          <TextView
            android:id="@+id/hl_%d_col4" 
            android:layout_column="3"
            android:text="%s"
            android:padding="4" />
        </TableRow>"""%(i,a,color,i,b,i,c,i,d)
        i += 1

    output = """
<TableLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="fill_parent"
    android:layout_height="wrap_content"
    android:stretchColumns="0,1,2,3">
    %s
</TableLayout>"""% rows
    return output


def set_history_layout(n):
    values = get_history_values(n)
    i = 0
    for v in values:
        a,b,c,d = v
        droid.fullSetProperty("hl_%d_col1"%i,"text", a)

        if a == 'v':
            droid.fullSetProperty("hl_%d_col1"%i, "textColor","#ff00ff00")
        else:
            droid.fullSetProperty("hl_%d_col1"%i, "textColor","#ffff0000")

        droid.fullSetProperty("hl_%d_col2"%i,"text", b)
        droid.fullSetProperty("hl_%d_col3"%i,"text", c)
        droid.fullSetProperty("hl_%d_col4"%i,"text", d)
        i += 1




status_text = ''
def update_layout():
    global status_text
    if not wallet.interface.is_connected:
        text = "Not connected..."
    elif wallet.blocks == 0:
        text = "Server not ready"
    elif not wallet.up_to_date:
        text = "Synchronizing..."
    else:
        c, u = wallet.get_balance()
        text = "Balance:"+format_satoshis(c) 
        if u : text += '   [' + format_satoshis(u,True).strip() + ']'


    # vibrate if status changed
    if text != status_text:
        if status_text and wallet.interface.is_connected and wallet.up_to_date:
            droid.vibrate()
        status_text = text

    droid.fullSetProperty("balanceTextView", "text", status_text)

    if wallet.up_to_date:
        set_history_layout(15)




def pay_to(recipient, amount, fee, label):

    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Password').result
        if not password: return
    else:
        password = None

    droid.dialogCreateSpinnerProgress("Electrum", "signing transaction...")
    droid.dialogShow()

    try:
        tx = wallet.mktx( recipient, amount, label, password, fee)
    except BaseException, e:
        modal_dialog('error', e.message)
        droid.dialogDismiss()
        return

    droid.dialogDismiss()

    r, h = wallet.sendtx( tx )
    if r:
        modal_dialog('Payment sent', h)
        return True
    else:
        modal_dialog('Error', h)





def recover():
    if not modal_question("Wallet not found","restore from seed?"):
        exit(1)

    code = droid.scanBarcode()
    r = code.result
    if r:
        seed = r['extras']['SCAN_RESULT']
    else:
        exit(1)

    if not modal_question('Seed', seed ):
        exit(1)

    wallet.seed = str(seed)
    wallet.init_mpk( wallet.seed )

    change_password_dialog()

    droid.dialogCreateSpinnerProgress("Electrum", "recovering wallet...")
    droid.dialogShow()
    WalletSynchronizer(wallet,True).start()
    wallet.update()
    wallet.save()
    droid.dialogDismiss()
    droid.vibrate()

    if wallet.is_found():
        # history and addressbook
        wallet.update_tx_history()
        wallet.fill_addressbook()
        modal_dialog("recovery successful")
    else:
        if not modal_question("no transactions found for this seed","do you want to keep this wallet?"):
            exit(1)
    wallet.save()



def make_new_contact():
    code = droid.scanBarcode()
    r = code.result
    if r:
        address = r['extras']['SCAN_RESULT']
        if address:
            if wallet.is_valid(address):
                if modal_question('Add to contacts?', address):
                    wallet.addressbook.append(address)
                    wallet.save()
        else:
            modal_dialog('Invalid address', address)


do_refresh = False

def update_callback():
    global do_refresh
    print "gui callback", wallet.interface.is_connected, wallet.up_to_date
    do_refresh = True
    droid.eventPost("refresh",'z')

def main_loop():
    global do_refresh

    update_layout()
    out = None
    quitting = False
    while out is None:

        event = droid.eventWait(1000).result
        if event is None:
            if do_refresh: 
                update_layout()
                do_refresh = False
            continue

        print "got event in main loop", repr(event)
        if event == 'OK': continue
        if event is None: continue
        #if event["name"]=="refresh":


        # request 2 taps before we exit
        if event["name"]=="key":
            if event["data"]["key"] == '4':
                if quitting:
                    out = 'quit'
                else: 
                    quitting = True
        else: quitting = False

        if event["name"]=="click":
            id=event["data"]["id"]

        elif event["name"]=="settings":
            out = 'settings'

        elif event["name"] in menu_commands:
            out = event["name"]

            if out == 'contacts':
                global contact_addr
                contact_addr = select_from_contacts()
                if contact_addr == 'newcontact':
                    make_new_contact()
                    contact_addr = None
                if not contact_addr:
                    out = None

            elif out == "receive":
                global receive_addr
                receive_addr = select_from_addresses()
                if not receive_addr:
                    out = None


    return out
                    

def payto_loop():
    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event in payto loop", event

        if event["name"] == "click":
            id = event["data"]["id"]

            if id=="buttonPay":

                droid.fullQuery()
                recipient = droid.fullQueryDetail("recipient").result.get('text')
                label  = droid.fullQueryDetail("label").result.get('text')
                amount = droid.fullQueryDetail('amount').result.get('text')
                try:
                    amount = int( 100000000 * Decimal(amount) )
                except:
                    modal_dialog('Error','invalid amount')
                    continue

                result = pay_to(recipient, amount, wallet.fee, label)
                if result:
                    out = 'main'

            elif id=="buttonContacts":
                addr = select_from_contacts()
                droid.fullSetProperty("recipient","text",addr)

            elif id=="buttonQR":
                code = droid.scanBarcode()
                r = code.result
                if r:
                    addr = r['extras']['SCAN_RESULT']
                    if addr:
                        droid.fullSetProperty("recipient","text",addr)
                    
        elif event["name"] in menu_commands:
            out = event["name"]

        elif event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'main'

        #elif event["name"]=="screen":
        #    if event["data"]=="destroy":
        #        out = 'main'

    return out


receive_addr = ''
contact_addr = ''


def receive_loop():
    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event
        if event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'main'

        elif event["name"]=="edit":
            edit_label(receive_addr)

    return out

def contacts_loop():
    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event
        if event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'main'

        elif event["name"]=="edit":
            edit_label(contact_addr)

    return out


def server_dialog(plist):
    droid.dialogCreateAlert("servers")
    droid.dialogSetItems( plist.keys() )
    droid.dialogShow()
    i = droid.dialogGetResponse().result.get('item')
    droid.dialogDismiss()
    if i is not None:
        response = plist.keys()[i]
        return response


def seed_dialog():
    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Password').result
        if not password: return
    else:
        password = None
    
    try:
        seed = wallet.pw_decode( wallet.seed, password)
    except:
        modal_dialog('error','incorrect password')
        return

    modal_dialog('Your seed is',seed)
    modal_dialog('Mnemonic code:', ' '.join(mnemonic.mn_encode(seed)) )

def change_password_dialog():
    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Current password').result
        if not password: return
    else:
        password = None

    try:
        seed = wallet.pw_decode( wallet.seed, password)
    except:
        modal_dialog('error','incorrect password')
        return

    new_password  = droid.dialogGetPassword('Choose a password').result
    password2  = droid.dialogGetPassword('Confirm new password').result
    if new_password != password2:
        modal_dialog('error','passwords do not match')
        return

    wallet.update_password(seed, new_password)
    if new_password:
        modal_dialog('Password updated','your wallet is encrypted')
    else:
        modal_dialog('Password removed','your wallet is not encrypted')
        

def settings_loop():
    droid.fullSetProperty("server","text",wallet.server)
    droid.fullSetProperty("fee","text", "%s"% str( Decimal( wallet.fee)/100000000 ) )

    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event

        plist = {}
        for item in wallet.interface.servers:
            host, pp = item
            z = {}
            for item2 in pp:
                protocol, port = item2
                z[protocol] = port
            plist[host] = z


        if event["name"] == "click":
            id = event["data"]["id"]

            if id=="buttonServer":
                host = server_dialog(plist)
                if host:
                    p = plist[host]
                    port = p['t']
                    srv = host + ':' + port + ':t'
                    droid.fullSetProperty("server","text",srv)

            elif id=="buttonProtocol":
                droid.fullQuery()
                srv = droid.fullQueryDetail("server").result.get('text')
                host = srv.split(':')[0]
                if host in plist:
                    server = protocol_dialog(host, plist[host])
                    if server:
                        droid.fullSetProperty("server","text",server)


            elif id=="buttonSave":
                droid.fullQuery()
                srv = droid.fullQueryDetail("server").result.get('text')
                fee = droid.fullQueryDetail("fee").result.get('text')
                try:
                    wallet.set_server(srv)
                except:
                    modal_dialog('error','invalid server')

                try:
                    fee = int( 100000000 * Decimal(fee) )
                    if wallet.fee != fee:
                        wallet.fee = fee
                        wallet.save()
                        out = 'main'
                except:
                    modal_dialog('error','invalid fee value')

        elif event["name"] in menu_commands:
            out = event["name"]

        elif event["name"] == 'password':
            change_password_dialog()

        elif event["name"] == 'seed':
            seed_dialog()

        elif event["name"] == 'cancel':
            out = 'main'

        elif event["name"] == "key":
            if event["data"]["key"] == '4':
                out = 'main'

    return out




menu_commands = ["send", "receive", "settings", "contacts", "main"]
droid = android.Android()
wallet = Wallet(update_callback)

wallet.set_path("/sdcard/electrum.dat")
wallet.read()
if not wallet.file_exists:
    recover()
else:
    WalletSynchronizer(wallet,True).start()


s = 'main'

def add_menu(s):
    droid.clearOptionsMenu()
    if s == 'main':
        droid.addOptionsMenuItem("Send","send",None,"")
        droid.addOptionsMenuItem("Receive","receive",None,"")
        droid.addOptionsMenuItem("Contacts","contacts",None,"")
        droid.addOptionsMenuItem("Settings","settings",None,"")
    elif s == 'receive':
        droid.addOptionsMenuItem("Edit","edit",None,"")
    elif s == 'contacts':
        droid.addOptionsMenuItem("Edit","edit",None,"")
        droid.addOptionsMenuItem("Pay to","paytocontact",None,"")
        droid.addOptionsMenuItem("Delete","removecontact",None,"")
    elif s == 'settings':
        droid.addOptionsMenuItem("Password","password",None,"")
        droid.addOptionsMenuItem("Seed","seed",None,"")

def make_bitmap(addr):
    # fixme: this is highly inefficient
    droid.dialogCreateSpinnerProgress("please wait")
    droid.dialogShow()
    import pyqrnative, bmp
    qr = pyqrnative.QRCode(4, pyqrnative.QRErrorCorrectLevel.H)
    qr.addData(addr)
    qr.make()
    k = qr.getModuleCount()
    bitmap = bmp.BitMap( 35*8, 35*8 )
    print len(bitmap.bitarray)
    bitmap.bitarray = []
    assert k == 33

    for r in range(35):
        tmparray = [ 0 ] * 35*8

        if 0 < r < 34:
            for c in range(k):
                if qr.isDark(r-1, c):
                    tmparray[ (1+c)*8:(2+c)*8] = [1]*8

        for i in range(8):
            bitmap.bitarray.append( tmparray[:] )

    bitmap.saveFile( "/sdcard/sl4a/qrcode.bmp" )
    droid.dialogDismiss()

        

while True:
    add_menu(s)
    if s == 'main':
        droid.fullShow(main_layout())
        s = main_loop()
        #droid.fullDismiss()

    elif s == 'send':
        droid.fullShow(payto_layout)
        s = payto_loop()
        #droid.fullDismiss()

    elif s == 'receive':
        make_bitmap(receive_addr)
        droid.fullShow(qr_layout(receive_addr))
        s = receive_loop()

    elif s == 'contacts':
        make_bitmap(contact_addr)
        droid.fullShow(qr_layout(contact_addr))
        s = contacts_loop()

    elif s == 'settings':
        droid.fullShow(settings_layout)
        s = settings_loop()
        #droid.fullDismiss()
    else:
        break

droid.makeToast("Bye!")
