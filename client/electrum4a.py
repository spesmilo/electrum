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


import datetime






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



def qr_code_layout(addr):
    return """<html>
  <head>
    <title>QR code</title>
       <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.2/jquery.min.js"></script>
       <script type="text/javascript" src="http://ecdsa.org/jquery.qrcode.min.js"></script>
       <script>
	  var address = '%s';
          var droid = new Android();
          var cb = function() {
            droid.eventPost("main", "");
          }
       </script>
  </head>

  <body>
       <div id="qrcode"></div>
       <div id="address"></div>
       <script> 
          jQuery('#address').html("bitcoin:"+address); 
          jQuery('#qrcode').qrcode("bitcoin:"+address);
      </script>

      <form onsubmit="cb(); return false;">
      <input type="submit" value="Exit" />
      </form>
  </body>
</html>"""%addr


title = """
        <TextView android:id="@+id/titleTextView" 
                android:layout_width="match_parent"
                android:layout_height="100" 
                android:text="Electrum"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center"
                android:textColor="0xff0055ff"
                android:textSize="30" >
        </TextView>
"""

def make_layout(s):
    return """<?xml version="1.0" encoding="utf-8"?>
      <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:id="@+id/background"
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="match_parent" 
        android:background="#ff000022">
        %s
        %s
      </LinearLayout>"""%(title,s)


def main_layout():
    return """<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:orientation="vertical" 
        android:background="#ff000022"
    android:layout_width="match_parent" 
    android:layout_height="match_parent">

<ScrollView 
        android:id="@+id/background"
        android:layout_width="match_parent"
        android:layout_height="match_parent" >

<LinearLayout
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="wrap_content" >

        %s

        <TextView android:id="@+id/balanceTextView" 
                android:layout_width="match_parent"
                android:layout_height="wrap_content" 
                android:text=""
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="left"
                android:textColor="0xffffffff"
                android:padding="10"
                android:textSize="18" >
        </TextView>


        <TextView android:id="@+id/historyTextView" 
                android:layout_width="match_parent"
                android:layout_height="70" 
                android:text="Recent transactions"
                android:textAppearance="?android:attr/textAppearanceLarge" 
                android:gravity="center_vertical|center_horizontal|center">
        </TextView>

        %s

</LinearLayout>
</ScrollView>
</LinearLayout>
"""%(title, get_history_layout(15))



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
                android:tag="Tag Me" android:inputType="textCapWords|textPhonetic|number">
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
                android:tag="Tag Me" android:inputType="textCapWords|textPhonetic|number">
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
        </LinearLayout>""")



settings_layout = make_layout("""

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
                android:inputType="textCapWords|textPhonetic|number">
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


        <Button android:id="@+id/buttonSave" android:layout_width="wrap_content"
                android:layout_height="wrap_content" android:text="Save"></Button>

""")



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

        label = line.get('label')
        #if not label: label = line['tx_hash']
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
        color = "0xff00ff00" if a == 'v' else "0xffff0000"
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
            droid.fullSetProperty("hl_%d_col1"%i, "textColor","0xff00ff00")
        else:
            droid.fullSetProperty("hl_%d_col1"%i, "textColor","0xffff0000")

        droid.fullSetProperty("hl_%d_col2"%i,"text", b)
        droid.fullSetProperty("hl_%d_col3"%i,"text", c)
        droid.fullSetProperty("hl_%d_col4"%i,"text", d)

        i += 1



def update_layout():

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

    droid.fullSetProperty("balanceTextView", "text", text)

    if wallet.was_updated and wallet.up_to_date:
        global first_time_update
        if not first_time_update:
            droid.vibrate()
        else:
            first_time_update = False
        wallet.was_updated = False
        set_history_layout(15)




def pay_to(recipient, amount, fee, label):

    if wallet.use_encryption:
        password  = droid.dialogGetPassword('Password').result
        print "password", password
    else:
        password = None

    droid.dialogCreateSpinnerProgress("Electrum", "signing transaction...")
    droid.dialogShow()
    tx = wallet.mktx( recipient, amount, label, password, fee)
    print tx
    droid.dialogDismiss()

    if tx:
        r, h = wallet.sendtx( tx )
        droid.dialogCreateAlert('tx sent', h)
        droid.dialogSetPositiveButtonText('OK')
        droid.dialogShow()
        response = droid.dialogGetResponse().result
        droid.dialogDismiss()
        return h
    else:
        return 'error'






def recover():
    droid.dialogCreateAlert("wallet file not found")
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogShow()
    resp = droid.dialogGetResponse().result
    print resp

    code = droid.scanBarcode()
    r = code.result
    if r:
        seed = r['extras']['SCAN_RESULT']
    else:
        exit(1)

    droid.dialogCreateAlert('seed', seed)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse().result
    droid.dialogDismiss()
    print response

    wallet.seed = str(seed)
    wallet.init_mpk( wallet.seed )
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
        droid.dialogCreateAlert("recovery successful")
        droid.dialogShow()
        wallet.save()
    else:
        droid.dialogCreateSpinnerProgress("wallet not found")
        droid.dialogShow()



def make_new_contact():
    code = droid.scanBarcode()
    r = code.result
    if r:
        address = r['extras']['SCAN_RESULT']
        if address:
            if wallet.is_valid(address):
                droid.dialogCreateAlert('Add to contacts?', address)
                droid.dialogSetPositiveButtonText('OK')
                droid.dialogSetNegativeButtonText('Cancel')
                droid.dialogShow()
                response = droid.dialogGetResponse().result
                droid.dialogDismiss()
                print response
                if response.get('which') == 'positive':
                    wallet.addressbook.append(address)
                    wallet.save()
        else:
            droid.dialogCreateAlert('Invalid address', address)
            droid.dialogSetPositiveButtonText('OK')
            droid.dialogShow()
            response = droid.dialogGetResponse().result
            droid.dialogDismiss()


def main_loop():
    update_layout()
    out = None
    while out is None:

        event = droid.eventWait(1000).result  # wait for 1 second
        if not event:
            update_layout()
            continue

        print "got event in main loop", event

        if event["name"]=="click":
            id=event["data"]["id"]

        elif event["name"]=="settings":
            out = 'settings'

        elif event["name"]=="key":
            if event["data"]["key"] == '4':
                out = 'quit'

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
                fee    = '0.001'
                amount = int( 100000000 * Decimal(amount) )
                fee    = int( 100000000 * Decimal(fee) )
                result = pay_to(recipient, amount, fee, label)

                droid.dialogCreateAlert('result', result)
                droid.dialogSetPositiveButtonText('OK')
                droid.dialogShow()
                droid.dialogGetResponse()
                droid.dialogDismiss()
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
        out = 'main'
    return out

def contacts_loop():
    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event
        out = 'main'
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


def protocol_dialog(plist):
    options=["TCP","HTTP","native"]
    droid.dialogCreateAlert("Protocol")
    droid.dialogSetSingleChoiceItems(options)



def settings_loop():
    droid.fullSetProperty("server","text",wallet.server)

    out = None
    while out is None:
        event = droid.eventWait().result
        print "got event", event

        if event["name"] == "click":

            id = event["data"]["id"]

            if id=="buttonServer":
                plist = {}
                for item in wallet.interface.servers:
                    host, pp = item
                    z = {}
                    for item2 in pp:
                        protocol, port = item2
                        z[protocol] = port
                    plist[host] = z

                host = server_dialog(plist)
                if host:
                    p = plist[host]
                    port = p['t']
                    srv = host + ':' + port + ':t'
                    droid.fullSetProperty("server","text",srv)

            elif id=="buttonSave":
                droid.fullQuery()
                srv = droid.fullQueryDetail("server").result.get('text')
                try:
                    wallet.set_server(srv)
                    out = 'main'
                except:
                    droid.dialogCreateAlert('error')
                    droid.dialogSetPositiveButtonText('OK')
                    droid.dialogShow()
                    droid.dialogGetResponse()
                    droid.dialogDismiss()
                    
            elif id=="buttonCancel":
                out = 'main'

        elif event["name"] == "key":
            if event["data"]["key"] == '4':
                out = 'main'

        elif event["name"] in menu_commands:
            out = event["name"]

    return out

                

menu_commands = ["send", "receive", "settings", "contacts", "main"]


first_time_update = True
droid = android.Android()
wallet = Wallet()

wallet.set_path("/sdcard/electrum.dat")
wallet.read()
if not wallet.file_exists:
    recover()
    exit(1)
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
    elif s == 'contacts':
        droid.addOptionsMenuItem("Pay to","paytocontact",None,"")
        droid.addOptionsMenuItem("Edit label","editcontact",None,"")
        droid.addOptionsMenuItem("Delete","removecontact",None,"")
    elif s == 'settings':
        droid.addOptionsMenuItem("Save","save",None,"")
        droid.addOptionsMenuItem("Cancel","cancel",None,"")
        

    #droid.addOptionsMenuItem("Quit","quit",None,"")


while True:
    add_menu(s)
    if s == 'main':
        droid.fullShow(main_layout())
        s = main_loop()
        droid.fullDismiss()
    elif s == 'send':
        droid.fullShow(payto_layout)
        s = payto_loop()
        droid.fullDismiss()

    elif s == 'receive':
        f = open('/sdcard/sl4a/scripts/recv.html',"w")
        f.write(qr_code_layout(receive_addr))
        f.close()
        droid.webViewShow("file:///sdcard/sl4a/scripts/recv.html")
        s = receive_loop()

    elif s == 'contacts':
        f = open('/sdcard/sl4a/scripts/recv.html',"w")
        f.write(qr_code_layout(contact_addr))
        f.close()
        droid.webViewShow("file:///sdcard/sl4a/scripts/recv.html")
        s = contacts_loop()

    elif s == 'settings':
        droid.fullShow(settings_layout)
        s = settings_loop()
        droid.fullDismiss()
    else:
        break

droid.makeToast("Bye!")
