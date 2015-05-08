#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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




from __future__ import absolute_import

import android
import sys
import os
import imp
import base64

script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(script_dir, 'packages'))

import qrcode

imp.load_module('electrum_ltc', *imp.find_module('lib'))

from electrum_ltc import SimpleConfig, Wallet, WalletStorage, format_satoshis
from electrum_ltc import util
from electrum_ltc.transaction import Transaction
from electrum_ltc.bitcoin import base_encode, base_decode

def modal_dialog(title, msg = None):
    droid.dialogCreateAlert(title,msg)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogShow()
    droid.dialogGetResponse()
    droid.dialogDismiss()

def modal_input(title, msg, value = None, etype=None):
    droid.dialogCreateInput(title, msg, value, etype)
    droid.dialogSetPositiveButtonText('OK')
    droid.dialogSetNegativeButtonText('Cancel')
    droid.dialogShow()
    response = droid.dialogGetResponse()
    result = response.result
    droid.dialogDismiss()

    if result is None:
        return modal_input(title, msg, value, etype)

    if result.get('which') == 'positive':
        return result.get('value')

def modal_question(q, msg, pos_text = 'OK', neg_text = 'Cancel'):
    droid.dialogCreateAlert(q, msg)
    droid.dialogSetPositiveButtonText(pos_text)
    droid.dialogSetNegativeButtonText(neg_text)
    droid.dialogShow()
    response = droid.dialogGetResponse()
    result = response.result
    droid.dialogDismiss()

    if result is None:
        return modal_question(q, msg, pos_text, neg_text)

    return result.get('which') == 'positive'





def make_layout(s):
    content = """

      <LinearLayout 
        android:id="@+id/zz"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" 
        android:background="#ff222222">

        <TextView
          android:id="@+id/textElectrum"
          android:text="Electrum-LTC Authenticator"
          android:textSize="7pt"
          android:textColor="#ff4444ff"
          android:gravity="left"
          android:layout_height="wrap_content"
          android:layout_width="match_parent"
        />
      </LinearLayout>

        %s   """%s


    return """<?xml version="1.0" encoding="utf-8"?>
      <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
        android:id="@+id/background"
        android:orientation="vertical" 
        android:layout_width="match_parent"
        android:layout_height="match_parent" 
        android:background="#ff000022">

      %s 
      </LinearLayout>"""%content






def qr_layout(title):
    title_view= """
    <TextView android:id="@+id/addrTextView"
    android:layout_width="match_parent"
    android:layout_height="50"
    android:text="%s"
    android:textAppearance="?android:attr/textAppearanceLarge"
    android:gravity="center_vertical|center_horizontal|center">
    </TextView>"""%title

    image_view="""
    <ImageView
    android:id="@+id/qrView"
    android:gravity="center"
    android:layout_width="match_parent"
    android:antialias="false"
    android:src=""
    />
    """
    return make_layout(title_view + image_view)










def add_menu():
    droid.clearOptionsMenu()
    droid.addOptionsMenuItem("Seed", "seed", None,"")
    droid.addOptionsMenuItem("Public Key", "xpub", None,"")
    droid.addOptionsMenuItem("Transaction", "scan", None,"")
    droid.addOptionsMenuItem("Password", "password", None,"")



def make_bitmap(data):
    # fixme: this is highly inefficient
    import qrcode
    from electrum_ltc import bmp
    qr = qrcode.QRCode()
    qr.add_data(data)
    bmp.save_qrcode(qr,"/sdcard/sl4a/qrcode.bmp")


droid = android.Android()
wallet = None

class Authenticator:

    def __init__(self):
        global wallet
        self.qr_data = None
        storage = WalletStorage('/sdcard/electrum-ltc/authenticator')
        if not storage.file_exists:

            action = self.restore_or_create()
            if not action:
                exit()
            password = droid.dialogGetPassword('Choose a password').result
            if password:
                password2 = droid.dialogGetPassword('Confirm password').result
                if password != password2:
                    modal_dialog('Error', 'Passwords do not match')
                    exit()
            else:
                password = None
            if action == 'create':
                wallet = Wallet(storage)
                seed = wallet.make_seed()
                modal_dialog('Your seed is:', seed)
            elif action == 'import':
                seed = self.seed_dialog()
                if not seed:
                    exit()
                if not Wallet.is_seed(seed):
                    exit()
                wallet = Wallet.from_seed(seed, storage)
            else:
                exit()

            wallet.add_seed(seed, password)
            wallet.create_master_keys(password)
            wallet.create_main_account(password)
        else:
            wallet = Wallet(storage)

    def restore_or_create(self):
        droid.dialogCreateAlert("Seed not found", "Do you want to create a new seed, or to import it?")
        droid.dialogSetPositiveButtonText('Create')
        droid.dialogSetNeutralButtonText('Import')
        droid.dialogSetNegativeButtonText('Cancel')
        droid.dialogShow()
        response = droid.dialogGetResponse().result
        droid.dialogDismiss()
        if not response: return
        if response.get('which') == 'negative':
            return
        return 'import' if response.get('which') == 'neutral' else 'create'

    def seed_dialog(self):
        if modal_question("Enter your seed", "Input method", 'QR Code', 'mnemonic'):
            code = droid.scanBarcode()
            r = code.result
            if r:
                seed = r['extras']['SCAN_RESULT']
            else:
                return
        else:
            seed = modal_input('Mnemonic', 'Please enter your seed phrase')
        return str(seed)

    def show_qr(self, data):
        path = "/sdcard/sl4a/qrcode.bmp"
        if data:
            droid.dialogCreateSpinnerProgress("please wait")
            droid.dialogShow()
            try:
                make_bitmap(data)
            finally:
                droid.dialogDismiss()
        else:
            with open(path, 'w') as f: f.write('')
        droid.fullSetProperty("qrView", "src", 'file://'+path)
        self.qr_data = data

    def show_title(self, title):
        droid.fullSetProperty("addrTextView","text", title)

    def get_password(self):
        if wallet.use_encryption:
            password = droid.dialogGetPassword('Password').result
            try:
                wallet.check_password(password)
            except:
                return False
            return password

    def main(self):
        add_menu()
        welcome = 'Use the menu to scan a transaction.'
        droid.fullShow(qr_layout(welcome))
        while True:
            event = droid.eventWait().result
            if not event:
                continue
            elif event["name"] == "key":
                if event["data"]["key"] == '4':
                    if self.qr_data:
                        self.show_qr(None)
                        self.show_title(welcome)
                    else:
                        break

            elif event["name"] == "seed":
                password = self.get_password()
                if password is False:
                    modal_dialog('Error','incorrect password')
                    continue
                seed = wallet.get_mnemonic(password)
                modal_dialog('Your seed is', seed)

            elif event["name"] == "password":
                self.change_password_dialog()

            elif event["name"] == "xpub":
                mpk = wallet.get_master_public_key()
                self.show_qr(mpk)
                self.show_title('master public key')

            elif event["name"] == "scan":
                r = droid.scanBarcode()
                r = r.result
                if not r:
                    continue
                data = r['extras']['SCAN_RESULT']
                data = base_decode(data.encode('utf8'), None, base=43)
                data = ''.join(chr(ord(b)) for b in data).encode('hex')
                tx = Transaction(data)
                #except:
                #    modal_dialog('Error', 'Cannot parse transaction')
                #    continue
                if not wallet.can_sign(tx):
                    modal_dialog('Error', 'Cannot sign this transaction')
                    continue
                lines = map(lambda x: x[0] + u'\t\t' + format_satoshis(x[1]) if x[1] else x[0], tx.get_outputs())
                if not modal_question('Sign?', '\n'.join(lines)):
                    continue
                password = self.get_password()
                if password is False:
                    modal_dialog('Error','incorrect password')
                    continue
                droid.dialogCreateSpinnerProgress("Signing")
                droid.dialogShow()
                wallet.sign_transaction(tx, password)
                droid.dialogDismiss()
                data = base_encode(str(tx).decode('hex'), base=43)
                self.show_qr(data)
                self.show_title('Signed Transaction')

        droid.makeToast("Bye!")


    def change_password_dialog(self):
        if wallet.use_encryption:
            password  = droid.dialogGetPassword('Your seed is encrypted').result
            if password is None:
                return
        else:
            password = None
        try:
            wallet.check_password(password)
        except Exception:
            modal_dialog('Error', 'Incorrect password')
            return
        new_password  = droid.dialogGetPassword('Choose a password').result
        if new_password == None:
            return
        if new_password != '':
            password2  = droid.dialogGetPassword('Confirm new password').result
            if new_password != password2:
                modal_dialog('Error', 'passwords do not match')
                return
        wallet.update_password(password, new_password)
        if new_password:
            modal_dialog('Password updated', 'Your seed is encrypted')
        else:
            modal_dialog('No password', 'Your seed is not encrypted')



if __name__ == "__main__":
    a = Authenticator()
    a.main()
