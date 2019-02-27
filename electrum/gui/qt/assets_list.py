#!/usr/bin/env python
#
# Electrum - lightweight Ocean client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from .util import *
from electrum.i18n import _
import requests
import json
from electrum import bitcoin, ecc
import base64

class AssetsList(MyTreeWidget):

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Serial No.'), _('Year'), _('Manufacturer'), _('Asset Fine Mass'), _('Mass Owned'), _('Fraction')],2)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.url = 'https://s3.eu-west-2.amazonaws.com/cb-mapping/map.json'
        getmap = requests.request('GET', self.url, timeout=10)
        self.amap = getmap.json()
        self.controller_pubkeys = []
        self.controller_pubkeys.append("045cb05851130ee7aa09ca43dae988d36ab6b8dbb06dd3948295b919084056d4ce2f2438add60811f7cb7898e17890dcfa4246309f17a7b2b14446d5e3d25b5bc9")
        self.controller_pubkeys.append("04925c07cdc8b04b6f4ab84e6e120648d91517911d2a28decf9ad37cae333413a58975c89eeec3fac0b576b23927df84bc6093d2e8c997effd928cd7defa627db7")
        self.controller_pubkeys.append("04de3441f8a7ecb17417cc764143bda6f19ee5dc85de94534af5a411cd6ef12b59054419dbbc46c139787fce75f1be9901a8e0aadcfd2462c3fafba995d342483e")
        self.verified = self.verify_mapping_sig()

    def on_update(self):
        self.wallet = self.parent.wallet
        tokrat = token_ratio(self.wallet.get_block_height())
        tokens = {}
        ownassets = {}
        item = self.currentItem()
        self.clear()
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            asset = x.get('asset')
            amount = float(x['value'])
            if asset in ownassets:
                tokens[asset] += amount
            else:
                tokens[asset] = amount

        for tokenid in tokens:
            for i,j in self.amap["assets"].items():
                if j["tokenid"] == tokenid:
                    if j["ref"] in ownassets:
                        ownassets[j["ref"]] += tokens[tokenid]
                    else:
                        ownassets[j["ref"]] = tokens[tokenid]
                    if j["mass"] < tokens[tokenid]*tokrat/1.0E+8:
                        tokens[tokenid] -= j["mass"]*1.0E+8/tokrat
                    else:
                        tokens[tokenid] = 0

        for myasset in ownassets:
            rmass = str("%.4f" % (float(ownassets[myasset])*tokrat/1.0E+8))+" oz "
            tmass = str("%.4f" % (float(self.get_mass_assetid(myasset))))+" oz "
            fraction = 100*(float(ownassets[myasset])*tokrat/1.0E+8)/float(self.get_mass_assetid(myasset))
            fraction_str = str("%.4f" % fraction)+" %"
            asset_ref = myasset.split("-")
            if len(asset_ref) != 3: return
            asset_item = SortableTreeWidgetItem([asset_ref[0], asset_ref[1], asset_ref[2], tmass, rmass, fraction_str])
            asset_item.setFont(0, QFont(MONOSPACE_FONT))
            asset_item.setFont(1, QFont(MONOSPACE_FONT))
            asset_item.setFont(2, QFont(MONOSPACE_FONT))
            asset_item.setFont(3, QFont(MONOSPACE_FONT))
            asset_item.setFont(4, QFont(MONOSPACE_FONT))
            self.addChild(asset_item)

    def create_menu(self, position):
        selected = [x.data(0, Qt.UserRole) for x in self.selectedItems()]
        if not selected:
            return
        menu = QMenu()
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False

    def verify_mapping_sig(self):
        nsig = len(self.amap["sigs"])
        if nsig < self.amap["n"]:
            return False
        jsonstring = json.dumps(self.amap["assets"],sort_keys=True)
        jsonstring += str(self.amap["n"]) + str(self.amap["m"]) + str(self.amap["time"]) + str(self.amap["height"])
        message = jsonstring.encode('utf-8')
        nvalid = 0
        for key in self.controller_pubkeys:
            for i,j in self.amap["sigs"].items():
                txin_type = 'p2pkh'
                address = bitcoin.pubkey_to_address(txin_type, key)
                sig = base64.b64decode(j)
                verified = ecc.verify_message_with_address(address, sig, message)
                if verified: nvalid += 1
        if nvalid >= self.amap["n"]:
            return True
        else:
            return False

    def get_mass_assetid(self,assetid):
        tmass = 0.0
        for i,j in self.amap["assets"].items():
            if j["ref"] == assetid:
                tmass += j["mass"]
        return tmass

