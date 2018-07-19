#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import json
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *

from .util import ButtonsLineEdit, Buttons, ButtonsTextEdit, CancelButton, MessageBoxMixin, EnterButton
from electrum.i18n import _
from electrum.plugins import run_hook
from electrum.bitcoin import is_contract_address, is_address, b58_address_to_hash160
from electrum.util import bh2u, print_error
import os

float_validator = QRegExpValidator(QRegExp('^(-?\d+)(\.\d{8})?$'))
int_validator = QIntValidator(0, 10 ** 9 - 1)
name_validator = QRegExpValidator(QRegExp('^.{10}$'))


class ContractInfoLayout(QVBoxLayout):
    def __init__(self, dialog, contract, callback):
        QVBoxLayout.__init__(self)
        if not contract:
            contract = {
                'name': '',
                'interface': '',
                'address': ''
            }
        self.contract = contract
        self.callback = callback
        self.dialog = dialog

        self.addWidget(QLabel(_("Contract Name:")))
        self.name_e = ButtonsLineEdit()
        self.name_e.setValidator(name_validator)
        self.addWidget(self.name_e)

        self.addWidget(QLabel(_("Address:")))
        self.address_e = ButtonsLineEdit()
        self.addWidget(self.address_e)

        #self.addWidget(QLabel(_("Interface(ABI):")))
        #self.interface_e = ButtonsTextEdit()
        #self.interface_e.setMinimumHeight(160)
        #self.addWidget(self.interface_e)

        self.cancel_btn = CancelButton(dialog)
        self.save_btn = QPushButton(_('Save'))
        self.save_btn.setDefault(True)
        self.save_btn.clicked.connect(self.save_input)

        self.addLayout(Buttons(*[self.cancel_btn, self.save_btn]))
        self.update()

    def update(self):
        name = self.contract.get('name', '')
        address = self.contract.get('address', '')
        self.name_e.setText(name)
        self.address_e.setText(address)

    def save_input(self):
        address = self.address_e.text()
        address = address.rstrip().lstrip()
        if not is_contract_address(address):
            self.dialog.show_message(_('invalid contract address'))
            return
        name = self.name_e.text()
        name = name.rstrip().lstrip()
        if len(name) > 10:
            self.dialog.show_message(_('name too long'))
            return
        if not name:
            self.dialog.show_message(_('empty name not allowed'))
            return
        self.contract['address'] = address
        self.contract['name'] = name
        self.callback(self.contract)


class ContractEditDialog(QDialog, MessageBoxMixin):
    def __init__(self, parent, contract=None):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Smart Contract'))
        self.setMinimumSize(700, 150)
        self.main_window = parent
        run_hook('contract_edit_dialog', self)
        layout = ContractInfoLayout(self, contract, callback=self.save)
        self.setLayout(layout)

    def save(self, contract):
        if self.parent().set_smart_contract(contract['name'],
                                            contract['address']):
            self.accept()


class ContractFuncLayout(QGridLayout):
    def __init__(self, dialog, contract):
        QGridLayout.__init__(self)
        self.setSpacing(8)
        self.setColumnStretch(3, 1)
        self.dialog = dialog
        self.contract = contract
        self.senders = self.dialog.parent().wallet.get_spendable_addresses()
        self.withdraw_infos=None
        self.withdraw_froms=None

        address_lb = QLabel(_("Address:"))
        self.address_e = ButtonsLineEdit()
        qr_show = lambda: dialog.parent().show_qrcode(str(self.address_e.text()), 'Address', parent=dialog)
        self.address_e.addButton(":icons/qrcode.png", qr_show, _("Show as QR code"))
        self.address_e.setText(self.contract['address'])
        self.address_e.setReadOnly(True)
        self.addWidget(address_lb, 1, 0)
        self.addWidget(self.address_e, 1, 1, 1, -1)

        abi_lb = QLabel(_('Function:'))
        self.abi_combo = QComboBox()

        self.abi_signatures = [(-1, "(transferTo)"), ]
        for index, abi in enumerate(contract.get('interface', [])):
            if abi.get("name") in ["init","on_deposit","on_upgrade","on_destroy"]:
                continue

            self.abi_signatures.append((index, abi.get("name")))

        self.abi_combo.addItems([s[1] for s in self.abi_signatures])
        self.abi_combo.setFixedWidth(self.address_e.width())
        if len(self.senders) > 0:
            self.abi_combo.setCurrentIndex(0)
        self.addWidget(abi_lb, 2, 0)
        self.addWidget(self.abi_combo, 2, 1, 1, -1)
        self.abi_combo.currentIndexChanged.connect(self.update)

        args_lb = QLabel(_('Parameters:'))
        self.args_e = QLineEdit()
        self.addWidget(args_lb, 3, 0)
        self.addWidget(self.args_e, 3, 1, 1, -1)

        self.optional_lb = QLabel(_('Optional:'))
        self.addWidget(self.optional_lb, 4, 0)
        self.optional_widget = QWidget()

        optional_layout = QHBoxLayout()
        optional_layout.setContentsMargins(0, 0, 0, 0)
        optional_layout.setSpacing(0)

        gas_limit_lb = QLabel(_('gas limit: '))
        self.gas_limit_e = ButtonsLineEdit()
        self.gas_limit_e.setValidator(int_validator)
        self.gas_limit_e.setText('100')
        gas_price_lb = QLabel(_('gas price(UB): '))
        self.gas_price_e = ButtonsLineEdit()
        self.gas_price_e.setValidator(float_validator)
        self.gas_price_e.setText('0.0000001')
        amount_lb = QLabel(_('amount(UB): '))
        self.amount_e = ButtonsLineEdit()
        self.amount_e.setValidator(float_validator)
        optional_layout.addWidget(gas_limit_lb)
        optional_layout.addWidget(self.gas_limit_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(gas_price_lb)
        optional_layout.addWidget(self.gas_price_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(amount_lb)
        optional_layout.addWidget(self.amount_e)
        optional_layout.addStretch(0)
        self.optional_widget.setLayout(optional_layout)
        self.addWidget(self.optional_widget, 4, 1, 1, -1)

        sender_lb = QLabel(_('Sender:'))
        self.addWidget(sender_lb, 5, 0)

        buttons = QHBoxLayout()
        self.sender_combo = QComboBox()
        self.sender_combo.setMinimumWidth(400)
        self.sender_combo.addItems(self.senders)
        buttons.addWidget(self.sender_combo)
        buttons.addStretch(1)
        self.call_button = EnterButton(_("Estimate"), self.do_call)
        self.sendto_button = EnterButton(_("Send to"), self.do_sendto)
        self.testtransfer_button = EnterButton(_("Test Transfer"), self.do_testtransfer)
        self.transferto_button = EnterButton(_("Transfer to"), self.do_transferto)
        buttons.addWidget(self.call_button)
        buttons.addWidget(self.sendto_button)
        buttons.addWidget(self.testtransfer_button)
        buttons.addWidget(self.transferto_button)
        buttons.addStretch()
        self.addLayout(buttons, 5, 1, 1, -1)

        self.update()

    def update(self):
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        self.sendto_button.setHidden(True)
        self.call_button.setHidden(True)
        self.testtransfer_button.setHidden(True)
        self.transferto_button.setHidden(True)

        def show_call():
            self.optional_widget.setEnabled(False)
            self.amount_e.setEnabled(False)
            self.call_button.setHidden(False)
            self.testtransfer_button.setHidden(True)
            self.transferto_button.setHidden(True)

        def show_sendto():
            self.optional_widget.setEnabled(True)
            self.amount_e.setEnabled(False)
            self.sendto_button.setHidden(False)
            self.testtransfer_button.setHidden(True)
            self.transferto_button.setHidden(True)

        def show_transfertest():
            self.optional_widget.setEnabled(True)
            self.amount_e.setEnabled(True)
            self.sendto_button.setHidden(True)
            self.testtransfer_button.setHidden(False)
            self.transferto_button.setHidden(True)

        def show_transferto():
            self.optional_widget.setEnabled(True)
            self.amount_e.setEnabled(True)
            self.sendto_button.setHidden(True)
            self.testtransfer_button.setHidden(False)
            self.transferto_button.setHidden(False)

        if abi_index == -1:
            show_transfertest()
        else:
            abi = self.contract['interface'][abi_index]
            show_call()

    def parse_values(self):
        def parse_edit_value(edit, times=10 ** 8):
            try:
                return int(float(edit.text()) * times)
            except ValueError:
                return 0

        return parse_edit_value(self.gas_limit_e, 1), parse_edit_value(self.gas_price_e), parse_edit_value(
            self.amount_e)

    def parse_args(self):
        args = self.args_e.text()
        abi_index = self.abi_signatures[self.abi_combo.currentIndex()][0]
        if abi_index == -1:
            abi = ""
        else:
            abi = self.contract['interface'][abi_index]["name"]
        if len(self.senders) > 0:
            sender = self.senders[self.sender_combo.currentIndex()]
        else:
            sender = ''
        if args == "":
            args = " "
        return abi, args, sender

    def do_call(self):
        try:
            abi, args, sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        result = self.dialog.do_call(abi, args, sender)
        if(result is None or "gasCount" not in result.keys()):
            return
        self.gas_limit_e.setText(str(int(result["gasCount"])+10))
        withdraw_from_infos = {}
        for change in result['balanceChanges']:
            if change["is_contract"] and not change["is_add"]:
                withdraw_from_infos[change["address"]] = change["amount"] * 1.0 / (10 ** 8)
        withdraw_infos = {}
        for change in result["balanceChanges"]:
            if not change["is_contract"] and change["is_add"]:
                withdraw_infos[change["address"]] = change["amount"] * 1.0 /  (10 ** 8)
        self.withdraw_infos =withdraw_infos
        self.withdraw_froms =withdraw_from_infos
        self.optional_widget.setEnabled(True)
        self.amount_e.setEnabled(False)
        self.sendto_button.setHidden(False)

    def do_sendto(self):
        try:
            abi, args, sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        if not sender:
            self.dialog.show_message('no sender selected')
            return

        gas_limit, gas_price, amount = self.parse_values()
        self.dialog.do_sendto(abi, args, gas_limit, gas_price, sender, self.withdraw_infos, self.withdraw_froms)

    def do_testtransfer(self):
        try:
            abi, args, sender = self.parse_args()
            gas_limit, gas_price, amount = self.parse_values()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        result = self.dialog.do_transfer_test( amount,args, sender)
        if(result is None or "gasCount" not in result.keys()):
            return
        self.gas_limit_e.setText(str(int(result["gasCount"])+10))
        self.transferto_button.setHidden(False)

    def do_transferto(self):
        try:
            abi, args, sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        if not sender:
            self.dialog.show_message('no sender selected')
            return

        gas_limit, gas_price, amount = self.parse_values()
        if gas_limit <10 or gas_price <10 or gas_limit>=1000000000:
            self.dialog.show_message(str("gas limit or gas price is illegal!"))
            return
        self.dialog.do_transferto( args, gas_limit, gas_price, amount, sender)


class ContractFuncDialog(QDialog, MessageBoxMixin):
    def __init__(self, parent, contract):
        QDialog.__init__(self, parent=parent)
        self.contract = contract
        self.setWindowTitle(contract['name'])
        self.setMinimumSize(700, 200)
        self.main_window = parent
        run_hook('contract_func_dialog', self)
        layout = ContractFuncLayout(self, contract)
        self.setLayout(layout)

    def do_call(self, abi, args, sender):
        address = self.contract['address']
        return self.parent().call_smart_contract(address, abi, args, sender, self)


    def do_transfer_test(self, amount, args, sender):
        address = self.contract['address']
        return self.parent().test_transfer_to_smart_contract(address, amount, args, sender, self)

    def do_sendto(self, abi, ars, gas_limit, gas_price, sender,withdraw_infos,withdraw_forms):
        address = self.contract['address']
        self.parent().sendto_smart_contract(address, abi, ars, gas_limit, gas_price, sender, self,withdraw_infos,withdraw_forms)

    def do_transferto(self, ars, gas_limit, gas_price, amount, sender):
        address = self.contract['address']
        self.parent().transfer_to_smart_contract(address, ars, gas_limit, gas_price, amount, sender, self)


class ContractCreateLayout(QVBoxLayout):
    def __init__(self, dialog):
        QVBoxLayout.__init__(self)
        self.dialog = dialog
        self.senders = self.dialog.parent().wallet.get_spendable_addresses()
        self.path = os.getcwd()



        params_layout = QHBoxLayout()
        params_layout.addWidget(QLabel(_("Bytecode:")))
        self.bytecode_e = QLineEdit()
        self.bytecode_e.setFixedWidth(400)
        #self.bytecode_e.setText(self.path)
        params_layout.addWidget(self.bytecode_e)


        self.button = QPushButton("Select ByteCode File")
        self.button.clicked.connect(self.changePath)
        params_layout.addWidget(self.button)
        self.addLayout(params_layout)

        optional_layout = QHBoxLayout()
        self.addLayout(optional_layout)
        gas_limit_lb = QLabel(_('gas limit:'))
        self.gas_limit_e = ButtonsLineEdit()
        self.gas_limit_e.setValidator(int_validator)
        self.gas_limit_e.setText('2500')
        gas_price_lb = QLabel(_('gas price(UB):'))
        self.gas_price_e = ButtonsLineEdit()
        self.gas_price_e.setValidator(float_validator)
        self.gas_price_e.setText('0.00000010')
        sender_lb = QLabel(_('sender:'))
        self.sender_combo = QComboBox()
        self.sender_combo.setMinimumWidth(300)
        self.sender_combo.addItems(self.senders)
        optional_layout.addWidget(gas_limit_lb)
        optional_layout.addWidget(self.gas_limit_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(gas_price_lb)
        optional_layout.addWidget(self.gas_price_e)
        optional_layout.addStretch(1)
        optional_layout.addWidget(sender_lb)
        optional_layout.addWidget(self.sender_combo)

        self.cancel_btn = CancelButton(dialog)
        self.create_btn = QPushButton(_('Create'))
        self.create_btn.setDefault(True)
        self.create_btn.clicked.connect(self.create)
        self.test_btn = QPushButton(_('Test'))
        self.test_btn.clicked.connect(self.test_create)
        self.create_btn.setDisabled(True)
        self.addLayout(Buttons(*[self.cancel_btn,self.test_btn, self.create_btn]))

    def changePath(self):
        open = QFileDialog()
        self.path = open.getOpenFileName(filter="GPC FILE (*.gpc)")
        # self.path = open.getExistingDirectory()
        self.bytecode_e.setText(self.path[0])

    def parse_args(self):
        sender = None
        if len(self.senders) > 0:
            sender = self.senders[self.sender_combo.currentIndex()]
        if not sender:
            raise Exception('no sender selected')
        return   sender

    def parse_values(self):
        def parse_edit_value(edit, times=10 ** 8):
            try:

                return int(float(edit.text()) * times)
            except ValueError:
                return 0

        return parse_edit_value(self.gas_limit_e, 1), parse_edit_value(self.gas_price_e)

    def test_create(self):
        try:
            sender = self.parse_args()
            bytecode_file_path = self.bytecode_e.text()
            with open(bytecode_file_path, 'rb') as f:
                data = f.read()
                bytecode = data
            result = self.dialog.do_create_test(bytecode, sender)
            if "gasCount" in result:
                self.gas_limit_e.setText(str(int(result["gasCount"])+10))
                self.create_btn.setDisabled(False)
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return

    def create(self):
        try:
            sender = self.parse_args()
        except (BaseException,) as e:
            self.dialog.show_message(str(e))
            return
        gas_limit, gas_price = self.parse_values()
        if gas_limit <10 or gas_price <10 or gas_limit>=1000000000:
            self.dialog.show_message(str("gas limit or gas price is illegal!"))
            return
        bytecode_file_path = self.bytecode_e.text()
        try:
            with open(bytecode_file_path, 'rb') as f:
                data = f.read()
                bytecode = data
        except BaseException as e:
            self.dialog.show_message(str(e))
            return

        self.dialog.do_create(bytecode, gas_limit, gas_price, sender)

    def interface_changed(self):
        interface_text = self.interface_e.text()
        try:
            interface = json.loads(interface_text)
            constructor = {}
            for abi in interface:
                if abi.get('type') == 'constructor':
                    constructor = abi
                    break
            self.constructor = constructor
            if not constructor:
                self.args_e.setPlaceholderText('')
                return
            signature = '{}'.format(', '.join(['{} {}'.format(i.get('type'), i.get('name'))
                                               for i in constructor.get('inputs', [])]))
            self.args_e.setPlaceholderText(signature)
        except (BaseException,) as e:
            self.constructor = {}
            self.args_e.setPlaceholderText('')
            print_error('[interface_changed]', str(e))


class ContractCreateDialog(QDialog, MessageBoxMixin):
    def __init__(self, parent):
        QDialog.__init__(self, parent=parent)
        self.setWindowTitle(_('Create Smart Contract'))
        self.setMinimumSize(700, 150)
        self.setMaximumSize(780, 150)
        self.main_window = parent
        run_hook('contract_create_dialog', self)
        layout = ContractCreateLayout(self)
        self.setLayout(layout)

    def do_create(self, bytecode, gas_limit, gas_price, sender):
        self.parent().create_smart_contract(bytecode, gas_limit, gas_price, sender, self)

    def do_create_test(self,bytecode,sender):
        return self.parent().create_smart_contract_test(bytecode,sender,self)
