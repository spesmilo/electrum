from electrum.i18n import _
from .util import (WindowModalDialog, )
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.Qt import QUrl, QDesktopServices


class CreateNewStaking(WindowModalDialog):

    def __call__(self, *args, **kwargs):
        self.show()

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.MIN_AMOUNT = 5
        self.stake_value = 0
        self.setEnabled(True)
        self.setMinimumSize(QtCore.QSize(440, 400))
        self.setMaximumSize(QtCore.QSize(440, 400))
        self.setBaseSize(QtCore.QSize(440, 400))
        self.setWindowTitle(_("Create New Stake"))
        self.verticalLayoutWidget = QtWidgets.QWidget(self)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(0, 10, 431, 391))
        self.Main_v_layout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.Main_v_layout.setSizeConstraint(QtWidgets.QLayout.SetMinimumSize)
        self.Main_v_layout.setContentsMargins(10, 10, 10, 10)
        self.Main_v_layout.setSpacing(10)
        self.title = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.title.setText(_("Create New Stake"))
        self.title.setMinimumSize(QtCore.QSize(300, 0))
        self.title.setMaximumSize(QtCore.QSize(16777215, 25))
        self.title.setBaseSize(QtCore.QSize(0, 25))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.title.setFont(font)
        self.title.setAlignment(QtCore.Qt.AlignCenter)
        self.Main_v_layout.addWidget(self.title)
        self.description_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.description_label.setText(
            _("Sed ut perspiciatis, unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, "
              "totam rem aperiam eaque ipsa, "))
        self.description_label.setMinimumSize(QtCore.QSize(300, 0))
        self.description_label.setMaximumSize(QtCore.QSize(900, 60))
        self.description_label.setAlignment(QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.description_label.setWordWrap(True)
        self.description_label.setIndent(-1)
        self.description_label.setOpenExternalLinks(False)
        self.Main_v_layout.addWidget(self.description_label)
        self.gridLayout = QtWidgets.QGridLayout()
        self.period_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.period_label.setText(_("Period"))
        self.gridLayout.addWidget(self.period_label, 3, 0, 1, 1)
        self.spinBox_amount = QtWidgets.QDoubleSpinBox(self.verticalLayoutWidget)
        self.spinBox_amount.setDecimals(8)
        self.spinBox_amount.setRange(self.MIN_AMOUNT, self.get_spendable_coins())
        self.spinBox_amount.valueChanged.connect(self.value_change)

        self.gridLayout.addWidget(self.spinBox_amount, 0, 1, 1, 4)
        self.amount_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.amount_label.setText(_("Amount"))
        self.gridLayout.addWidget(self.amount_label, 0, 0, 1, 1)

        self.amount_value_error_label = QtWidgets.QLabel()
        self.amount_value_error_label.setText(_("The minimum stake value is 5 ELCASH"))
        self.amount_value_error_label.setStyleSheet('color: red')

        if self.valid_enough_coins(min_coins=self.MIN_AMOUNT):
            self.amount_value_error_label.hide()

        self.gridLayout.addWidget(self.amount_value_error_label, 1, 0, 1, 5)

        self.radio30 = QtWidgets.QRadioButton(self.verticalLayoutWidget)
        self.radio30.setText(_("30 Days"))
        self.radio30.setChecked(True)
        self.period = {
            'days': 30,
            'blocks': 144 * 30,
        }
        self.radio30.toggled.connect(lambda: self.radio_state(self.radio30))
        self.radio30.toggled.connect(self.value_change)
        self.gridLayout.addWidget(self.radio30, 3, 1, 1, 1)
        self.radio90 = QtWidgets.QRadioButton(self.verticalLayoutWidget)
        self.radio90.setText(_("90 Days"))
        self.radio90.toggled.connect(lambda: self.radio_state(self.radio90))
        self.radio90.toggled.connect(self.value_change)
        self.gridLayout.addWidget(self.radio90, 3, 2, 1, 1)
        self.radio180 = QtWidgets.QRadioButton(self.verticalLayoutWidget)
        self.radio180.setText(_("180 Days"))
        self.radio180.toggled.connect(lambda: self.radio_state(self.radio180))
        self.radio180.toggled.connect(self.value_change)
        self.gridLayout.addWidget(self.radio180, 3, 3, 1, 1)
        self.radio360 = QtWidgets.QRadioButton(self.verticalLayoutWidget)
        self.radio360.setText(_("360 Days"))
        self.radio360.toggled.connect(lambda: self.radio_state(self.radio360))
        self.radio360.toggled.connect(self.value_change)
        self.gridLayout.addWidget(self.radio360, 3, 4, 1, 1)
        self.Main_v_layout.addLayout(self.gridLayout)
        self.vl_rewords = QtWidgets.QVBoxLayout()
        self.vl_rewords.setSizeConstraint(QtWidgets.QLayout.SetMinimumSize)
        self.vl_rewords.setSpacing(0)
        self.label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label.setText(_("Guaranteed rewords:"))
        self.label.setMaximumSize(QtCore.QSize(16777215, 20))
        self.vl_rewords.addWidget(self.label)
        self.gp_value_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.gp_value_label.setText(
            _("Governance Power: ") +
            str(self.spinBox_amount.value() * self.period['days'] * 0.008) +
            ' GP')
        self.gp_value_label.setMaximumSize(QtCore.QSize(16777215, 20))
        self.vl_rewords.addWidget(self.gp_value_label)
        self.free_trans_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.free_trans_label.setText(
            _("Daily free transactions limit:") +
            str(self.spinBox_amount.value() * self.period['days'] * 0.01) +
            ' bytes')
        self.free_trans_label.setMaximumSize(QtCore.QSize(16777215, 20))
        self.vl_rewords.addWidget(self.free_trans_label)
        spacer_item = QtWidgets.QSpacerItem(0, 10, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        self.vl_rewords.addItem(spacer_item)
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.label_6.setText(_("Predicted Rewords:"))
        self.label_6.setMaximumSize(QtCore.QSize(16777215, 30))
        self.label_6.setBaseSize(QtCore.QSize(0, 30))
        self.vl_rewords.addWidget(self.label_6)
        self.ep_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.ep_label.setText(
            _("Estimated payout: ") +
            str(self.spinBox_amount.value() * self.period['days'] * 0.21) +
            ' ELCASH')
        self.ep_label.setMaximumSize(QtCore.QSize(16777215, 20))
        self.vl_rewords.addWidget(self.ep_label)
        self.Main_v_layout.addLayout(self.vl_rewords)
        self.description2_label = QtWidgets.QLabel(self.verticalLayoutWidget)
        self.description2_label.setText(_("Click Next to go confirmation view. "))
        self.description2_label.setMaximumSize(QtCore.QSize(16777215, 50))
        self.Main_v_layout.addWidget(self.description2_label)
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setSpacing(2)
        self.terms_button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.terms_button.setText(_("Terms & Conditions"))
        self.terms_button.setMaximumSize(QtCore.QSize(140, 16777215))
        font = QtGui.QFont()
        font.setUnderline(True)
        self.terms_button.setFont(font)
        self.terms_button.setText(_("Terms & Conditions"))
        self.terms_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.terms_button.setStyleSheet("border: none;")
        self.terms_button.setAutoDefault(True)
        self.gridLayout_2.addWidget(self.terms_button, 0, 1, 1, 1)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        spacer_item1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacer_item1)
        self.cancel_button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.cancel_button.setText(_("Cancel"))
        self.cancel_button.clicked.connect(self.on_push_cancel_button)
        self.cancel_button.setMaximumSize(QtCore.QSize(60, 16777215))
        self.cancel_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.horizontalLayout.addWidget(self.cancel_button)
        self.next_button = QtWidgets.QPushButton(self.verticalLayoutWidget)
        self.next_button.setText(_("Next"))

        if not self.valid_enough_coins(self.MIN_AMOUNT):
            self.next_button.setEnabled(False)

        self.next_button.setMaximumSize(QtCore.QSize(60, 16777215))
        self.next_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.next_button.clicked.connect(self.on_push_next_button)
        self.horizontalLayout.addWidget(self.next_button)
        self.gridLayout_2.addLayout(self.horizontalLayout, 0, 5, 1, 2)
        self.Main_v_layout.addLayout(self.gridLayout_2)

    def on_push_next_button(self):
        if self.valid_enough_coins(min_coins=self.spinBox_amount.value()):
            self.dialog = dialog = CreateNewStakingTwo(parent=self)
            dialog.show()
            self.hide()

    def on_push_cancel_button(self):
        self.hide()

    def value_change(self):

        if self.valid_enough_coins(min_coins=self.spinBox_amount.value()):
            self.amount_value_error_label.hide()
        else:
            self.amount_value_error_label.show()

        self.ep_label.setText(
            _("Estimated payout: ") +
            str(self.spinBox_amount.value() * self.period['days'] * 0.21) +
            ' ELCASH')

        self.free_trans_label.setText(
            _("Daily free transactions limit:") +
            str(self.spinBox_amount.value() * self.period['days'] * 0.017) +
            ' bytes')

        self.gp_value_label.setText(
            _("Governance Power: ") +
            str(self.spinBox_amount.value() * self.period['days'] * 0.008) +
            ' GP')

    def radio_state(self, b):
        if b.text() == "30 Days":
            if b.isChecked():
                self.period = {
                    'days': 30,
                    'blocks': 144 * 30,
                }

        if b.text() == "90 Days":
            if b.isChecked():
                self.period = {
                    'days': 90,
                    'blocks': 144 * 90,
                }
        if b.text() == "180 Days":
            if b.isChecked():
                self.period = {
                    'days': 180,
                    'blocks': 144 * 180,
                }
        if b.text() == "360 Days":
            if b.isChecked():
                self.period = {
                    'days': 360,
                    'blocks': 144 * 360,
                }

    def valid_enough_coins(self, min_coins):
        coins = self.get_spendable_coins()
        if not coins >= min_coins:
            return False
        else:
            return True

    def get_spendable_coins(self):
        coins = 0
        for i in self.parent.wallet.get_spendable_coins(None, nonlocal_only=True):
            coins += i._trusted_value_sats
        return coins * 0.00000001


class CreateNewStakingTwo(WindowModalDialog):

    def __call__(self, *args, **kwargs):
        self.show()

    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.wallet = parent.parent.wallet
        self.password_required = self.wallet.has_keystore_encryption()
        self.setWindowModality(QtCore.Qt.WindowModal)
        self.setEnabled(True)
        self.resize(420, 500)
        self.setMinimumSize(QtCore.QSize(420, 500))
        self.setMaximumSize(QtCore.QSize(420, 500))
        self.setWindowTitle("Create New Stake")
        self.main_box = QtWidgets.QVBoxLayout(self)
        self.title = QtWidgets.QLabel()
        self.title.setText(_("Staking Detail"))
        size_policy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Maximum)
        size_policy.setHorizontalStretch(0)
        size_policy.setVerticalStretch(0)
        size_policy.setHeightForWidth(self.title.sizePolicy().hasHeightForWidth())
        self.title.setSizePolicy(size_policy)
        self.title.setMaximumSize(QtCore.QSize(600, 35))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.title.setFont(font)
        self.title.setAlignment(QtCore.Qt.AlignCenter)
        self.main_box.addWidget(self.title)
        self.data_grid_box = QtWidgets.QGridLayout()
        self.payout_label_2 = QtWidgets.QLabel()
        self.payout_label_2.setText(
            str(parent.spinBox_amount.value() * parent.period['days'] * 0.021) +
            ' ELCASH'
        )
        self.data_grid_box.addWidget(self.payout_label_2, 7, 1, 1, 1)
        self.gp_label_2 = QtWidgets.QLabel()
        self.gp_label_2.setText(str(parent.spinBox_amount.value() * parent.period['days'] * 0.008) + ' GP')
        self.data_grid_box.addWidget(self.gp_label_2, 4, 1, 1, 1)
        self.payout_label = QtWidgets.QLabel()
        self.payout_label.setText(_("Estimated payout:"))
        self.data_grid_box.addWidget(self.payout_label, 7, 0, 1, 1)
        self.block_label = QtWidgets.QLabel()
        self.block_label.setText(_("Block required:"))
        self.data_grid_box.addWidget(self.block_label, 2, 0, 1, 1)
        self.rewords_label = QtWidgets.QLabel()
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.rewords_label.setFont(font)
        self.rewords_label.setText(_("Predicted rewords:"))
        self.data_grid_box.addWidget(self.rewords_label, 6, 0, 1, 1)
        self.gp_label = QtWidgets.QLabel()
        self.gp_label.setText(_("Governance Power:"))
        self.data_grid_box.addWidget(self.gp_label, 4, 0, 1, 1)
        self.fee_label_2 = QtWidgets.QLabel()
        self.fee_label_2.setText(_("Daily free transactions limit:"))
        self.data_grid_box.addWidget(self.fee_label_2, 5, 0, 1, 1)
        self.fee_label = QtWidgets.QLabel()

        self.fee_label.setText(
            str(parent.spinBox_amount.value() * parent.period['days'] * 0.017) +
            ' bytes')
        self.data_grid_box.addWidget(self.fee_label, 5, 1, 1, 1)
        self.amount_label_2 = QtWidgets.QLabel()
        amount = parent.spinBox_amount.value()
        self.amount_label_2.setText(str(amount) + _(" Elcash"))
        self.data_grid_box.addWidget(self.amount_label_2, 0, 1, 1, 1)
        self.g_reword = QtWidgets.QLabel()
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.g_reword.setFont(font)
        self.g_reword.setText(_("Guaranted rewords:"))
        self.data_grid_box.addWidget(self.g_reword, 3, 0, 1, 1)
        self.block_label_2 = QtWidgets.QLabel()
        blocks_period = parent.period['blocks']
        self.block_label_2.setText(str(blocks_period))
        self.data_grid_box.addWidget(self.block_label_2, 2, 1, 1, 1)
        self.pertiod_label = QtWidgets.QLabel()
        self.pertiod_label.setText(_("Period:"))
        self.data_grid_box.addWidget(self.pertiod_label, 1, 0, 1, 1)
        self.period_label = QtWidgets.QLabel()
        self.period_label.setText(str(parent.period['days']) + _(" days"))
        self.data_grid_box.addWidget(self.period_label, 1, 1, 1, 1)
        self.amount_label = QtWidgets.QLabel()
        self.amount_label.setText(_("Amount to be staked:"))
        self.data_grid_box.addWidget(self.amount_label, 0, 0, 1, 1)
        self.main_box.addLayout(self.data_grid_box)
        self.penality_label = QtWidgets.QLabel()
        self.penality_label.setMaximumSize(QtCore.QSize(16777215, 40))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.penality_label.setFont(font)
        self.penality_label.setText(_("PENALTY"))
        self.main_box.addWidget(self.penality_label)
        self.description_label = QtWidgets.QLabel()
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(239, 41, 41))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(239, 41, 41))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.WindowText, brush)
        brush = QtGui.QBrush(QtGui.QColor(190, 190, 190))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText, brush)
        self.description_label.setPalette(palette)
        self.description_label.setText(_("If you unstake this transaction ealier you will be charged 3% as "
                                         "penality and you will loose daily free transaction limit."))
        self.description_label.setAlignment(QtCore.Qt.AlignLeading | QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.description_label.setWordWrap(True)
        self.main_box.addWidget(self.description_label)
        self.password_layout = QtWidgets.QHBoxLayout()
        self.password_label = QtWidgets.QLabel()
        self.password_label.setText(_("Password:"))
        self.password_label.setMaximumSize(QtCore.QSize(16777215, 40))
        self.password_layout.addWidget(self.password_label)
        self.password_lineEdit = QtWidgets.QLineEdit()
        self.password_lineEdit.setText("")
        self.password_layout.addWidget(self.password_lineEdit)
        self.main_box.addLayout(self.password_layout)
        self.password_error_label = QtWidgets.QLabel()
        self.password_error_label.setText(_("incorrect password"))
        self.password_error_label.setStyleSheet('color: red')
        self.main_box.addWidget(self.password_error_label)
        self.password_error_label.hide()

        if not self.password_required:
            self.password_label.hide()
            self.password_lineEdit.hide()

        self.text_tabel = QtWidgets.QLabel()
        self.text_tabel.setText(_("Click Send to proceed"))
        self.main_box.addWidget(self.text_tabel)
        self.button_layout = QtWidgets.QHBoxLayout()
        spacer_item = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.button_layout.addItem(spacer_item)
        self.back_button = QtWidgets.QPushButton()
        self.back_button.setText(_("Back"))
        self.back_button.clicked.connect(self.on_push_back_button)
        self.button_layout.addWidget(self.back_button)
        self.cancel_button = QtWidgets.QPushButton()
        self.cancel_button.setText(_("Cancel"))
        self.cancel_button.clicked.connect(self.on_push_cancel_button)
        self.button_layout.addWidget(self.cancel_button)
        self.send_button = QtWidgets.QPushButton()
        self.send_button.setText(_("Send"))
        self.send_button.clicked.connect(self.on_push_send_window)
        self.button_layout.addWidget(self.send_button)
        self.main_box.addLayout(self.button_layout)

    def on_push_back_button(self):
        dialog = self.parent
        dialog.show()
        self.hide()

    def on_push_cancel_button(self):
        self.hide()

    def on_push_send_window(self):
        password = self.password_lineEdit.text() or None
        if self.password_required:
            if password is None:
                return
            try:
                self.wallet.check_password(password)
            except Exception as e:
                self.password_error_label.show()
                self.password_lineEdit.setStyleSheet("background-color: red;")
                return

        self.is_send = True
        self.hide()
        dialog = CreateNewStakingFinish(parent=self)
        dialog.show()


class CreateNewStakingFinish(WindowModalDialog):

    def __call__(self, *args, **kwargs):
        self.show()

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowModality(QtCore.Qt.WindowModal)
        self.setEnabled(True)
        self.setMinimumSize(QtCore.QSize(720, 100))
        self.setMaximumSize(QtCore.QSize(720, 100))
        self.setWindowTitle(_("Create New Stake"))
        self.main_box = QtWidgets.QVBoxLayout(self)
        self.info_label = QtWidgets.QLabel()
        self.info_label.setText(_("Succes!"))
        self.main_box.addWidget(self.info_label)
        self.info_label1 = QtWidgets.QLabel()
        transaction_id = 'ab56766804280c622dedb5d608e9a43df027409686de77e417d0b74ea32b5f3c'  # todo
        self.info_label1.setText(_("Transaction ID:") + transaction_id)
        self.main_box.addWidget(self.info_label1)
        self.button_layout = QtWidgets.QHBoxLayout()
        spacer_item = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.button_layout.addItem(spacer_item)
        self.cancel_button = QtWidgets.QPushButton()
        self.cancel_button.setText(_("View in explorer"))
        self.cancel_button.clicked.connect(self.on_push_explorer_button)
        self.button_layout.addWidget(self.cancel_button)
        self.ok_button = QtWidgets.QPushButton()
        self.ok_button.setText(_("ok"))
        self.ok_button.clicked.connect(self.on_push_ok_button)
        self.button_layout.addWidget(self.ok_button)
        self.main_box.addLayout(self.button_layout)

    def on_push_explorer_button(self):
        url = QUrl("https://explorer.electriccash.global/")
        QDesktopServices.openUrl(url)
        self.hide()

    def on_push_ok_button(self):
        self.hide()

