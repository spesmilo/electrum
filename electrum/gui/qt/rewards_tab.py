from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt

from .rewards_list import available_predicted_rewards_list, refresh_available_rewards_window, \
    refresh_predicted_rewards_window, governance_power_controller, refresh_governance_power_window, \
    governance_power_list, free_limit_list, free_limit_window
from .util import WindowModalDialog
from ...i18n import _


class Section:
    TITLE_LABEL = None

    def __init__(self, root_widget):
        self._text = None
        self._root_widget = root_widget
        self._label_size_policy = self._create_label_size_policy()
        self._button_size_policy = self._create_button_size_policy()

        self._root_layout = QtWidgets.QVBoxLayout()

        self._label_layout = QtWidgets.QVBoxLayout()
        self._label_layout.setContentsMargins(-1, 15, -1, 15)
        self._root_layout.addLayout(self._label_layout)

        self._button_layout = QtWidgets.QVBoxLayout()
        self._button_layout.setSizeConstraint(QtWidgets.QLayout.SetMaximumSize)
        self._button_layout.setContentsMargins(40, -1, 40, -1)
        self._root_layout.addLayout(self._button_layout)

        self._title_label = QtWidgets.QLabel(root_widget)
        self._label_size_policy.setHeightForWidth(
            self._title_label.sizePolicy().hasHeightForWidth()
        )
        self._title_label.setSizePolicy(self._label_size_policy)
        self._title_label.setAlignment(QtCore.Qt.AlignCenter)
        title_label_font = QtGui.QFont()
        title_label_font.setBold(True)
        title_label_font.setWeight(75)
        self._title_label.setFont(title_label_font)
        self._title_label.setText(self.TITLE_LABEL)
        self._label_layout.addWidget(self._title_label)

        self._value_label = QtWidgets.QLabel(root_widget)
        self._label_size_policy.setHeightForWidth(
            self._value_label.sizePolicy().hasHeightForWidth()
        )
        self._value_label.setSizePolicy(self._label_size_policy)
        self._value_label.setAlignment(QtCore.Qt.AlignCenter)
        self._label_layout.addWidget(self._value_label)

        self._details_button = QtWidgets.QPushButton(root_widget)
        self._button_size_policy.setHeightForWidth(
            self._details_button.sizePolicy().hasHeightForWidth()
        )
        self._details_button.setSizePolicy(self._button_size_policy)
        self._button_layout.addWidget(self._details_button)
        self._details_button.setText('Details')
        self._details_button.clicked.connect(lambda: self.display_detail_popup())

        spacer = QtWidgets.QSpacerItem(
            20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum
        )
        self._button_layout.addItem(spacer)

    @staticmethod
    def _create_button_size_policy():
        size_policy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum
        )
        size_policy.setVerticalStretch(0)
        size_policy.setHorizontalStretch(0)

        return size_policy

    @staticmethod
    def _create_label_size_policy():
        size_policy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Minimum
        )
        size_policy.setVerticalStretch(0)
        size_policy.setHorizontalStretch(0)

        return size_policy

    def display_detail_popup(self):
        raise NotImplemented()

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        self._text = value
        self._value_label.setText(value)

    @property
    def layout(self):
        return self._root_layout


class RewardPopup(WindowModalDialog):
    def __init__(self, parent, title, text, table=None):
        super().__init__(parent)
        self.setEnabled(True)
        self._setup_window()

        self.main_layout = self.create_main_layout()
        self.title_label = self._setup_title(title=title)
        self.text_label = self._setup_text(main_text=text)
        if table is not None:
            self._setup_table(table=table)

    def create_main_layout(self):
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        return main_layout

    def _setup_window(self):
        self.setMinimumSize(QtCore.QSize(440, 400))
        self.setMaximumSize(QtCore.QSize(440, 400))
        self.setBaseSize(QtCore.QSize(440, 400))

    def _setup_title(self, title):
        title_label = QtWidgets.QLabel()
        title_label.setMinimumSize(QtCore.QSize(0, 40))
        title_label.setMaximumSize(QtCore.QSize(16777215, 40))
        title_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        title_label_text = QtGui.QFont()
        title_label_text.setBold(True)
        title_label_text.setPointSize(16)

        title_label.setFont(title_label_text)
        title_label.setText(title)

        self.main_layout.addWidget(title_label)

        return title_label

    def _setup_text(self, main_text):
        text_label = QtWidgets.QLabel()
        text_label.setWordWrap(True)
        text_label.setText(main_text)

        self.main_layout.addWidget(text_label)

        return text_label

    def _setup_table(self, table):
        self.main_layout.addWidget(table)


class AvailableRewardsSection(Section):
    TITLE_LABEL = 'Available reward'

    def display_detail_popup(self):
        available_reward_popup = RewardPopup(
            parent=self._root_widget,
            title='Available Rewards',
            text=_(
                "Check the details of the rewards you can already claim. "
                "These are your guaranteed payouts, so you can already "
                "start thinking about what you will spend them on."
            ),
            table=available_predicted_rewards_list
        )

        refresh_available_rewards_window()
        available_reward_popup.open()


class TotalPredictedStakingRewardSection(Section):
    TITLE_LABEL = 'Total predicted staking reward'

    def display_detail_popup(self):
        predicted_staking_popup = RewardPopup(
            parent=self._root_widget,
            title='Predicted staking rewards',
            text=_(
                "Check the details of your predicted rewards. The "
                "payout amount is dependent on multiple factors and "
                "may change dynamically, so don't plan what you will "
                "buy with it just yet."
            ),
            table=available_predicted_rewards_list
        )
        refresh_predicted_rewards_window()
        predicted_staking_popup.open()


class GovernancePowerSection(Section):
    TITLE_LABEL = 'Governance Power'

    def display_detail_popup(self):
        governance_power_popup = RewardPopup(
            parent=self._root_widget,
            title='Governance Power',
            text=_(
                "Governance Power lets you decide on the future of"
                "Electric Cash.\n\n"
                "You can use it to vote on important community issues"
                "and propose your own improvements.\n\n"
                "To cast a vote, you need GP points earned through"
                "staking. You will see and use them here when Governance"
                "Power become available."
            ),
            table=governance_power_list
        )
        refresh_governance_power_window()
        governance_power_popup.open()


class DailyFreeTransactionLimitSection(Section):
    TITLE_LABEL = 'Daily free transaction limit'

    def display_detail_popup(self):
        daily_free_transactions = RewardPopup(
            parent=self._root_widget,
            title='Daily free transactions limit',
            text=_(
                "This is the number of bytes you can use every day to "
                "make free transactions. It's one of the rewards that "
                "you can enjoy as long as you're staking. Note that if "
                "you go over this limit, you will have to pay the network "
                "fees."
            ),
            table=free_limit_list
        )
        free_limit_window()
        daily_free_transactions.open()


class RewardsWindow(QtWidgets.QWidget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._setup_window()
        self._main_layout = self._create_main_layout()

        self._available_section = AvailableRewardsSection(root_widget=self)
        self._main_layout.addLayout(self._available_section.layout)

        self._predicted_section = TotalPredictedStakingRewardSection(root_widget=self)
        self._main_layout.addLayout(self._predicted_section.layout)

        self._governance_power_section = GovernancePowerSection(root_widget=self)
        self._main_layout.addLayout(self._governance_power_section.layout)

        self._daily_free_section = DailyFreeTransactionLimitSection(root_widget=self)
        self._main_layout.addLayout(self._daily_free_section.layout)

    def _setup_window(self):
        self.resize(854, 404)
        self.setMinimumSize(QtCore.QSize(500, 300))
        self.setMaximumSize(QtCore.QSize(854, 404))

    def _create_main_layout(self):
        root_layout = QtWidgets.QHBoxLayout(self)
        main_layout = QtWidgets.QHBoxLayout()
        main_layout.setContentsMargins(-1, 50, -1, 175)

        root_layout.addLayout(main_layout)

        return main_layout

    def set_available_rewards_text(self, value):
        self._available_section.text = f'{value:.8f} ELCASH'

    def set_total_predicted_staking_reward_text(self, value):
        self._predicted_section.text = f'{value:.8f} ELCASH'

    def set_governance_power_text(self, value):
        self._governance_power_section.text = f'{value} GP'

    def set_daily_free_transaction_limit(self, value):
        self._daily_free_section.text = f'{value} bytes'
