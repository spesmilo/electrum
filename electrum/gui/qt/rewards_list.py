from datetime import datetime, timedelta

from .staking.utils import get_data_for_available_rewards_tab, get_predicted_rewards_data
from ...common.services import CustomTableWidgetController
from ...common.widgets import CustomTableWidget
from ...staking.tx_type import TxType
from ...wallet import Abstract_Wallet


class AvailablePredictedRewardsList(CustomTableWidget):
    pass


def refresh_available_rewards_window(wallet: Abstract_Wallet):
    payoudates, amounts, status = get_data_for_available_rewards_tab(wallet)

    available_predicted_rewards_controller.insert_data(
        table_data={
            'Payout date': payoudates,
            'Amount': amounts,
            'Status': status
        }
    )


def refresh_predicted_rewards_window(wallet: Abstract_Wallet):
    payout_dates, amounts, status = get_predicted_rewards_data(wallet=wallet)
    available_predicted_rewards_controller.insert_data(table_data={
        'Payout date': payout_dates,
        'Amount': amounts,
        'Status': status,
    })


available_predicted_rewards_list = AvailablePredictedRewardsList(
    column_names=['Payout date', 'Amount', 'Status'],
)

available_predicted_rewards_controller = CustomTableWidgetController(table_widget=available_predicted_rewards_list)


#####
class GovernancePowerList(CustomTableWidget):
    pass


def refresh_governance_power_window():
    governance_power_controller.insert_data(table_data={
        'Date': ['2021-12-12', '2021-12-12'],
        'Total reward': ['11111.00000001', '1'],
    })


governance_power_list = GovernancePowerList(
    column_names=['Date', 'Total reward'],
)

governance_power_controller = CustomTableWidgetController(table_widget=governance_power_list)


class FreeLimitList(CustomTableWidget):
    pass


def free_limit_window():
    free_limit_controller.insert_data(table_data={
        'Payout date': ['2021-12-12', '2021-12-12'],
        'Total reward': ['1000 bytes', '1bytes'],
    })


free_limit_list = FreeLimitList(
    column_names=['Payout date', 'Total reward'],
)

free_limit_controller = CustomTableWidgetController(table_widget=free_limit_list)
