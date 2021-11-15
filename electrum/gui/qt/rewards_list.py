
from ...common.services import CustomTableWidgetController
from ...common.widgets import CustomTableWidget


class AvailablePredictedRewardsList(CustomTableWidget):
    pass


def refresh_available_rewards_window():
    available_predicted_rewards_controller.insert_data(table_data={
        'Payout date': ['2021-12-12', '2021-12-12'],
        'Amount': ['1000111111.00000001', '1'],
        'Status': ['Ready to Claim', 'b']
    })


def refresh_predicted_rewards_window():
    available_predicted_rewards_controller.insert_data(table_data={
        'Payout date': ['2021-12-12', '2021-12-12'],
        'Amount': ['1000111111.00000001', '555'],
        'Status': ['Staked', 'Staked']
    })


available_predicted_rewards_list = AvailablePredictedRewardsList(
    starting_empty_cells=0,
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
