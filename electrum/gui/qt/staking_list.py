#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
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

from electrum.common.widgets import CustomTableWidget
from .staking_detail_tx_window import CompletedMultiClaimedStakeDialog, CompletedSingleClaimedStakeDialog, \
    CompletedReadyToClaimStakeDialog, UnstakedMultiStakeDialog, UnstakedSingleStakeDialog, StakedDialog
from ...stake import stake_api


def staking_list_copy_context_menu_on_click(row_data, **context):
    print('row data ', row_data)
    print('my context is ', context)


def staking_list_view_transaction_context_menu_on_click(row_data, **context):
    details_tx_data = stake_api.get_tx_details(tx_hash=row_data['tx_hash'])
    if row_data['Type'] == 'Staked':
        dialog = StakedDialog(row_data['wallet'])
        dialog.show()

    elif row_data['Type'] == 'Unstaked':
        print(row_data)

    elif row_data['Type'] == 'Completed':
        dialog = CompletedReadyToClaimStakeDialog(parent=context['window'], data=row_data, detail_tx=details_tx_data)
        dialog.show()


def staking_list_view_on_block_explorer_context_menu_on_click(row_data, **context):
    print('row data ', row_data)
    print('my context is ', context)


STAKING_LIST_CONTEXT_MENU_OPTIONS = {
    'Copy': staking_list_copy_context_menu_on_click,
    'View Transaction': staking_list_view_transaction_context_menu_on_click,
    'View on block explorer': staking_list_view_on_block_explorer_context_menu_on_click,
}


class StakingList(CustomTableWidget):
    pass


staking_list = StakingList(
    starting_empty_cells=0,
    context_menu_options=STAKING_LIST_CONTEXT_MENU_OPTIONS,
    column_names=['Start Date', 'Amount', 'Staking Period', 'Blocks Left', 'Type'],
)
