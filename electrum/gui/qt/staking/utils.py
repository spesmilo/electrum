from datetime import datetime, timedelta

from electrum.staking.tx_type import TxType
from electrum.wallet import Abstract_Wallet


def get_data_for_available_rewards_tab(wallet: Abstract_Wallet):
    transactions = wallet.db.transactions

    payout_dates = []
    amounts = []
    status = []

    for t in transactions:
        if transactions[t].tx_type.name == 'STAKING_DEPOSIT' \
                and transactions[t].staking_info.fulfilled and not transactions[t].staking_info.paid_out:
            finish_height = transactions[t].staking_info.deposit_height + transactions[t].staking_info.staking_period
            block_header = wallet.network.run_from_another_thread(wallet.network.get_block_header(finish_height, 'catchup'))
            payout_dates.append(datetime.fromtimestamp(block_header['timestamp']).strftime("%Y-%m-%d"))
            amounts.append(
                transactions[t].staking_info.accumulated_reward
            )
            status.append("Ready to Claim")

    return payout_dates, amounts, status


def get_predicted_rewards_data(wallet: Abstract_Wallet):
    amounts = []
    payout_dates = []
    status = []

    transactions = wallet.db.transactions
    verified_tx = wallet.db.verified_tx
    staking_info = wallet.network.run_from_another_thread(wallet.network.get_staking_info())
    period_info = staking_info['interestInfo']
    current_height = wallet.network.get_server_height()
    for t in transactions:
        tx = transactions[t]
        if tx.tx_type == TxType.STAKING_DEPOSIT and not tx.staking_info.fulfilled and not tx.staking_info.paid_out:
            max_reward = tx.staking_info.staking_amount * (period_info[str(tx.staking_info.staking_period)] * tx.staking_info.staking_period / 51840)
            completed_period = (current_height - tx.staking_info.deposit_height) / tx.staking_info.staking_period
            max_current_reward = max_reward * completed_period
            pr = max_reward * max_current_reward / tx.staking_info.accumulated_reward
            amounts.append(pr)
            payout_date = datetime.fromtimestamp(verified_tx[t][1]) + timedelta(tx.staking_info.staking_period / 144)
            payout_dates.append(payout_date.strftime("%Y-%m-%d"))
            status.append('Stake')
    return payout_dates, amounts, status


def get_sum_available_rewards(wallet: Abstract_Wallet):
    transactions = wallet.db.transactions
    av = 0
    for t in transactions:
        if transactions[t].tx_type == TxType.STAKING_DEPOSIT \
                and transactions[t].staking_info.fulfilled and not transactions[t].staking_info.paid_out:
            av += transactions[t].staking_info.accumulated_reward
    return av


def get_sum_predicted_rewards(wallet: Abstract_Wallet):
    blocks_in_year = 52560  # 365 * 24 * 60 / 10
    transactions = wallet.db.transactions
    staking_info = wallet.network.run_from_another_thread(wallet.network.get_staking_info())
    period_info = staking_info['interestInfo']
    current_height = wallet.network.get_server_height()
    pr = 0
    for t in transactions:
        tx = transactions[t]
        if tx.tx_type == TxType.STAKING_DEPOSIT and not tx.staking_info.fulfilled and not tx.staking_info.paid_out:
            max_reward = tx.staking_info.staking_amount * (period_info[str(tx.staking_info.staking_period)] * tx.staking_info.staking_period / blocks_in_year)
            completed_period = (current_height - tx.staking_info.deposit_height) / tx.staking_info.staking_period
            max_current_reward = max_reward * completed_period
            pr += max_reward * max_current_reward / tx.staking_info.accumulated_reward
    return pr