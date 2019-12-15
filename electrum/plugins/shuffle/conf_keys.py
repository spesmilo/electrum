#!/usr/bin/env python3

class ConfKeys:
    ''' A central place to keep all the cashshuffle-related config and
    wallet.storage keys for easier code maintenance. '''

    class Global:
        '''The below go in the global config '''
        # keys to be deleted if we ever see them. This keys are from older versions and are irrelevant now.
        DEFUNCT = ('cashshuffle_server', 'cashshuffle_server_v1', 'shuffle_noprompt', 'shuffle_noprompt2',)

        SERVER = "cashshuffle_server_v2" # specifies server config to use
        VIEW_POOLS_SIMPLE = 'shuffle_view_pools_simple'  # specifies that the "Pools" window shows a reduced/simplified view. Defaults to True if not found in conf.
        HIDE_TXS_FROM_HISTORY = 'shuffle_hide_txs_from_history'  # Default false. if true, all history lists app-wide will suppress the Shuffle transactions from the history
        MIN_COIN_VALUE = 'shuffle_min_coin_value'  # specifies the lower bound that the user set on what coin value (amount) can be eligible for shuffling.
        MAX_COIN_VALUE = 'shuffle_max_coin_value'  # spcifies the upper bound that the user set on what coin value (amount) can be eligible for shuffling.

    class PerWallet:
        '''The below are per-wallet and go in wallet.storage'''
        # keys to be deleted if we ever see them. This keys are from older versions and are irrelevant now.
        DEFUNCT = ('shuffle_spend_mode',)

        ENABLED = 'cashshuffle_enabled'  # whether cashshuffle is enabeld for this wallet.
        MAIN_WINDOW_NAGGER_ANSWER = 'shuffle_nagger_answer' # if None, nag user about "this wallet has cashshuffle disabled" on wallet startup. see main_window.py, if boolean value and not None, user won't be nagged but cashshuffle will auto-enable itself (or not) based on this value. TODO: also put this in the app preferences.
        SESSION_COUNTER = 'shuffle_session_counter'  # the number of times this wallet window has run cashshuffle. Incremented on each enabling, per wallet.
        SHUFFLE_COUNTER = 'shuffle_shuffle_counter'  # the number of successful shuffles we have performed with this plugin for this wallet.
        COINS_FROZEN_BY_SHUFFLING = 'coins_frozen_by_shuffling' # list of coins frozen by shuffling. in case we crash.
        SPEND_UNSHUFFLED_NAGGER_NOPROMPT = 'shuffle_spend_unshuffled_nonag'  # Whether or not to nag the user when they select "spend unshuffled" in Send tab.
        DISABLE_NAGGER_NOPROMPT = 'shuffle_disable_nonag'
        CHANGE_SHARED_WITH_OTHERS = 'shuffle_change_addrs_shared_with_others' # A list of addresses we've sent over the network as 'change' addrs. These should not be used as shuffled output addresses as it would leak a bit of privacy. See clifordsymack#105
