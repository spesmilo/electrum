#!/usr/bin/env python3

class ConfKeys:
    ''' A central place to keep all the cashshuffle-related config and
    wallet.storage keys for easier code maintenance. '''

    class Global:
        '''The below go in the global config '''
        # keys to be deleted if we ever see them. This keys are from older versions and are irrelevant now.
        DEFUNCT = ('cashshuffle_server', 'cashshuffle_server_v1', 'shuffle_noprompt',)

        SERVER = "cashshuffle_server_v2" # specifies server config to use
        MAIN_WINDOW_NAGGER_NOPROMPT = 'shuffle_noprompt2' # specifies whether to nag user about "this wallet has cashshuffle disabled" on wallet startup. see main_window.py

    class PerWallet:
        '''The below are per-wallet and go in wallet.storage'''
        # keys to be deleted if we ever see them. This keys are from older versions and are irrelevant now.
        DEFUNCT = []
        
        ENABLED = 'cashshuffle_enabled'  # whether cashshuffle is enabeld for this wallet.
        SESSION_COUNTER = 'shuffle_session_counter'  # the number of times this wallet window has run cashshuffle. Incremented on each enabling, per wallet.
        SHUFFLE_COUNTER = 'shuffle_shuffle_counter'  # the number of successful shuffles we have performed with this plugin for this wallet.
        COINS_FROZEN_BY_SHUFFLING = 'coins_frozen_by_shuffling' # list of coins frozen by shuffling. in case we crash.
        SPEND_MODE = 'shuffle_spend_mode' # the "spend shuffled" or "spend unshuffled" mode selected in the UI Send tab.
        SPEND_UNSHUFFLED_NAGGER_NOPROMPT = 'shuffle_spend_unshuffled_nonag'  # Whether or not to nag the user when they select "spend unshuffled" in Send tab.
        DISABLE_NAGGER_NOPROMPT = 'shuffle_disable_nonag'
