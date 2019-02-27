#!/usr/bin/env python3

# Old keys from previous versions. Will clean them up from config if seen.
DELETE_KEYS = ('cashshuffle_server', 'cashshuffle_server_v1', 'shuffle_noprompt')

# The below go in global config:
SHUFFLE_SERVER_KEY = "cashshuffle_server_v2" # specifies server config to use
SHUFFLE_NAGGER_NOPROMPT = 'shuffle_noprompt2' # specifies whether to nag user about "this wallet has cashshuffle disabled" on wallet startup. see main_window.py
# /global config

# The below are per-wallet and go in wallet.storage
CASHSHUFFLE_ENABLED = 'cashshuffle_enabled'  # whether cashshuffle is enabeld for this wallet.
COINS_FROZEN_BY_SHUFFLING = 'coins_frozen_by_shuffling' # list of coins frozen by shuffling. in case we crash.
SHUFFLE_SPEND_MODE = 'shuffle_spend_mode' # the "spend shuffled" or "spend unshuffled" mode selected in the UI Send tab.
SPEND_UNSHUFFLED_NAGGER_NOPROMPT = 'shuffle_spend_unshuffled_nonag'  # Whether or not to nag the user when they select "spend unshuffled" in Send tab.
# /wallet.storage
