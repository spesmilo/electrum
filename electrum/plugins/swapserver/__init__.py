from electrum.simple_config import ConfigVar
config_vars = [
    ConfigVar('swapserver_port', default=None, type_=int),
    ConfigVar('swapserver_fee_millionths', default=5000, type_=int),
    ConfigVar('swapserver_ann_pow_nonce', default=0, type_=int),
]
