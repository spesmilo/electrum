from electrum.simple_config import ConfigVar, SimpleConfig

SimpleConfig.SWAPSERVER_PORT = ConfigVar('plugins.swapserver.port', default=None, type_=int, plugin=__name__)
SimpleConfig.SWAPSERVER_FEE_MILLIONTHS = ConfigVar('plugins.swapserver.fee_millionths', default=5000, type_=int, plugin=__name__)
SimpleConfig.SWAPSERVER_ANN_POW_NONCE = ConfigVar('plugins.swapserver.ann_pow_nonce', default=0, type_=int, plugin=__name__)
