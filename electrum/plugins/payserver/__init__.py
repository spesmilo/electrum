from electrum.simple_config import ConfigVar, SimpleConfig

SimpleConfig.PAYSERVER_PORT = ConfigVar('plugins.payserver.port', default=8080, type_=int, plugin=__name__)
SimpleConfig.PAYSERVER_ROOT = ConfigVar('plugins.payserver.root', default='/r', type_=str, plugin=__name__)
SimpleConfig.PAYSERVER_ALLOW_CREATE_INVOICE = ConfigVar('plugins.payserver.allow_create_invoice', default=False, type_=bool, plugin=__name__)
