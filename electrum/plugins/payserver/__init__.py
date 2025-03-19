from electrum.simple_config import ConfigVar, SimpleConfig

SimpleConfig.PAYSERVER_PORT = ConfigVar('payserver_port', default=8080, type_=int)
SimpleConfig.PAYSERVER_ROOT = ConfigVar('payserver_root', default='/r', type_=str)
SimpleConfig.PAYSERVER_ALLOW_CREATE_INVOICE = ConfigVar('payserver_allow_create_invoice', default=False, type_=bool)
