from electrum.simple_config import ConfigVar
config_vars = [
    ConfigVar('payserver_port', default=8080, type_=int),
    ConfigVar('payserver_root', default='/r', type_=str),
    ConfigVar('payserver_allow_create_invoice', default=False, type_=bool),
]
