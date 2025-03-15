from electrum.simple_config import ConfigVar
config_vars = [
    ConfigVar('watchtower_server_port', default=None, type_=int),
    ConfigVar('watchtower_server_user', default=None, type_=str),
    ConfigVar('watchtower_server_password', default=None, type_=str),
]
