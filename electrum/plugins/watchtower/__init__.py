from electrum.simple_config import ConfigVar, SimpleConfig

SimpleConfig.WATCHTOWER_SERVER_PORT = ConfigVar('plugins.watchtower.server_port', default=None, type_=int, plugin=__name__)
SimpleConfig.WATCHTOWER_SERVER_USER = ConfigVar('plugins.watchtower.server_user', default=None, type_=str, plugin=__name__)
SimpleConfig.WATCHTOWER_SERVER_PASSWORD = ConfigVar('plugins.watchtower.server_password', default=None, type_=str, plugin=__name__)
