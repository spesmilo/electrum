IRC is used by Electrum server to find 'peers' - other Electrum servers. The current list can be seen by running:

./server.py peers

The following config file options are used by the IRC part of Electrum server:

[server]
irc = yes
host = fqdn.host.name.tld
ircname = some short description

'irc' is used to determine whether the IRC thread will be started or the Electrum server will run in private mode. In private mode, ./server.py peers will always return an empty list.

'host' is a fqdn of your Electrum server. It is used both when binding the listener for incoming client connections, and also as part of the realname field in IRC (see below).

'ircname' is a short text that will be appended to 'host' when composing the IRC realname field:

realname = 'host' + ' ' + 'ircname', for example 'fqdn.host.name.tld some short description'
