import "../controls"

WizardComponent {
    valid: true

    onAccept: {
        var p = {}
        p['enabled'] = pc.proxy_enabled
        if (pc.proxy_enabled) {
            var type = pc.proxy_types[pc.proxy_type].toLowerCase()
            if (type == 'tor')
                type = 'socks5'
            p['mode'] = type
            p['host'] = pc.proxy_address
            p['port'] = pc.proxy_port
            p['user'] = pc.username
            p['password'] = pc.password
        }
        wizard_data['proxy'] = p
    }

    ProxyConfig {
        id: pc
        width: parent.width
    }
}
