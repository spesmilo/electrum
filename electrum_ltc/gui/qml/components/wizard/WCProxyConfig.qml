import "../controls"

WizardComponent {
    valid: true

    onAccept: {
        wizard_data['proxy'] = pc.toProxyDict()
    }

    ProxyConfig {
        id: pc
        width: parent.width
    }
}
