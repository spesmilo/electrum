import "../controls"

WizardComponent {
    valid: true

    function apply() {
        wizard_data['proxy'] = pc.toProxyDict()
    }

    ProxyConfig {
        id: pc
        width: parent.width
    }
}
