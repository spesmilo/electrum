import "../controls"

WizardComponent {
    valid: true
    last: true

    function apply() {
        wizard_data['oneserver'] = !sc.auto_server
        wizard_data['server'] = sc.address
    }

    ServerConfig {
        id: sc
        width: parent.width
    }
}
