import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: pc.valid
    title: qsTr('Proxy')

    function apply() {
        wizard_data['proxy'] = pc.toProxyDict()
    }

    ColumnLayout {
        width: parent.width
        spacing: constants.paddingLarge

        ProxyConfig {
            id: pc
            Layout.fillWidth: true
            proxy_enabled: false

            Component.onCompleted: {
                pc.doh_endpoint = Network.proxy['doh_endpoint']
            }
        }
    }
}
