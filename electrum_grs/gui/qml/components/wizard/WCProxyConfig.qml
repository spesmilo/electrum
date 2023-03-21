import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

WizardComponent {
    valid: true

    function apply() {
        wizard_data['proxy'] = pc.toProxyDict()
    }

    ColumnLayout {
        width: parent.width
        spacing: constants.paddingLarge

        Label {
            text: qsTr('Proxy settings')
        }

        ProxyConfig {
            id: pc
            Layout.fillWidth: true
            proxy_enabled: true
        }
    }
}
