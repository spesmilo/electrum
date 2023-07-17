import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true

    function apply() {
        wizard_data['proxy'] = pc.toProxyDict()
    }

    ColumnLayout {
        width: parent.width
        spacing: constants.paddingLarge

        ProxyConfig {
            id: pc
            Layout.fillWidth: true
            proxy_enabled: true
        }
    }
}
