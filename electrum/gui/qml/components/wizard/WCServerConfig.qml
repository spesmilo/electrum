import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true
    last: true
    title: qsTr('Server')

    function apply() {
        wizard_data['server'] = sc.address
        wizard_data['autoconnect'] = sc.serverConnectMode == ServerConnectModeComboBox.Mode.Autoconnect
        wizard_data['one_server'] = sc.serverConnectMode == ServerConnectModeComboBox.Mode.Single
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: constants.paddingLarge

        ServerConfig {
            id: sc
            Layout.fillWidth: true
            Layout.fillHeight: true
        }
    }
}
