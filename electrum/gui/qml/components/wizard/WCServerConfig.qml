import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true
    last: true
    title: qsTr('Server')

    function apply() {
        wizard_data['autoconnect'] = sc.address.trim() == ""
        wizard_data['server'] = sc.address
        wizard_data['one_server'] = sc.one_server
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: constants.paddingLarge

        ServerConfig {
            id: sc
            showAutoselectServer: false
            Layout.fillWidth: true
            Layout.fillHeight: true
        }
    }
}
