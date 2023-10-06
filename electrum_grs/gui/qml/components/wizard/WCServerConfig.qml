import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

WizardComponent {
    valid: true
    last: true

    function apply() {
        wizard_data['autoconnect'] = false
        wizard_data['server'] = sc.address
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
