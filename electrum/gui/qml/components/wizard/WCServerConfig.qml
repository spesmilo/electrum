import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

WizardComponent {
    valid: true
    last: true

    function apply() {
        wizard_data['oneserver'] = !sc.auto_server
        wizard_data['server'] = sc.address
    }

    ColumnLayout {
        width: parent.width
        spacing: constants.paddingLarge

        Label {
            text: qsTr('Server settings')
        }

        ServerConfig {
            id: sc
            width: parent.width
        }
    }
}
