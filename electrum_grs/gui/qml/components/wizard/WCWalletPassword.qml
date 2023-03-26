import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

WizardComponent {
    valid: password1.text === password2.text && password1.text.length >= 6

    function apply() {
        wizard_data['password'] = password1.text
        wizard_data['encrypt'] = password1.text != ''
    }

    ColumnLayout {
        Label {
            text: Daemon.singlePasswordEnabled
                ? qsTr('Enter password')
                : qsTr('Enter password for %1').arg(wizard_data['wallet_name'])
        }
        PasswordField {
            id: password1
        }
        Label {
            text: qsTr('Enter password (again)')
        }
        PasswordField {
            id: password2
            showReveal: false
            echoMode: password1.echoMode
            enabled: password1.text.length >= 6
        }
    }
}
