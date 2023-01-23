import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

WizardComponent {
    valid: password1.text === password2.text && password1.text.length > 4

    function apply() {
        wizard_data['password'] = password1.text
        wizard_data['encrypt'] = password1.text != ''
    }

    GridLayout {
        columns: 1
        Label { text: qsTr('Password protect wallet?') }
        PasswordField {
            id: password1
        }
        PasswordField {
            id: password2
        }
    }
}
