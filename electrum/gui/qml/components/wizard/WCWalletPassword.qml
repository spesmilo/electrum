import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: password1.text === password2.text

    onAccept: {
        wizard_data['password'] = password1.text
        wizard_data['encrypt'] = doencrypt.checked
    }

    GridLayout {
        columns: 1
        Label { text: qsTr('Password protect wallet?') }
        TextField {
            id: password1
            echoMode: TextInput.Password
        }
        TextField {
            id: password2
            echoMode: TextInput.Password
        }
        CheckBox {
            id: doencrypt
            enabled: password1.text !== ''
            text: qsTr('Encrypt wallet')
        }
    }
}
