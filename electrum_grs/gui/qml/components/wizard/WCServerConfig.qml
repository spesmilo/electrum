import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: true
    last: true

    onAccept: {
        wizard_data['oneserver'] = !auto_server.checked
        wizard_data['server'] = address.text
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Server settings')
        }

        CheckBox {
            id: auto_server
            text: qsTr('Select server automatically')
            checked: true
        }

        GridLayout {
            columns: 2
            Layout.fillWidth: true

            Label {
                text: qsTr("Server")
                enabled: address.enabled
            }

            TextField {
                id: address
                enabled: !auto_server.checked
            }
        }
    }

}
