import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../controls"

WizardComponent {
    valid: true

    function apply() {
        wizard_data['autoconnect'] = serverconnectgroup.checkedButton.connecttype === 'auto'
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('How do you want to connect to a server?')
        }

        InfoTextArea {
            text: qsTr('Electrum communicates with remote servers to get information about your transactions and addresses. The servers all fulfill the same purpose only differing in hardware. In most cases you simply want to let Electrum pick one at random.  However if you prefer feel free to select a server manually.')
            Layout.fillWidth: true
        }

        ButtonGroup {
            id: serverconnectgroup
            onCheckedButtonChanged: checkIsLast()
        }

        RadioButton {
            ButtonGroup.group: serverconnectgroup
            property string connecttype: 'auto'
            text: qsTr('Auto connect')
            checked: true
        }
        RadioButton {
            ButtonGroup.group: serverconnectgroup
            property string connecttype: 'manual'
            text: qsTr('Select servers manually')
        }

    }

}
