import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true

    function apply() {
        wizard_data['autoconnect'] = serverconnectgroup.checkedButton.connecttype === 'auto'
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true
            text: qsTr('How do you want to connect to a server?')
            wrapMode: Text.Wrap
        }

        InfoTextArea {
            Layout.fillWidth: true
            text: qsTr('Electrum communicates with remote servers to get information about your transactions and addresses. The servers all fulfill the same purpose only differing in hardware. In most cases you simply want to let Electrum pick one at random.  However if you prefer feel free to select a server manually.')
        }

        ButtonGroup {
            id: serverconnectgroup
            onCheckedButtonChanged: checkIsLast()
        }

        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: serverconnectgroup
            property string connecttype: 'auto'
            text: qsTr('Auto connect')
            checked: true
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: serverconnectgroup
            property string connecttype: 'manual'
            text: qsTr('Select servers manually')
        }

    }

}
