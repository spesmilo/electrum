import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: keystoregroup.checkedButton !== null

    function apply() {
        wizard_data['keystore_type'] = keystoregroup.checkedButton.keystoretype
    }

    ButtonGroup {
        id: keystoregroup
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true
            wrapMode: Text.Wrap
            text: qsTr('Do you want to create a new seed, restore using an existing seed, or restore from master key?')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'createseed'
            checked: true
            text: qsTr('Create a new seed')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'haveseed'
            text: qsTr('I already have a seed')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'masterkey'
            text: qsTr('Use a master key')
        }
        ElRadioButton {
            Layout.fillWidth: true
            enabled: false
            visible: false
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'hardware'
            text: qsTr('Use a hardware device')
        }
    }
}

