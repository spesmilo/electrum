import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

WizardComponent {
    valid: keystoregroup.checkedButton !== null

    onAccept: {
        wizard_data['keystore_type'] = keystoregroup.checkedButton.keystoretype
    }

    ButtonGroup {
        id: keystoregroup
    }

    GridLayout {
        columns: 1
        Label { text: qsTr('What kind of wallet do you want to create?') }
        RadioButton {
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'createseed'
            checked: true
            text: qsTr('Create a new seed')
        }
        RadioButton {
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'haveseed'
            text: qsTr('I already have a seed')
        }
        RadioButton {
            enabled: false
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'masterkey'
            text: qsTr('Use a master key')
        }
        RadioButton {
            enabled: false
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'hardware'
            text: qsTr('Use a hardware device')
        }
    }
}

