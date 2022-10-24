import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../../../gui/qml/components/wizard"

WizardComponent {
    valid: keystoregroup.checkedButton !== null

    onAccept: {
        wizard_data['keystore_type'] = keystoregroup.checkedButton.keystoretype
    }

    ButtonGroup {
        id: keystoregroup
    }

    ColumnLayout {
        width: parent.width
        Label {
            text: qsTr('Do you want to create a new seed, or restore a wallet using an existing seed?')
            Layout.preferredWidth: parent.width
            wrapMode: Text.Wrap
        }
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
    }
}

