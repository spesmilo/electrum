import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: keystoregroup.checkedButton !== null

    function apply() {
        wizard_data['cosigner_keystore_type'] = keystoregroup.checkedButton.keystoretype
    }

    ButtonGroup {
        id: keystoregroup
    }

    ColumnLayout {
        Label {
            text: qsTr('Add a cosigner to your multi-sig wallet')
        }
        RadioButton {
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'key'
            checked: true
            text: qsTr('Cosigner key')
        }
        RadioButton {
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'seed'
            text: qsTr('Cosigner seed')
        }
    }
}

