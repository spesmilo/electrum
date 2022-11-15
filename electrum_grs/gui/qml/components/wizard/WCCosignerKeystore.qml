import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: keystoregroup.checkedButton !== null

    property int cosigner: 0
    property int participants: 0

    function apply() {
        wizard_data['cosigner_keystore_type'] = keystoregroup.checkedButton.keystoretype
        wizard_data['multisig_current_cosigner'] = cosigner
        wizard_data['multisig_cosigner_data'][cosigner.toString()] = {}
    }

    ButtonGroup {
        id: keystoregroup
    }

    ColumnLayout {
        Label {
            text: qsTr('Add cosigner #%1 of %2 to your multi-sig wallet').arg(cosigner).arg(participants)
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

    Component.onCompleted: {
        participants = wizard_data['multisig_participants']

        // cosigner index is determined here and put on the wizard_data dict in apply()
        // as this page is the start for each additional cosigner
        cosigner = 2 + Object.keys(wizard_data['multisig_cosigner_data']).length
    }
}

