import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

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
            text: qsTr('How do you want to set up your 2FA wallet?')
            Layout.preferredWidth: parent.width
            wrapMode: Text.Wrap
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'cosigner_qr'
            checked: true
            text: qsTr('Scan the cosigner QR code displayed by Electrum desktop')
        }
        ElRadioButton {
            Layout.fillWidth: true
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'haveseed'
            text: qsTr('Restore from my 2FA seed, with two-factor authentication disabled')
        }
    }
}
