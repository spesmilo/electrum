import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: keystoregroup.checkedButton !== null

    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey: wizard_data['multisig_master_pubkey']

    function apply() {
        wizard_data['cosigner_keystore_type'] = keystoregroup.checkedButton.keystoretype
        wizard_data['multisig_current_cosigner'] = cosigner
        wizard_data['multisig_cosigner_data'][cosigner.toString()] = {
            'keystore_type': keystoregroup.checkedButton.keystoretype
        }
    }

    ButtonGroup {
        id: keystoregroup
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true

            visible: cosigner
            text: qsTr('Here is your master public key. Please share it with your cosigners')
            wrapMode: Text.Wrap
        }

        TextHighlightPane {
            Layout.fillWidth: true

            visible: cosigner

            RowLayout {
                width: parent.width
                Label {
                    Layout.fillWidth: true
                    text: multisigMasterPubkey
                    font.pixelSize: constants.fontSizeMedium
                    font.family: FixedFont
                    wrapMode: Text.Wrap
                }
                ToolButton {
                    icon.source: '../../../icons/share.png'
                    icon.color: 'transparent'
                    onClicked: {
                        var dialog = app.genericShareDialog.createObject(app,
                            { title: qsTr('Master public key'), text: multisigMasterPubkey }
                        )
                        dialog.open()
                    }
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            visible: cosigner
            color: Material.accentColor
        }

        Label {
            Layout.fillWidth: true
            text: qsTr('Add cosigner #%1 of %2 to your multi-sig wallet').arg(cosigner).arg(participants)
            wrapMode: Text.Wrap
        }
        ElRadioButton {
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'masterkey'
            checked: true
            text: qsTr('Cosigner key')
        }
        ElRadioButton {
            ButtonGroup.group: keystoregroup
            property string keystoretype: 'haveseed'
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

