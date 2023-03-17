import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: false

    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey: wizard_data['multisig_master_pubkey']

    function apply() {
        applyMasterKey(masterkey_ta.text)
    }

    function applyMasterKey(key) {
        key = key.trim()
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['master_key'] = key
        } else {
            wizard_data['master_key'] = key
        }
    }

    function verifyMasterKey(key) {
        valid = false
        validationtext.text = ''
        key = key.trim()

        if (!bitcoin.verifyMasterKey(key, wizard_data['wallet_type'])) {
            validationtext.text = qsTr('Error: invalid master key')
            return false
        }

        if (cosigner) {
            applyMasterKey(key)
            if (wiz.hasDuplicateKeys(wizard_data)) {
                validationtext.text = qsTr('Error: duplicate master public key')
                return false
            }
        }

        return valid = true
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
            Layout.preferredWidth: parent.width
            Layout.preferredHeight: 1
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            visible: cosigner
            color: Material.accentColor
        }

        Label {
            text: qsTr('Cosigner #%1 of %2').arg(cosigner).arg(participants)
            visible: cosigner
        }

        Label {
            text: cosigner
                    ? qsTr('Enter cosigner master public key')
                    : qsTr('Create keystore from a master key')
        }

        RowLayout {
            TextArea {
                id: masterkey_ta
                Layout.fillWidth: true
                Layout.minimumHeight: 80
                font.family: FixedFont
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: {
                    if (activeFocus)
                        verifyMasterKey(text)
                }
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
            }
            ColumnLayout {
                ToolButton {
                    icon.source: '../../../icons/paste.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    onClicked: {
                        if (verifyMasterKey(AppController.clipboardToText()))
                            masterkey_ta.text = AppController.clipboardToText()
                        else
                            masterkey_ta.text = ''
                    }
                }
                ToolButton {
                    icon.source: '../../../icons/qrcode.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    scale: 1.2
                    onClicked: {
                        var scan = qrscan.createObject(root)
                        scan.onFound.connect(function() {
                            if (verifyMasterKey(scan.scanData))
                                masterkey_ta.text = scan.scanData
                            else
                                masterkey_ta.text = ''
                            scan.destroy()
                        })
                    }
                }
            }
        }

        TextArea {
            id: validationtext
            visible: text
            Layout.fillWidth: true
            readOnly: true
            wrapMode: TextInput.WordWrap
            background: Rectangle {
                color: 'transparent'
            }
        }
    }

    Component {
        id: qrscan
        QRScan {
            width: root.width
            height: root.height

            ToolButton {
                icon.source: '../../../icons/closebutton.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                anchors.right: parent.right
                anchors.top: parent.top
                onClicked: {
                    parent.destroy()
                }
            }
        }
    }

    Bitcoin {
        id: bitcoin
        onValidationMessageChanged: validationtext.text = validationMessage
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == 'multisig') {
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
            participants = wizard_data['multisig_participants']
        }
        Qt.callLater(masterkey_ta.forceActiveFocus)
    }
}
