import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: false

    property int cosigner: 0
    property int participants: 0

    function apply() {
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['master_key'] = masterkey_ta.text
        } else {
            wizard_data['master_key'] = masterkey_ta.text
        }
    }

    function verifyMasterKey(key) {
        valid = false
        validationtext.text = ''

        if (!bitcoin.verifyMasterKey(key.trim(), wizard_data['wallet_type'])) {
            validationtext.text = qsTr('Error: invalid master key')
            return false
        }

        if (cosigner) {
            apply()
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
            text: qsTr('Cosigner #%1 of %2').arg(cosigner).arg(participants)
            visible: cosigner
        }

        Label {
            text: qsTr('Create keystore from a master key')
        }

        RowLayout {
            TextArea {
                id: masterkey_ta
                Layout.fillWidth: true
                Layout.minimumHeight: 80
                font.family: FixedFont
                focus: true
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: verifyMasterKey(text)
            }
            ColumnLayout {
                ToolButton {
                    icon.source: '../../../icons/paste.png'
                    icon.height: constants.iconSizeMedium
                    icon.width: constants.iconSizeMedium
                    onClicked: {
                        masterkey_ta.text = AppController.clipboardToText()
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
                            masterkey_ta.text = scan.scanData
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
    }
}
