import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root
    securePage: true

    valid: false

    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey

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

        if (!key) {
            validationtext.text = ''
            return false
        }

        if (!bitcoin.verifyMasterKey(key, wizard_data['wallet_type'])) {
            validationtext.text = qsTr('Error: invalid master key')
            return false
        }

        if (cosigner) {
            applyMasterKey(key)
            if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                validationtext.text = qsTr('Error: duplicate master public key')
                return false
            }
            if (wiz.hasHeterogeneousMasterKeys(wizard_data)) {
                validationtext.text = qsTr('Error: master public key types do not match')
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
                        var dialog = app.genericShareDialog.createObject(app, {
                            title: qsTr('Master public key'),
                            text: multisigMasterPubkey
                        })
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
            text: qsTr('Cosigner #%1 of %2').arg(cosigner).arg(participants)
            visible: cosigner
        }

        Label {
            Layout.fillWidth: true
            text: cosigner
                    ? qsTr('Enter cosigner master public key')
                    : qsTr('Create keystore from a master key')
            wrapMode: Text.Wrap
        }

        RowLayout {
            ElTextArea {
                id: masterkey_ta
                Layout.fillWidth: true
                Layout.minimumHeight: 160
                font.family: FixedFont
                wrapMode: TextEdit.WrapAnywhere
                onTextChanged: {
                    if (activeFocus)
                        verifyMasterKey(text)
                }
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                background: PaneInsetBackground {
                    baseColor: constants.darkerDialogBackground
                }
            }
            ColumnLayout {
                Layout.alignment: Qt.AlignTop
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
                        var dialog = app.scanDialog.createObject(app, {
                            hint: cosigner
                                ? qsTr('Scan a cosigner master public key')
                                : qsTr('Scan a master key')
                        })
                        dialog.onFound.connect(function() {
                            if (verifyMasterKey(dialog.scanData))
                                masterkey_ta.text = dialog.scanData
                            else
                                masterkey_ta.text = ''
                            dialog.close()
                        })
                        dialog.open()
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

    Bitcoin {
        id: bitcoin
        onValidationMessageChanged: {
            validationtext.text = validationMessage
        }
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == 'multisig') {
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
            participants = wizard_data['multisig_participants']

            if ('multisig_master_pubkey' in wizard_data) {
                multisigMasterPubkey = wizard_data['multisig_master_pubkey']
            }
        }
        Qt.callLater(masterkey_ta.forceActiveFocus)
    }
}
