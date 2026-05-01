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
            wizard_data['key_origin_derivation'] = derivation_tf.text.trim()
            wizard_data['key_origin_fingerprint'] = fingerprint_tf.text.trim().toLowerCase()
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
            validationtext.text = bitcoin.validationMessage
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

    function validateKeyOrigin() {
        if (cosigner || wizard_data['wallet_type'] === 'multisig')
            return true
        if (bitcoin.masterKeyDepth(masterkey_ta.text.trim()) <= 1)
            return true
        var msg = bitcoin.verifyKeyOriginInfo(
            masterkey_ta.text.trim(),
            derivation_tf.text.trim(),
            fingerprint_tf.text.trim()
        )
        keyOriginError.text = msg
        return msg === ''
    }

    function revalidate() {
        var keyOk = verifyMasterKey(masterkey_ta.text)
        var originOk = validateKeyOrigin()
        valid = keyOk && originOk
        if (keyOk)
            apply()
    }

    ColumnLayout {
        width: parent.width

        Label {
            Layout.fillWidth: true

            visible: cosigner
            text: qsTr('Here is your master public key. Please share it with your cosigners')
            wrapMode: Text.Wrap
        }

        DialogHighlightPane {
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
                    ? [qsTr('Please enter the master public key (xpub) of your cosigner.'),
                       qsTr('Enter their master private key (xprv) if you want to be able to sign for them.')
                       ].join('\n')
                    : [qsTr('Please enter your master private key (xprv).'),
                       qsTr('You can also enter a public key (xpub) here, but be aware you will then create a watch-only wallet if all cosigners are added using public keys.')
                       ].join('\n')
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
                    if (anyActiveFocus) {
                        revalidate()
                    }
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
                    onClicked: {
                        var dialog = app.scanDialog.createObject(app, {
                            hint: cosigner
                                ? qsTr('Scan a cosigner master public key')
                                : qsTr('Scan a master key')
                        })
                        dialog.onFoundText.connect(function(data) {
                            if (verifyMasterKey(data))
                                masterkey_ta.text = data
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

        ColumnLayout {
            id: keyOriginSection
            visible: !cosigner
                     && wizard_data['wallet_type'] !== 'multisig'
                     && bitcoin.masterKeyDepth(masterkey_ta.text.trim()) > 1
            Layout.fillWidth: true
            Layout.topMargin: constants.paddingMedium
            spacing: constants.paddingSmall

            Heading {
                    text: qsTr('Key Origin Info')
            }

            InfoTextArea {
                Layout.fillWidth: true
                text: qsTr('These fields may be required for a hardware wallet to sign the generated PSBTs.')
                font.pixelSize: constants.fontSizeSmall
            }

            Label {
                text: qsTr('Derivation path (optional)')
                font.pixelSize: constants.fontSizeSmall
            }
            TextField {
                id: derivation_tf
                Layout.fillWidth: true
                placeholderText: "m/84'/0'/0'"
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: {
                    if (anyActiveFocus) revalidate()
                }
            }

            Label {
                text: qsTr('BIP32 master fingerprint (optional)')
                font.pixelSize: constants.fontSizeSmall
            }
            TextField {
                id: fingerprint_tf
                Layout.fillWidth: true
                placeholderText: qsTr('8 hex chars, e.g. deadbeef')
                maximumLength: 8
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: {
                    if (anyActiveFocus) revalidate()
                }
            }

            InfoTextArea {
                id: keyOriginError
                Layout.fillWidth: true
                visible: text !== ''
                iconStyle: InfoTextArea.IconStyle.Error
                font.pixelSize: constants.fontSizeSmall
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
