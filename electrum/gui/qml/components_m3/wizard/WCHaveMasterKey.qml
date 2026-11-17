import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: a master key (xprv / xpub) for a new wallet or for a cosigner of a multisig wallet.
// repeats: components/wizard/WCHaveMasterKey.qml:10-211 @ e6df7e1c8 (securePage, valid, cosigner, participants,
// multisigMasterPubkey; apply() / applyMasterKey(); verifyMasterKey() with bitcoin.verifyMasterKey and the duplicate /
// heterogeneous checks of a cosigner; the two versions of the explanation; the key field verified on every change
// while it has the focus; paste (verified, else the field is cleared) and scan (app.scanDialog with the hint, the same
// check, close); the validation text, also set from Bitcoin.validationMessage; Component.onCompleted reading
// wizard_data and the focus in the field).
// Look (DESIGN-M2-onboarding.md 3.1): CosignerHeader (the master public key to share, "Cosigner #%1 of %2"), the
// explanation, an outlined M3TextArea in the fixed font with the icon buttons paste / scan beside it, the error
// below in m3.error. The page scrolls (the classic page does not) and keeps the field visible above the keyboard.
// Strings carried over keep the translation context of WCHaveMasterKey.qml.
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
            validationtext.text = qsTranslate('WCHaveMasterKey', 'Error: invalid master key')
            return false
        }

        if (cosigner) {
            applyMasterKey(key)
            if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                validationtext.text = qsTranslate('WCHaveMasterKey', 'Error: duplicate master public key')
                return false
            }
            if (wiz.hasHeterogeneousMasterKeys(wizard_data)) {
                validationtext.text = qsTranslate('WCHaveMasterKey', 'Error: master public key types do not match')
                return false
            }
        }

        return valid = true
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: {
            if (masterkey_ta.anyActiveFocus)
                root.ensureVisible(flick, keyRow)
        }

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            CosignerHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                pubkey: multisigMasterPubkey
                cosigner: root.cosigner
                participants: root.participants
            }

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: cosigner ? 0 : m3.space8
                role: 'bodyLarge'
                wrapMode: Text.Wrap
                text: cosigner
                        ? [qsTranslate('WCHaveMasterKey', 'Please enter the master public key (xpub) of your cosigner.'),
                           qsTranslate('WCHaveMasterKey', 'Enter their master private key (xprv) if you want to be able to sign for them.')
                           ].join('\n')
                        : [qsTranslate('WCHaveMasterKey', 'Please enter your master private key (xprv).'),
                           qsTranslate('WCHaveMasterKey', 'You can also enter a public key (xpub) here, but be aware you will then create a watch-only wallet if all cosigners are added using public keys')
                           ].join('\n')
            }

            RowLayout {
                id: keyRow
                Layout.fillWidth: true
                spacing: m3.space4

                M3TextArea {
                    id: masterkey_ta
                    Layout.fillWidth: true
                    Layout.minimumHeight: 160
                    Layout.preferredHeight: 160
                    font.family: FixedFont
                    wrapMode: TextEdit.WrapAnywhere
                    errorText: validationtext.text
                    onTextChanged: {
                        if (anyActiveFocus) {
                            verifyMasterKey(text)
                        }
                    }
                    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                }
                ColumnLayout {
                    Layout.alignment: Qt.AlignTop
                    spacing: 0
                    M3IconButton {
                        icon.source: Qt.resolvedUrl('../../../icons/m3/content_paste.png')
                        tooltip: qsTranslate('SendDialog', 'Paste')
                        onClicked: {
                            if (verifyMasterKey(AppController.clipboardToText()))
                                masterkey_ta.text = AppController.clipboardToText()
                            else
                                masterkey_ta.text = ''
                        }
                    }
                    M3IconButton {
                        icon.source: Qt.resolvedUrl('../../../icons/m3/qr_code_scanner.png')
                        tooltip: cosigner
                            ? qsTranslate('WCHaveMasterKey', 'Scan a cosigner master public key')
                            : qsTranslate('WCHaveMasterKey', 'Scan a master key')
                        onClicked: {
                            var dialog = app.scanDialog.createObject(app, {
                                hint: cosigner
                                    ? qsTranslate('WCHaveMasterKey', 'Scan a cosigner master public key')
                                    : qsTranslate('WCHaveMasterKey', 'Scan a master key')
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

            M3Text {
                id: validationtext
                visible: text
                Layout.fillWidth: true
                Layout.leftMargin: m3.space16
                Layout.rightMargin: m3.space16 + 48
                role: 'bodySmall'
                color: m3.error
                wrapMode: Text.Wrap
            }
        }
    }

    Connections {
        target: masterkey_ta.textArea
        function onActiveFocusChanged() {
            if (masterkey_ta.textArea.activeFocus)
                Qt.callLater(root.ensureVisible, flick, keyRow)
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
        Qt.callLater(masterkey_ta.textArea.forceActiveFocus)
    }
}
