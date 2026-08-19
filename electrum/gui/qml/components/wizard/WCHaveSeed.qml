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

    property bool is2fa: false
    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey: wizard_data['multisig_master_pubkey']

    property string _seedType
    property string _validationMessage
    property bool _canPassphrase
    property bool _seedValid

    function apply() {
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed'] = seedtext.text
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_type'] = _seedType
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extend'] = extendcb.checked
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
        } else {
            wizard_data['seed'] = seedtext.text
            wizard_data['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['seed_type'] = _seedType
            wizard_data['seed_extend'] = extendcb.checked
            wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''

            // determine script type from electrum seed type
            // (used to limit script type options for bip39 cosigners)
            if (wizard_data['wallet_type'] == 'multisig' && seed_variant_cb.currentValue == 'electrum') {
                wizard_data['script_type'] = {
                    'standard': 'p2sh',
                    'segwit': 'p2wsh'
                }[_seedType]
            }
        }
    }

    function setSeedTypeHelpText() {
        var t = {
            'electrum': [
                // not shown as electrum is the default seed type anyways and the name is self-explanatory
                qsTr('Electrum seeds are the default seed type.'),
                qsTr('If you are restoring from a seed previously created by Electrum, choose this option')
            ].join(' '),
            'bip39': [
                qsTr('BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                qsTr('BIP39 seeds do not include a version number, which compromises compatibility with future software.'),
            ].join(' '),
            'slip39': [
                qsTr('SLIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
            ].join(' ')
        }
        infotext.text = t[seed_variant_cb.currentValue]
        infotext.visible = !cosigner && !is2fa && seed_variant_cb.currentValue != 'electrum'
    }

    function checkValid() {
        valid = false
        _seedValid = false

        var verifyResult = wiz.verifySeed(seedtext.text, seed_variant_cb.currentValue, wizard_data['wallet_type'])

        _validationMessage = verifyResult.message
        _seedType = verifyResult.type
        _canPassphrase = verifyResult.can_passphrase
        syncExtControls()

        if (!cosigner || !verifyResult.valid) {
            _seedValid = verifyResult.valid
        } else {
            // bip39 validate after derivation path is known
            if (seed_variant_cb.currentValue == 'electrum') {
                apply()
                if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                    _validationMessage = qsTr('Error: duplicate master public key')
                    return
                } else if (wiz.hasHeterogeneousMasterKeys(wizard_data)) {
                    _validationMessage = qsTr('Error: master public key types do not match')
                    return
                } else {
                    _seedValid = true
                }
            } else {
                _seedValid = true
            }
        }

        valid = _seedValid
    }

    function syncExtControls() {
        var variant = seed_variant_cb.currentValue
        if (variant == 'bip39') {
            extendcb.text = qsTr('Use a BIP39 passphrase')
            extreason.text = ''
            if (!seedtext.text.trim()) {
                extendcb.checked = false
                extendcb.enabled = false
            } else {
                extendcb.enabled = true
            }
            return
        }
        extendcb.text = qsTr('Extend this seed with custom words')
        if (!_seedType) {
            extendcb.checked = false
            extendcb.enabled = false
            extreason.text = ''
            return
        }
        if (!_canPassphrase) {
            extendcb.checked = false
            extendcb.enabled = false
            if (_seedType == 'old')
                extreason.text = qsTr('Old Electrum seeds have no extra word.')
            else
                extreason.text = qsTr('This seed cannot be extended with an extra word.')
            return
        }
        extendcb.enabled = true
        extreason.text = ''
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        GridLayout {
            id: mainLayout
            width: parent.width
            columns: 2

            Label {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                visible: cosigner
                text: qsTr('Here is your master public key. Please share it with your cosigners')
                wrapMode: Text.Wrap
            }

            DialogHighlightPane {
                Layout.columnSpan: 2
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
                Layout.columnSpan: 2
                Layout.preferredWidth: parent.width
                Layout.preferredHeight: 1
                Layout.topMargin: constants.paddingLarge
                Layout.bottomMargin: constants.paddingLarge
                visible: cosigner
                color: Material.accentColor
            }

            Label {
                Layout.columnSpan: 2
                visible: cosigner
                text: qsTr('Cosigner #%1 of %2').arg(cosigner).arg(participants)
            }

            Label {
                Layout.fillWidth: true
                visible: !is2fa
                text: qsTr('Seed Type')
            }

            ComboBox {
                id: seed_variant_cb

                visible: !is2fa

                textRole: 'text'
                valueRole: 'value'
                model: [
                    { text: 'Electrum', value: 'electrum' },
                    { text: 'BIP39', value: 'bip39' }
                ]
                onActivated: {
                    setSeedTypeHelpText()
                    checkIsLast()
                    checkValid()
                }
                delegate: ItemDelegate {
                    width: seed_variant_cb.width
                    text: modelData.text
                    // grey BIP39 only after an Electrum version actually decodes
                    enabled: !(modelData.value == 'bip39'
                               && seed_variant_cb.currentValue == 'electrum'
                               && root._seedType
                               && root._seedType != 'old')
                }
            }

            InfoTextArea {
                id: infotext
                Layout.fillWidth: true
                Layout.columnSpan: 2
                Layout.topMargin: constants.paddingLarge
                compact: true
                backgroundColor: constants.darkerDialogBackground
            }

            SeedTextArea {
                id: seedtext
                Layout.fillWidth: true
                Layout.columnSpan: 2
                Layout.topMargin: constants.paddingLarge

                placeholderText: cosigner ? qsTr('Enter cosigner seed') : qsTr('Enter your seed')

                indicatorValid: root._seedValid
                    ? root._seedType == 'bip39' && root._validationMessage
                        ? false
                        : root._seedValid
                    : root._seedValid
                indicatorText: root._validationMessage
                        ? root._validationMessage
                        : root._seedType
                onTextChanged: {
                    startValidationTimer()
                }
            }

            ElCheckBox {
                id: extendcb
                Layout.columnSpan: 2
                Layout.fillWidth: true
                enabled: false
                text: qsTr('Extend this seed with custom words')
                onCheckedChanged: checkIsLast()
            }

            Label {
                id: extreason
                Layout.columnSpan: 2
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: text
            }

            Label {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: extendcb.checked && extendcb.enabled
                text: seed_variant_cb.currentValue == 'bip39'
                    ? [
                        qsTr('Enter an optional BIP39 passphrase.'),
                        qsTr('Each passphrase derives a different wallet.'),
                        qsTr('This is sometimes incorrectly called the "25th word".'),
                        qsTr('Note that this is NOT your encryption password.'),
                        qsTr('If you do not know what this is, leave this field empty.'),
                    ].join(' ')
                    : [
                        qsTr('You may extend your seed with custom words.'),
                        qsTr('Your seed extension must be saved together with your seed.'),
                        qsTr('Note that this is NOT your encryption password.'),
                        qsTr('If you do not know what this is, leave this field empty.'),
                    ].join(' ')
            }

            TextField {
                id: customwordstext
                Layout.columnSpan: 2
                Layout.fillWidth: true
                visible: extendcb.checked && extendcb.enabled
                placeholderText: seed_variant_cb.currentValue == 'bip39'
                    ? qsTr('Enter your BIP39 passphrase')
                    : qsTr('Enter your custom word(s)')
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: checkIsLast()
            }
        }
    }

    function startValidationTimer() {
        valid = false
        root._seedType = ''
        root._validationMessage = ''
        syncExtControls()
        validationTimer.restart()
    }

    Timer {
        id: validationTimer
        interval: 500
        repeat: false
        onTriggered: {
            checkValid()
            // checkIsLast depends on seed_extend from the on-page checkbox
            checkIsLast()
        }
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == '2fa') {
            is2fa = true
        } else if (wizard_data['wallet_type'] == 'multisig') {
            participants = wizard_data['multisig_participants']
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
        }
        setSeedTypeHelpText()
        Qt.callLater(seedtext.forceActiveFocus)
    }

}
