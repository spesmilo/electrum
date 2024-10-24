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
        var seed_extend = extendcb.checked && _canPassphrase
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed'] = seedtext.text
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_type'] = _seedType
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extend'] = seed_extend
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extra_words'] = seed_extend ? customwordstext.text : ''
        } else {
            wizard_data['seed'] = seedtext.text
            wizard_data['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['seed_type'] = _seedType
            wizard_data['seed_extend'] = seed_extend
            wizard_data['seed_extra_words'] = seed_extend ? customwordstext.text : ''

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
                qsTr('Electrum seeds are the default seed type.'),
                qsTr('If you are restoring from a seed previously created by Electrum, choose this option')
            ].join(' '),
            'bip39': [
                qsTr('BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                '<br/><br/>',
                qsTr('However, we do not generate BIP39 seeds, because they do not meet our safety standard.'),
                qsTr('BIP39 seeds do not include a version number, which compromises compatibility with future software.')
            ].join(' '),
            'slip39': [
                qsTr('SLIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                '<br/><br/>',
                qsTr('However, we do not generate SLIP39 seeds.')
            ].join(' ')
        }
        infotext.text = t[seed_variant_cb.currentValue]
    }

    function checkValid() {
        valid = false
        _seedValid = false

        var verifyResult = wiz.verifySeed(seedtext.text, seed_variant_cb.currentValue, wizard_data['wallet_type'])

        _validationMessage = verifyResult.message
        _seedType = verifyResult.type
        _canPassphrase = verifyResult.can_passphrase

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

        if (_canPassphrase && extendcb.checked && customwordstext.text == '') {
            valid = false
            return
        }

        valid = _seedValid
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

            TextHighlightPane {
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
                    { text: qsTr('Electrum'), value: 'electrum' },
                    { text: qsTr('BIP39'), value: 'bip39' }
                ]
                onActivated: {
                    setSeedTypeHelpText()
                    checkIsLast()
                    checkValid()
                }
            }

            InfoTextArea {
                id: infotext
                visible: !cosigner && !is2fa
                Layout.fillWidth: true
                Layout.columnSpan: 2
                Layout.bottomMargin: constants.paddingLarge
            }

            SeedTextArea {
                id: seedtext
                Layout.fillWidth: true
                Layout.columnSpan: 2

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
                visible: _canPassphrase
                text: qsTr('Extend seed with custom words')
                onCheckedChanged: startValidationTimer()
            }

            TextField {
                id: customwordstext
                visible: extendcb.checked && extendcb.visible
                Layout.fillWidth: true
                Layout.columnSpan: 2
                placeholderText: qsTr('Enter your custom word(s)')
                inputMethodHints: Qt.ImhNoPredictiveText

                onTextChanged: startValidationTimer()
            }
        }
    }

    function startValidationTimer() {
        valid = false
        root._seedType = ''
        root._validationMessage = ''
        validationTimer.restart()
    }

    Timer {
        id: validationTimer
        interval: 500
        repeat: false
        onTriggered: checkValid()
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
