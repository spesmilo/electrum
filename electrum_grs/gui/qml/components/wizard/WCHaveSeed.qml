import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: false

    property bool is2fa: false
    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey: wizard_data['multisig_master_pubkey']

    function apply() {
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed'] = seedtext.text
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_type'] = bitcoin.seed_type
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extend'] = extendcb.checked
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
        } else {
            wizard_data['seed'] = seedtext.text
            wizard_data['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['seed_type'] = bitcoin.seed_type
            wizard_data['seed_extend'] = extendcb.checked
            wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
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
        validationtext.text = ''

        var validSeed = bitcoin.verifySeed(seedtext.text, seed_variant_cb.currentValue, wizard_data['wallet_type'])
        if (!cosigner || !validSeed) {
            valid = validSeed
            return
        } else {
            apply()
            if (wiz.hasDuplicateKeys(wizard_data)) {
                validationtext.text = qsTr('Error: duplicate master public key')
                return
            } else {
                valid = true
            }
        }
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
                Layout.fillWidth: true
                Layout.columnSpan: 2
            }

            SeedTextArea {
                id: seedtext
                Layout.fillWidth: true
                Layout.columnSpan: 2

                placeholderText: cosigner ? qsTr('Enter cosigner seed') : qsTr('Enter your seed')

                onTextChanged: {
                    startValidationTimer()
                }

                Rectangle {
                    anchors.fill: contentText
                    color: root.valid ? 'green' : 'red'
                    border.color: Material.accentColor
                    radius: 2
                }
                Label {
                    id: contentText
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    leftPadding: text != '' ? constants.paddingLarge : 0
                    rightPadding: text != '' ? constants.paddingLarge : 0
                    font.bold: false
                    font.pixelSize: constants.fontSizeSmall
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

            CheckBox {
                id: extendcb
                Layout.columnSpan: 2
                text: qsTr('Extend seed with custom words')
                onCheckedChanged: startValidationTimer()
            }
            TextField {
                id: customwordstext
                visible: extendcb.checked
                Layout.fillWidth: true
                Layout.columnSpan: 2
                placeholderText: qsTr('Enter your custom word(s)')
                onTextChanged: startValidationTimer()
            }
        }
    }

    Bitcoin {
        id: bitcoin
        onSeedTypeChanged: contentText.text = bitcoin.seed_type
        onValidationMessageChanged: validationtext.text = validationMessage
    }

    function startValidationTimer() {
        valid = false
        contentText.text = ''
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
