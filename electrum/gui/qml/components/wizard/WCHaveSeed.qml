import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import ".."
import "../controls"

WizardComponent {
    id: root
    valid: false

    property bool is2fa: false

    function apply() {
        wizard_data['seed'] = seedtext.text
        wizard_data['seed_variant'] = seed_variant.currentValue
        wizard_data['seed_type'] = bitcoin.seed_type
        wizard_data['seed_extend'] = extendcb.checked
        wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
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
        infotext.text = t[seed_variant.currentValue]
    }

    function checkValid() {
        bitcoin.verify_seed(seedtext.text, seed_variant.currentValue, wizard_data['wallet_type'])
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
                visible: !is2fa
                text: qsTr('Seed Type')
                Layout.fillWidth: true
            }
            ComboBox {
                id: seed_variant
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
            Label {
                text: qsTr('Enter your seed')
                Layout.columnSpan: 2
            }
            SeedTextArea {
                id: seedtext
                Layout.fillWidth: true
                Layout.columnSpan: 2
                onTextChanged: {
                    validationTimer.restart()
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
                visible: text != ''
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
            }
            TextField {
                id: customwordstext
                visible: extendcb.checked
                Layout.fillWidth: true
                Layout.columnSpan: 2
                placeholderText: qsTr('Enter your custom word(s)')
            }
        }
    }

    Bitcoin {
        id: bitcoin
        onSeedTypeChanged: contentText.text = bitcoin.seed_type
        onSeedValidChanged: root.valid = bitcoin.seed_valid
        onValidationMessageChanged: validationtext.text = bitcoin.validation_message
    }

    Timer {
        id: validationTimer
        interval: 500
        repeat: false
        onTriggered: checkValid()
    }

    Component.onCompleted: {
        setSeedTypeHelpText()
    }

    onReadyChanged: {
        if (!ready)
            return

        if (wizard_data['wallet_type'] == '2fa')
            root.is2fa = true
    }
}
