import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Item {
    property Component walletname: Component {
        WizardComponent {
            valid: wallet_name.text.length > 0

            onAccept: {
                wizard_data['wallet_name'] = wallet_name.text
            }

            GridLayout {
                columns: 1
                Label { text: qsTr('Wallet name') }
                TextField {
                    id: wallet_name
                }
            }
        }
    }

    property Component wallettype: Component {
        WizardComponent {
            valid: wallettypegroup.checkedButton !== null

            onAccept: {
                wizard_data['wallet_type'] = wallettypegroup.checkedButton.wallettype
            }

            ButtonGroup {
                id: wallettypegroup
            }

            GridLayout {
                columns: 1
                Label { text: qsTr('What kind of wallet do you want to create?') }
                RadioButton {
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: 'standard'
                    checked: true
                    text: qsTr('Standard Wallet')
                }
                RadioButton {
                    enabled: false
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: '2fa'
                    text: qsTr('Wallet with two-factor authentication')
                }
                RadioButton {
                    enabled: false
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: 'multisig'
                    text: qsTr('Multi-signature wallet')
                }
                RadioButton {
                    enabled: false
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: 'import'
                    text: qsTr('Import Bitcoin addresses or private keys')
                }
            }
        }
    }

    property Component keystore: Component {
        WizardComponent {
            valid: keystoregroup.checkedButton !== null

            onAccept: {
                wizard_data['keystore_type'] = keystoregroup.checkedButton.keystoretype
            }

            ButtonGroup {
                id: keystoregroup
            }

            GridLayout {
                columns: 1
                Label { text: qsTr('What kind of wallet do you want to create?') }
                RadioButton {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'createseed'
                    checked: true
                    text: qsTr('Create a new seed')
                }
                RadioButton {
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'haveseed'
                    text: qsTr('I already have a seed')
                }
                RadioButton {
                    enabled: false
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'masterkey'
                    text: qsTr('Use a master key')
                }
                RadioButton {
                    enabled: false
                    ButtonGroup.group: keystoregroup
                    property string keystoretype: 'hardware'
                    text: qsTr('Use a hardware device')
                }
            }
        }

    }

    property Component createseed: Component {
        WizardComponent {
            valid: seedtext.text != ''

            onAccept: {
                wizard_data['seed'] = seedtext.text
                wizard_data['seed_type'] = 'segwit'
                wizard_data['seed_extend'] = extendcb.checked
                wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
            }

            function setWarningText(numwords) {
                var t = [
                    "<p>",
                    qsTr("Please save these %1 words on paper (order is important). ").arg(numwords),
                    qsTr("This seed will allow you to recover your wallet in case of computer failure."),
                    "</p>",
                    "<b>" + qsTr("WARNING") + ":</b>",
                    "<ul>",
                    "<li>" + qsTr("Never disclose your seed.") + "</li>",
                    "<li>" + qsTr("Never type it on a website.") + "</li>",
                    "<li>" + qsTr("Do not store it electronically.") + "</li>",
                    "</ul>"
                ]
                warningtext.text = t.join("")
            }

            GridLayout {
                width: parent.width
                columns: 1

                InfoTextArea {
                    id: warningtext
                    Layout.fillWidth: true
                    iconStyle: InfoTextArea.IconStyle.Warn
                }
                Label { text: qsTr('Your wallet generation seed is:') }
                TextArea {
                    id: seedtext
                    readOnly: true
                    Layout.fillWidth: true
                    wrapMode: TextInput.WordWrap
                    background: Rectangle {
                        color: "transparent"
                        border.color: Material.accentColor
                    }
                    leftInset: -5
                    rightInset: -5

                    BusyIndicator {
                        anchors.centerIn: parent
                        height: parent.height *2/3
                        visible: seedtext.text == ''
                    }

                }
                CheckBox {
                    id: extendcb
                    text: qsTr('Extend seed with custom words')
                }
                TextField {
                    id: customwordstext
                    visible: extendcb.checked
                    Layout.fillWidth: true
                    placeholderText: qsTr('Enter your custom word(s)')
                    echoMode: TextInput.Password
                }
                Component.onCompleted : {
                    setWarningText(12)
                    bitcoin.generate_seed()
                }
            }

            Bitcoin {
                id: bitcoin
                onGeneratedSeedChanged: {
                    seedtext.text = generated_seed
                    setWarningText(generated_seed.split(" ").length)
                }
            }
        }
    }

    property Component haveseed: Component {
        WizardComponent {
            valid: false

            onAccept: {
                wizard_data['seed'] = seedtext.text
                wizard_data['seed_extend'] = extendcb.checked
                wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
                wizard_data['seed_bip39'] = bip39cb.checked
            }

            function checkValid() {
            }

            function setSeedTypeHelpText() {
                var t = {
                    'Electrum': [
                        qsTr('Electrum seeds are the default seed type.'),
                        qsTr('If you are restoring from a seed previously created by Electrum, choose this option')
                    ].join(' '),
                    'BIP39': [
                        qsTr('BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                        '<br/><br/>',
                        qsTr('However, we do not generate BIP39 seeds, because they do not meet our safety standard.'),
                        qsTr('BIP39 seeds do not include a version number, which compromises compatibility with future software.'),
                        '<br/><br/>',
                        qsTr('We do not guarantee that BIP39 imports will always be supported in Electrum.')
                    ].join(' '),
                    'SLIP39': [
                        qsTr('SLIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                        '<br/><br/>',
                        qsTr('However, we do not generate SLIP39 seeds.')
                    ].join(' ')
                }
                infotext.text = t[seed_type.currentText]
            }

            GridLayout {
                width: parent.width
                columns: 2

                Label {
                    text: qsTr('Seed Type')
                }
                ComboBox {
                    id: seed_type
                    model: ['Electrum', 'BIP39', 'SLIP39']
                    onActivated: setSeedTypeHelpText()
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
                TextArea {
                    id: seedtext
                    wrapMode: TextInput.WordWrap
                    Layout.fillWidth: true
                    Layout.columnSpan: 2
                    background: Rectangle {
                        color: "transparent"
                        border.color: Material.accentColor
                    }
                    leftInset: -5
                    rightInset: -5
                    onTextChanged: {
                        checkValid()
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
                    echoMode: TextInput.Password
                }
            }

            Bitcoin {
                id: bitcoin
            }
            Component.onCompleted: {
                setSeedTypeHelpText()
            }
        }
    }

    property Component confirmseed: Component {
        WizardComponent {
            valid: false

            function checkValid() {
                var seedvalid = confirm.text == wizard_data['seed']
                var customwordsvalid =  customwordstext.text == wizard_data['seed_extra_words']
                valid = seedvalid && (wizard_data['seed_extend'] ? customwordsvalid : true)
            }

            GridLayout {
                width: parent.width
                columns: 1

                InfoTextArea {
                    Layout.fillWidth: true
                    text: qsTr('Your seed is important!') + ' ' +
                        qsTr('If you lose your seed, your money will be permanently lost.') + ' ' +
                        qsTr('To make sure that you have properly saved your seed, please retype it here.')
                }
                Label { text: qsTr('Confirm your seed (re-enter)') }
                TextArea {
                    id: confirm
                    wrapMode: TextInput.WordWrap
                    Layout.fillWidth: true
                    onTextChanged: {
                        checkValid()
                    }
                }
                TextField {
                    id: customwordstext
                    Layout.fillWidth: true
                    placeholderText: qsTr('Enter your custom word(s)')
                    echoMode: TextInput.Password
                    onTextChanged: {
                        checkValid()
                    }
                }
            }

            onReadyChanged: {
                if (ready)
                    customwordstext.visible = wizard_data['seed_extend']
            }
        }
    }

    property Component walletpassword: Component {
        WizardComponent {
            valid: password1.text === password2.text

            onAccept: {
                wizard_data['password'] = password1.text
                wizard_data['encrypt'] = doencrypt.checked
            }

            GridLayout {
                columns: 1
                Label { text: qsTr('Password protect wallet?') }
                TextField {
                    id: password1
                    echoMode: TextInput.Password
                }
                TextField {
                    id: password2
                    echoMode: TextInput.Password
                }
                CheckBox {
                    id: doencrypt
                    enabled: password1.text !== ''
                    text: qsTr('Encrypt wallet')
                }
            }
        }
    }


}
