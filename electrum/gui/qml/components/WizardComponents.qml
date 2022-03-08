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
            valid: true

            onAccept: {
                wizard_data['seed'] = seedtext.text
                wizard_data['seed_type'] = 'segwit'
                wizard_data['seed_extend'] = extendcb.checked
                wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
            }

            GridLayout {
                width: parent.width
                columns: 1

                TextArea {
                    id: warningtext
                    readOnly: true
                    Layout.fillWidth: true
                    wrapMode: TextInput.WordWrap
                    textFormat: TextEdit.RichText
                    background: Rectangle { color: "transparent" }
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
                    bitcoin.generate_seed()
                }
            }

            Bitcoin {
                id: bitcoin
                onGeneratedSeedChanged: {
                    seedtext.text = generated_seed

                    var t = [
                        "<p>",
                        qsTr("Please save these %1 words on paper (order is important). ").arg(generated_seed.split(" ").length),
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
            }
        }
    }

    property Component haveseed: Component {
        WizardComponent {
            valid: true

            onAccept: {
                wizard_data['seed'] = seedtext.text
                wizard_data['seed_extend'] = extendcb.checked
                wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
                wizard_data['seed_bip39'] = bip39cb.checked
            }

            GridLayout {
                width: parent.width
                columns: 1

                Label { text: qsTr('Enter your seed') }
                TextArea {
                    id: seedtext
                    wrapMode: TextInput.WordWrap
                    Layout.fillWidth: true
                    background: Rectangle {
                        color: "transparent"
                        border.color: Material.accentColor
                    }
                    leftInset: -5
                    rightInset: -5
                }
                CheckBox {
                    id: extendcb
                    enabled: true
                    text: qsTr('Extend seed with custom words')
                }
                TextField {
                    id: customwordstext
                    visible: extendcb.checked
                    Layout.fillWidth: true
                    placeholderText: qsTr('Enter your custom word(s)')
                    echoMode: TextInput.Password
                }
                CheckBox {
                    id: bip39cb
                    enabled: true
                    text: qsTr('BIP39')
                }
            }

            Bitcoin {
                id: bitcoin
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

                TextArea {
                    readOnly: true
                    Layout.fillWidth: true
                    wrapMode: TextInput.WordWrap
                    text: qsTr('Your seed is important!') + ' ' +
                        qsTr('If you lose your seed, your money will be permanently lost.') + ' ' +
                        qsTr('To make sure that you have properly saved your seed, please retype it here.')
                    background: Rectangle { color: "transparent" }
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
