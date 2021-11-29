import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Item {
    property Component walletname: Component {
        WizardComponent {
            valid: wallet_name.text.length > 0
            //property alias wallet_name: wallet_name.text
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
                wizard_data['seed_extend'] = extendcb.checked
            }

            GridLayout {
                columns: 1
                Label { text: qsTr('Generating seed') }
                TextArea {
                    id: seedtext
                    text: 'test this is a fake seed as you might expect'
                    readOnly: true
                    Layout.fillWidth: true
                    wrapMode: TextInput.WordWrap
                }
                CheckBox {
                    id: extendcb
                    text: qsTr('Extend seed with custom words')
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
                wizard_data['seed_bip39'] = bip39cb.checked
            }

            GridLayout {
                columns: 1
                Label { text: qsTr('Enter your seed') }
                TextArea {
                    id: seedtext
                    wrapMode: TextInput.WordWrap
                    Layout.fillWidth: true
                }
                CheckBox {
                    id: extendcb
                    enabled: true
                    text: qsTr('Extend seed with custom words')
                }
                CheckBox {
                    id: bip39cb
                    enabled: true
                    text: qsTr('BIP39')
                }
            }
        }
    }

    property Component confirmseed: Component {
        WizardComponent {
            valid: confirm.text !== ''
            Layout.fillWidth: true

            GridLayout {
                Layout.fillWidth: true
                columns: 1
                Label { text: qsTr('Confirm your seed (re-enter)') }
                TextArea {
                    id: confirm
                    wrapMode: TextInput.WordWrap
                    Layout.fillWidth: true
                    onTextChanged: {
                        console.log("TODO: verify seed")
                    }
                }
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
