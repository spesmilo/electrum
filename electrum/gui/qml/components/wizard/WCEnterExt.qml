import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root
    securePage: true

    valid: true

    property int cosigner: 0
    property string seedVariant: ''

    title: seedVariant == 'bip39' ? qsTr('BIP39 Passphrase') : qsTr('Seed Extension')

    function apply() {
        // page is only shown after the user opted in on the seed page
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extend'] = true
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extra_words'] = customwordstext.text
        } else {
            wizard_data['seed_extend'] = true
            wizard_data['seed_extra_words'] = customwordstext.text
        }
    }

    function checkValid() {
        valid = false
        validationtext.text = ''

        apply()
        if (cosigner && wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant'] == 'electrum') {
            // check if master keys are not duplicated after entering passphrase
            if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                validationtext.text = qsTr('Error: duplicate master public key')
                return
            }
        }
        valid = true
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip: true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: constants.paddingLarge

            InfoTextArea {
                id: validationtext
                Layout.fillWidth: true
                Layout.columnSpan: 2
                backgroundColor: constants.darkerDialogBackground
                visible: text
                iconStyle: InfoTextArea.IconStyle.Error
            }

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: seedVariant == 'bip39'
                    ? [
                        qsTr('Enter an optional BIP39 passphrase.'),
                        qsTr('Each passphrase derives a different wallet.'),
                        qsTr('This is sometimes incorrectly called the "25th word".'),
                        qsTr('Note that this is NOT your encryption password.'),
                        qsTr('If you do not know what this is, leave this field empty.'),
                    ].join(' ')
                    : [
                        qsTr('You may extend your seed with a Passphrase (e.g. password manager generated passphrase, custom words, a combination of both...).'),
                        qsTr("You will need to save both your seed and the extension Passphrase together."),
                        qsTr('Note that this is NOT your wallet file encryption password.'),
                        qsTr('If you do not know what this is, leave this field empty.'),
                    ].join(' ')
            }

            TextField {
                id: customwordstext
                Layout.fillWidth: true
                Layout.columnSpan: 2
                placeholderText: seedVariant == 'bip39'
                    ? qsTr('Enter your BIP39 Passphrase')
                    : qsTr('Enter your custom Passphrase')
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: startValidationTimer()
            }
        }
    }

    function startValidationTimer() {
        valid = false
        validationTimer.restart()
    }

    Timer {
        id: validationTimer
        interval: 250
        repeat: false
        onTriggered: checkValid()
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == 'multisig') {
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
        }
        if (cosigner)
            seedVariant = wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant']
        else
            seedVariant = wizard_data['seed_variant']
        checkValid()
    }
}
