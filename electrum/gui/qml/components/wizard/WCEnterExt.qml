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

    function apply() {
        var seed_extend = extendcb.checked
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extend'] = seed_extend
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extra_words'] = seed_extend ? customwordstext.text : ''
        } else {
            wizard_data['seed_extend'] = seed_extend
            wizard_data['seed_extra_words'] = seed_extend ? customwordstext.text : ''
        }
    }

    function checkValid() {
        valid = false
        validationtext.text = ''

        if (extendcb.checked && customwordstext.text == '') {
            return
        } else {
            // passphrase is either disabled or filled with text
            apply()
            if (cosigner && wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant'] == 'electrum') {
                // check if master keys are not duplicated after entering passphrase
                if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                    validationtext.text = qsTr('Error: duplicate master public key')
                    return
                }
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
                visible: text
                iconStyle: InfoTextArea.IconStyle.Error
            }

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: [
                    qsTr('You may extend your seed with custom words.'),
                    qsTr('Your seed extension must be saved together with your seed.'),
                    qsTr('Note that this is NOT your encryption password.'),
                    '<br/>',
                    qsTr('Do not enable it unless you know what it does!'),
                ].join(' ')
            }

            ElCheckBox {
                id: extendcb
                Layout.columnSpan: 2
                Layout.fillWidth: true
                text: qsTr('Extend seed with custom words')
                onCheckedChanged: checkValid()
            }

            TextField {
                id: customwordstext
                enabled: extendcb.checked
                Layout.fillWidth: true
                Layout.columnSpan: 2
                placeholderText: qsTr('Enter your custom word(s)')
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
        checkValid()
    }
}
