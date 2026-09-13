import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

WizardComponent {
    securePage: true

    valid: seedtext.text != ''

    function apply() {
        wizard_data['seed'] = seedtext.text
        wizard_data['seed_variant'] = 'electrum' // generated seed always electrum variant
        wizard_data['seed_extend'] = extendcb.checked
        wizard_data['seed_extra_words'] = extendcb.checked ? customwordstext.text : ''
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        GridLayout {
            id: mainLayout
            width: parent.width
            columns: 1

            Label {
                Layout.topMargin: constants.paddingMedium
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr('Your wallet generation seed is:')
            }

            SeedTextArea {
                id: seedtext
                readOnly: true
                Layout.fillWidth: true

                BusyIndicator {
                    anchors.centerIn: parent
                    height: parent.height * 2/3
                    visible: seedtext.text == ''
                }
            }

            ElCheckBox {
                id: extendcb
                Layout.fillWidth: true
                enabled: seedtext.text != ''
                text: qsTr('Extend this seed with a Passphrase')
                onCheckedChanged: checkIsLast()
            }

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: extendcb.checked
                text: [
                    qsTr('You may extend your seed with a Passphrase (e.g. password manager generated passphrase, custom words, a combination of both...).'),
                    qsTr("You will need to save both your seed and the extension Passphrase together."),
                    qsTr('Note that this is NOT your wallet file encryption password.'),
                    qsTr('If you do not know what this is, leave this field empty.'),
                ].join(' ')
            }

            TextField {
                id: customwordstext
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingXSmall
                visible: extendcb.checked
                placeholderText: qsTr('Enter your custom Passphrase')
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: checkIsLast()
            }

            InfoTextArea {
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingSmall
                backgroundColor: constants.darkerDialogBackground
                iconStyle: InfoTextArea.IconStyle.Warn
                text: {
                    var n = seedtext.text.split(' ').filter(Boolean).length || 12
                    var save = extendcb.checked
                        ? qsTr('Please save these %1 words and your custom Passphrase on paper (order is important).').arg(n)
                        : qsTr('Please save these %1 words on paper (order is important).').arg(n)
                    return [
                        '<p>',
                        save,
                        qsTr('This seed will allow you to recover your wallet in case of computer failure.'),
                        '</p>',
                        '<b>' + qsTr('WARNING') + ':</b>',
                        '<ul>',
                        '<li>' + qsTr('Never disclose your seed.') + '</li>',
                        '<li>' + qsTr('Never type it on a website.') + '</li>',
                        '<li>' + qsTr('Do not store it electronically.') + '</li>',
                        '</ul>'
                    ].join(' ')
                }
            }
        }
    }

    Component.onCompleted: {
        bitcoin.generateSeed(wizard_data['seed_type'])
    }

    Bitcoin {
        id: bitcoin
        onGeneratedSeedChanged: {
            seedtext.text = generatedSeed
        }
    }
}
