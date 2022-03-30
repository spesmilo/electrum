import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import ".."

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
            '<p>',
            qsTr('Please save these %1 words on paper (order is important).').arg(numwords),
            qsTr('This seed will allow you to recover your wallet in case of computer failure.'),
            '</p>',
            '<b>' + qsTr('WARNING') + ':</b>',
            '<ul>',
            '<li>' + qsTr('Never disclose your seed.') + '</li>',
            '<li>' + qsTr('Never type it on a website.') + '</li>',
            '<li>' + qsTr('Do not store it electronically.') + '</li>',
            '</ul>'
        ]
        warningtext.text = t.join(' ')
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

            InfoTextArea {
                id: warningtext
                Layout.fillWidth: true
                iconStyle: InfoTextArea.IconStyle.Warn
            }
            Label { text: qsTr('Your wallet generation seed is:') }
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
            CheckBox {
                id: extendcb
                text: qsTr('Extend seed with custom words')
            }
            TextField {
                id: customwordstext
                visible: extendcb.checked
                Layout.fillWidth: true
                placeholderText: qsTr('Enter your custom word(s)')
            }
            Component.onCompleted : {
                setWarningText(12)
                bitcoin.generate_seed()
            }
        }
    }

    Bitcoin {
        id: bitcoin
        onGeneratedSeedChanged: {
            seedtext.text = generated_seed
            setWarningText(generated_seed.split(' ').length)
        }
    }
}
