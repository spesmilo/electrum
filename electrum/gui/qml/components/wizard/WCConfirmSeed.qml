import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import ".."

WizardComponent {
    valid: false

    function checkValid() {
        var seedvalid = confirm.text == wizard_data['seed']
        var customwordsvalid =  customwordstext.text == wizard_data['seed_extra_words']
        valid = seedvalid && (wizard_data['seed_extend'] ? customwordsvalid : true)
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
                Layout.fillWidth: true
                text: qsTr('Your seed is important!') + ' ' +
                    qsTr('If you lose your seed, your money will be permanently lost.') + ' ' +
                    qsTr('To make sure that you have properly saved your seed, please retype it here.')
            }
            Label { text: qsTr('Confirm your seed (re-enter)') }
            SeedTextArea {
                id: confirm
                Layout.fillWidth: true
                onTextChanged: {
                    checkValid()
                }
            }
            TextField {
                id: customwordstext
                Layout.fillWidth: true
                placeholderText: qsTr('Enter your custom word(s)')
                onTextChanged: {
                    checkValid()
                }
            }
        }
    }

    onReadyChanged: {
        if (ready)
            customwordstext.visible = wizard_data['seed_extend']
    }
}
