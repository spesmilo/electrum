import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import ".."
import "../controls"

WizardComponent {
    securePage: true

    valid: false

    function checkValid() {
        var seedvalid = wizard.wiz.isMatchingSeed(wizard_data['seed'], confirm.text)
        valid = seedvalid
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip:true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width

            InfoTextArea {
                Layout.fillWidth: true
                Layout.bottomMargin: constants.paddingLarge
                text: qsTr('Your seed is important!') + ' ' +
                    qsTr('If you lose your seed, your money will be permanently lost.') + ' ' +
                    qsTr('To make sure that you have properly saved your seed, please retype it here.')
            }

            Label {
                text: qsTr('Confirm your seed (re-enter)')
            }

            SeedTextArea {
                id: confirm
                Layout.fillWidth: true
                placeholderText: qsTr('Enter your seed')
                onTextChanged: checkValid()
            }
        }
    }
}
