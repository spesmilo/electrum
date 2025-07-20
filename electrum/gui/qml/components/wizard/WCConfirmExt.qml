import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root
    securePage: true

    valid: false

    property int cosigner: 0

    function checkValid() {
        valid = false
        var input = customwordstext.text
        if (input == '') {
            return
        }

        if (cosigner) {
            // multisig cosigner
            if (input != wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extra_words']) {
                return
            }
        } else {
            if (input != wizard_data['seed_extra_words']) {
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

            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr('Please enter your custom word(s) a second time:')
            }

            TextField {
                id: customwordstext
                Layout.fillWidth: true
                Layout.columnSpan: 2
                placeholderText: qsTr('Enter your custom word(s) here')
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: checkValid()
            }
        }
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == 'multisig') {
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
        }
    }
}