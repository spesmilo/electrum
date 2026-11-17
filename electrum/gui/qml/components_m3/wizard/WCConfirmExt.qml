import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

// Material 3 page: the seed extension entered a second time.
// repeats: components/wizard/WCConfirmExt.qml:10-71 @ e6df7e1c8 (securePage, valid, cosigner, checkValid(), the
// input method hints, Component.onCompleted).
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
        id: flick
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: {
            if (customwordstext.activeFocus)
                root.ensureVisible(flick, customwordsField)
        }

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCConfirmExt', 'Please enter your custom word(s) a second time:')
            }

            M3TextField {
                id: customwordsField
                Layout.fillWidth: true
                label: qsTranslate('WCConfirmExt', 'Enter your custom word(s) here')
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: checkValid()
            }
        }
    }

    // the TextField of the classic page
    readonly property Item customwordstext: customwordsField.field

    Connections {
        target: customwordsField.field
        function onActiveFocusChanged() {
            if (customwordsField.field.activeFocus)
                Qt.callLater(root.ensureVisible, flick, customwordsField)
        }
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == 'multisig') {
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
        }
    }
}
