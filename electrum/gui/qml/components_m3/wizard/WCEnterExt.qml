import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

// Material 3 page: optional seed extension (custom words).
// repeats: components/wizard/WCEnterExt.qml:10-120 @ e6df7e1c8 (securePage, valid, cosigner, apply(),
// checkValid() with wiz.hasDuplicateMasterKeys for a multisig cosigner, the 250 ms validation timer, the custom
// words field shown only while the extension is on, its input method hints, Component.onCompleted).
// The checkbox extendcb is a switch row; its state is kept in seedExtend (read by the same apply/checkValid).
// The "Do not enable it unless you know what it does!" line is a warning above the switch, and the switch is a
// plain row below it (DESIGN-M2.md finding 19: the option must not look like the recommended step).
WizardComponent {
    id: root
    securePage: true

    valid: true

    property int cosigner: 0
    property bool seedExtend: false

    onSeedExtendChanged: checkValid()

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
                    validationtext.text = qsTranslate('WCEnterExt', 'Error: duplicate master public key')
                    return
                }
            }
        }
        valid = true
    }

    // the checkbox of the classic page
    readonly property QtObject extendcb: QtObject {
        readonly property bool checked: root.seedExtend
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

            M3InfoText {
                id: validationtext
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                visible: text
                tone: 'error'
            }

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'bodyLarge'
                wrapMode: Text.Wrap
                text: [
                    qsTranslate('WCEnterExt', 'You may extend your seed with custom words.'),
                    qsTranslate('WCEnterExt', 'Your seed extension must be saved together with your seed.'),
                    qsTranslate('WCEnterExt', 'Note that this is NOT your encryption password.')
                ].join(' ')
            }

            M3InfoText {
                Layout.fillWidth: true
                tone: 'warn'
                text: qsTranslate('WCEnterExt', 'Do not enable it unless you know what it does!')
            }

            M3SwitchRow {
                Layout.fillWidth: true
                headline: qsTranslate('WCEnterExt', 'Extend seed with custom words')
                headlineMaxLines: 2
                checked: root.seedExtend
                onUserToggled: (checked) => { root.seedExtend = checked }
            }

            M3TextField {
                id: customwordsField
                visible: extendcb.checked  // users confuse this with the seed re-entry if shown
                Layout.fillWidth: true
                label: qsTranslate('WCEnterExt', 'Enter your custom word(s)')
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                onTextChanged: startValidationTimer()
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
