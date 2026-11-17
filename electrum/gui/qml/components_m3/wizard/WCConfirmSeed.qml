import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: the new seed typed again, with the seed keyboard pinned to the bottom.
// repeats: components/wizard/WCConfirmSeed.qml:10-51 @ e6df7e1c8 (securePage, valid, checkValid() with
// wizard.wiz.isMatchingSeed on every change, the strings).
// Added (DESIGN-M2.md finding 5, view only, `valid` still comes from isMatchingSeed): the number of the first word
// that does not match the seed shown before, below the field; the keyboard has a "delete word" key.
WizardComponent {
    id: root
    securePage: true

    valid: false

    function checkValid() {
        var seedvalid = wizard.wiz.isMatchingSeed(wizard_data['seed'], confirm.text)
        valid = seedvalid
    }

    // number (1-based) of the first typed word that differs from the seed, 0 if none; the word being typed (no
    // space after it yet) only has to be the start of the right word
    function _firstMismatch() {
        var want = String(wizard_data['seed'] || '').split(/\s+/).filter(function(w) { return w !== '' })
        var text = confirm.text
        var got = text.split(/\s+/).filter(function(w) { return w !== '' })
        var typing = !/\s$/.test(text)
        for (var i = 0; i < got.length; i++) {
            if (i >= want.length)
                return i + 1
            if (typing && i == got.length - 1 ? want[i].indexOf(got[i]) !== 0 : want[i] !== got[i])
                return i + 1
        }
        return 0
    }

    Flickable {
        id: flick
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: keyboard.top
        contentHeight: mainLayout.height + m3.space16
        clip:true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: root.ensureVisible(flick, confirm)

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3InfoText {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('WCConfirmSeed', 'Your seed is important!') + ' ' +
                    qsTranslate('WCConfirmSeed', 'If you lose your seed, your money will be permanently lost.') + ' ' +
                    qsTranslate('WCConfirmSeed', 'To make sure that you have properly saved your seed, please retype it here.')
            }

            M3Text {
                Layout.fillWidth: true
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCConfirmSeed', 'Confirm your seed (re-enter)')
            }

            M3SeedField {
                id: confirm
                Layout.fillWidth: true
                placeholderText: qsTranslate('WCConfirmSeed', 'Enter your seed')
                indicatorValid: false
                indicatorText: mismatch > 0 ? qsTr('Word %1 does not match').arg(mismatch) : ''
                property int mismatch: 0
                onTextChanged: {
                    checkValid()
                    mismatch = root._firstMismatch()
                    Qt.callLater(root.ensureVisible, flick, confirm)
                }
            }
        }
    }

    M3SeedKeyboard {
        id: keyboard
        anchors.bottom: parent.bottom
        x: -root.leftPadding
        width: root.width
        target: confirm
        keyHeight: wizard.height < 640 ? 40 : 48
    }
}
