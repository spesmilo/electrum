import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: the new seed typed again, with the seed keyboard pinned to the bottom.
// repeats: components/wizard/WCConfirmSeed.qml:10-51 @ e6df7e1c8 (securePage, valid, checkValid() with
// wizard.wiz.isMatchingSeed on every change, the strings).
// Added (DESIGN-M2.md finding 5, view only, `valid` still comes from isMatchingSeed): the number of the first word
// that does not match the seed shown before, below the field; the keyboard has a "delete word" key. The words are
// compared as mnemonic.is_matching_seed compares them (split on the same whitespace, case kept), and the line is
// never shown while the page is valid; the field with that line is scrolled into view once the line shows up.
WizardComponent {
    id: root
    securePage: true

    valid: false

    function checkValid() {
        var seedvalid = wizard.wiz.isMatchingSeed(wizard_data['seed'], confirm.text)
        valid = seedvalid
    }

    // the words of a text as mnemonic.is_matching_seed splits them: Python str.split() with no argument, i.e. on
    // the characters of str.isspace() (JS \s differs: it lacks \x1c-\x1f and \x85 and has \ufeff); the case is
    // kept, as there (it does not lower the words: "Abandon" does not match "abandon")
    function _words(text) {
        return text.split(/[\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/)
            .filter(function(w) { return w !== '' })
    }

    // number (1-based) of the first typed word that differs from the seed, 0 if none; the word being typed (no
    // space after it yet) only has to be the start of the right word
    function _firstMismatch() {
        var want = _words(String(wizard_data['seed'] || ''))
        var text = confirm.text
        var got = _words(text)
        var typing = _words(text.slice(-1)).length > 0  // the last character is not a space
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
                indicatorText: mismatch > 0 && !root.valid ? qsTr('Word %1 does not match').arg(mismatch) : ''
                property int mismatch: 0
                onTextChanged: {
                    checkValid()
                    mismatch = root._firstMismatch()
                    Qt.callLater(root.ensureVisible, flick, confirm)
                }
                // the line below the field showed up: scroll it into view as well
                onHeightChanged: Qt.callLater(root.ensureVisible, flick, confirm)
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
