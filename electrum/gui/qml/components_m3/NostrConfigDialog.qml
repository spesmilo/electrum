import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Nostr relays" of the Material 3 GUI, opened by the Network page (NetworkPage); a full-screen dialog
// (M2-MAP F-1), as the classic one.
// repeats: components/NostrConfigDialog.qml:10-121 @ e6df7e1c8: the title; `valid`, clean_array() and verify()
// (the relay pattern); the explanation; the text box of relays, one per line, filled from Config.nostrRelays
// (commas to new lines) when the dialog is created, with its input hints, verified on each change; Paste appends
// the clipboard on a new line when it verifies; Ok enabled by valid writes Config.nostrRelays (the cleaned list,
// joined by commas) and closes the dialog. Only the look differs.
// Differences: Material 3 look (M3InfoText, M3TextArea, Paste as an icon button beside the box, Ok as the main
// button below the content); no icon in the header (no Material 3 glyph for the Nostr brand, R-15).
// Strings keep the translation context of the classic file (qsTranslate('NostrConfigDialog', ...)).
M3FullScreenDialog {
    id: rootItem

    title: qsTranslate('NostrConfigDialog', 'Nostr relays')

    property bool valid: true

    function clean_array(text) {
        var relays = []
        const fragments = text.split("\n")
        fragments.forEach(function(fragment) {
            fragment = fragment.trim()
            if (fragment != "" && !relays.includes(fragment))
                relays.push(fragment)
        })
        return relays
    }

    function verify(text) {
        const re=/^wss?:\/\/([a-zA-Z0-9\-]+\.)+[a-zA-Z]+(\/.*)?$/
        const relays = clean_array(text)
        var isvalid = relays.every(function(relay) {
            return re.test(relay)
        })
        return isvalid
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                // the text box takes the free height of the screen, at least 5 lines
                height: Math.max(implicitHeight, flickable.height - 2 * m3.space16)
                spacing: m3.space16

                M3InfoText {
                    Layout.fillWidth: true
                    compact: true
                    text: qsTranslate('NostrConfigDialog', 'Nostr relays are used to send and receive submarine swap offers.') +
                        ' ' + qsTranslate('NostrConfigDialog', 'For multisig wallets, nostr is also used to relay transactions to your co-signers.') +
                        ' ' + qsTranslate('NostrConfigDialog', 'Connections to nostr are only made when required, and ephemerally.')
                }

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyLarge'
                    wrapMode: Text.Wrap
                    text: qsTranslate('NostrConfigDialog', 'Enter the list of Nostr relays')
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: m3.space4

                    M3TextArea {
                        id: relays_ta
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        Layout.minimumHeight: 140
                        font.family: FixedFont
                        wrapMode: TextEdit.WrapAnywhere
                        onTextChanged: valid = verify(text)
                        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 0
                        M3IconButton {
                            tooltip: qsTr('Paste')
                            icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                            onClicked: {
                                if (verify(AppController.clipboardToText())) {
                                    if (!relays_ta.text.endsWith('\n'))
                                        relays_ta.text = relays_ta.text + '\n'
                                    relays_ta.text = relays_ta.text + AppController.clipboardToText()
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- Ok (NostrConfigDialog.qml:102-115): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: okButton.implicitHeight + 2 * m3.space16
            color: m3.surface

            M3Button {
                id: okButton
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                variant: 'filled'
                size: 56
                icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                text: qsTranslate('NostrConfigDialog', 'Ok')
                enabled: valid
                onClicked: {
                    Config.nostrRelays = clean_array(relays_ta.text).join(",")
                    rootItem.close()
                }
            }
        }
    }

    // NostrConfigDialog.qml:119-121
    Component.onCompleted: {
        relays_ta.text = Config.nostrRelays.replace(/,/g, "\n")
    }
}
