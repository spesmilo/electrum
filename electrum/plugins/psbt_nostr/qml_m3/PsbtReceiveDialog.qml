import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../../../gui/qml/components_m3/controls"

// Material 3 dialog of the psbt_nostr plugin: a PSBT was received from a co-signer (created by qml_m3/main.qml).
// repeats: plugins/psbt_nostr/qml/PsbtReceiveDialog.qml:8-94 @ e6df7e1c8: the title, the enum Choice (None, Open,
// Save) and the API tx_label, can_be_saved, choice; z: 1 (above dialogs whose parent is the overlay); the message
// with the label, if any, and the question; Open (choice Open, doAccept()), Discard (doReject()), Save to Wallet
// (only when can_be_saved: choice Save, doAccept()).
// Differences: an M3Dialog (M2-MAP F-2, zone probe wave 3 R-16); the message is plain text: the label (it comes
// from the co-signer) is a line of its own instead of bold rich text; the help glyph instead of the classic
// question icon; text buttons, Open first.
// Strings keep the translation context of the classic file (qsTranslate('PsbtReceiveDialog', ...)).
M3Dialog {
    id: dialog
    title: qsTranslate('PsbtReceiveDialog', 'PSBT received')
    iconSource: Qt.resolvedUrl('../../../gui/icons/m3/help.png')

    enum Choice {
        None,
        Open,
        Save
    }

    property string tx_label
    property bool can_be_saved
    property int choice: PsbtReceiveDialog.Choice.None

    // TODO: it might be better to defer popup until no dialogs are shown
    z: 1 // raise z so it also covers dialogs using overlay as parent

    contentItem: ColumnLayout {
        spacing: m3.space8

        M3Text {
            Layout.fillWidth: true
            role: 'bodyMedium'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            text: qsTranslate('PsbtReceiveDialog', 'A transaction was received from your cosigner.')
        }
        M3Text {
            Layout.fillWidth: true
            visible: dialog.tx_label != ''
            role: 'labelLarge'
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            textFormat: Text.PlainText
            text: dialog.tx_label
        }
        M3Text {
            Layout.fillWidth: true
            role: 'bodyMedium'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            text: qsTranslate('PsbtReceiveDialog', 'Do you want to open it now?')
        }
    }

    // right to left: Open is the rightmost
    buttons: [
        M3Button {
            variant: 'text'
            text: qsTranslate('PsbtReceiveDialog', 'Open')
            onClicked: {
                choice = PsbtReceiveDialog.Choice.Open
                doAccept()
            }
        },
        M3Button {
            variant: 'text'
            text: qsTranslate('PsbtReceiveDialog', 'Discard')
            onClicked: doReject()
        },
        M3Button {
            variant: 'text'
            text: qsTranslate('PsbtReceiveDialog', 'Save to Wallet')
            visible: dialog.can_be_saved
            onClicked: {
                choice = PsbtReceiveDialog.Choice.Save
                doAccept()
            }
        }
    ]
}
