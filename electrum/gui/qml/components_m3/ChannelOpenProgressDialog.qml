import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Progress of a channel opening in the Material 3 GUI: the one instance app.channelOpenProgressDialog (main.qml),
// driven by the ChannelOpener handlers of the Material 3 OpenChannelDialog and also of the classic one (still
// reachable through the classic fallback pages).
// repeats: components/ChannelOpenProgressDialog.qml:10-129: the API (writable `state` '' / 'success' /
// 'failed', `error`, `info`, `peer`, `channelBackup`, resetDialog(), open()); no closing until the outcome
// (allowClose false, true in both outcome states); the spinner while opening, the outcome text, the peer, the
// error (failed) or the info (success) in plain text; on close with a channel backup, the "Save Channel Backup"
// share dialog with its help.
// Look: an M3Dialog; the headline and the icon above it follow the state ("Opening Channel..."
// with a spinner below, "Success!" with check_circle, "Problem opening channel" with error); after the outcome an
// "Ok" button closes the dialog (besides the Android back button and a tap outside, as allowClose allows).
// resetDialog() is the classic one (it does not clear `info`, which is shown only after success sets it).
// Strings keep the translation context of the classic file (qsTranslate('ChannelOpenProgressDialog', ...)).
M3Dialog {
    id: dialog

    title: qsTranslate('ChannelOpenProgressDialog', 'Opening Channel...')

    allowClose: false

    property alias state: s.state
    property alias error: errorText.text
    property alias info: infoText.text
    property alias peer: peerText.text

    property string channelBackup

    function resetDialog() {
        state = ''
        errorText.text = ''
        peerText.text = ''
        channelBackup = ''
    }

    Item {
        id: s
        state: ''
        states: [
            State {
                name: 'success'
                PropertyChanges { target: dialog; allowClose: true }
                PropertyChanges { target: dialog; title: qsTranslate('ChannelOpenProgressDialog', 'Success!') }
                PropertyChanges { target: dialog; iconSource: Qt.resolvedUrl('../../icons/m3/check_circle.png') }
                PropertyChanges { target: infoText; visible: true }
            },
            State {
                name: 'failed'
                PropertyChanges { target: dialog; allowClose: true }
                PropertyChanges { target: dialog; title: qsTranslate('ChannelOpenProgressDialog', 'Problem opening channel') }
                PropertyChanges { target: dialog; iconSource: Qt.resolvedUrl('../../icons/m3/error.png') }
                PropertyChanges { target: errorText; visible: true }
            }
        ]
    }

    contentItem: ColumnLayout {
        spacing: m3.space16

        BusyIndicator {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 48
            Layout.preferredHeight: 48
            running: visible
            visible: s.state == ''
        }

        Rectangle {
            Layout.fillWidth: true
            visible: peerText.text !== ''
            implicitHeight: peerText.implicitHeight + 2 * m3.space12
            radius: m3.radiusM
            color: m3.surfaceContainer
            M3Text {
                id: peerText
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: m3.space12
                anchors.verticalCenter: parent.verticalCenter
                role: 'bodyMedium'
                wrapMode: Text.WrapAnywhere
                horizontalAlignment: Text.AlignHCenter
            }
        }

        M3InfoText {
            id: errorText
            Layout.fillWidth: true
            visible: false
            iconStyle: M3InfoText.IconStyle.Error
            textFormat: Text.PlainText
        }

        M3InfoText {
            id: infoText
            Layout.fillWidth: true
            visible: false
            textFormat: Text.PlainText
        }
    }

    buttons: [
        M3Button {
            variant: 'text'
            visible: dialog.allowClose
            text: qsTr('Ok')
            onClicked: dialog.close()
        }
    ]

    onClosed: {
        if (!dialog.channelBackup)
            return

        var sharedialog = app.genericShareDialog.createObject(app, {
            title: qsTranslate('ChannelOpenProgressDialog', 'Save Channel Backup'),
            text_qr: dialog.channelBackup,
            text_help: qsTranslate('ChannelOpenProgressDialog', 'The channel you created is not recoverable from seed.')
            + ' ' + qsTranslate('ChannelOpenProgressDialog', 'To prevent fund losses, please save this backup on another device.')
            + ' ' + qsTranslate('ChannelOpenProgressDialog', 'It may be imported in another Electrum wallet with the same seed.')
        })
        sharedialog.open()
    }
}
