import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog
    width: parent.width
    height: parent.height

    title: qsTr('Opening Channel...')

    allowClose: false

    property alias state: s.state
    property alias error: errorText.text
    property alias info: infoText.text
    property alias peer: peerText.text

    property string channelBackup

    function reset() {
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
                PropertyChanges { target: stateText; text: qsTr('Success!') }
                PropertyChanges { target: infoText; visible: true }
                PropertyChanges { target: icon; source: '../../icons/confirmed.png' }
            },
            State {
                name: 'failed'
                PropertyChanges { target: dialog; allowClose: true }
                PropertyChanges { target: stateText; text: qsTr('Problem opening channel') }
                PropertyChanges { target: errorText; visible: true }
                PropertyChanges { target: icon; source: '../../icons/warning.png' }
            }
        ]
    }

    ColumnLayout {
        id: content
        anchors.centerIn: parent
        width: parent.width
        spacing: constants.paddingLarge

        RowLayout {
                Layout.alignment: Qt.AlignHCenter
            Image {
                id: icon
                source: ''
                visible: source != ''
                Layout.preferredWidth: constants.iconSizeLarge
                Layout.preferredHeight: constants.iconSizeLarge
            }
            BusyIndicator {
                id: spinner
                running: visible
                visible: s.state == ''
                Layout.preferredWidth: constants.iconSizeLarge
                Layout.preferredHeight: constants.iconSizeLarge
            }

            Label {
                id: stateText
                text: qsTr('Opening Channel...')
                font.pixelSize: constants.fontSizeXXLarge
            }
        }

        TextHighlightPane {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: dialog.width * 3/4
            Label {
                id: peerText
                font.pixelSize: constants.fontSizeMedium
                width: parent.width
                wrapMode: Text.Wrap
                horizontalAlignment: Text.AlignHCenter
            }
        }

        InfoTextArea {
            id: errorText
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: dialog.width * 2/3
            visible: false
            iconStyle: InfoTextArea.IconStyle.Error
            textFormat: TextEdit.PlainText
        }

        InfoTextArea {
            id: infoText
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: dialog.width * 2/3
            visible: false
            textFormat: TextEdit.PlainText
        }
    }

    onClosed: {
        if (!dialog.channelBackup)
            return

        var sharedialog = app.genericShareDialog.createObject(app, {
            title: qsTr('Save Channel Backup'),
            text_qr: dialog.channelBackup,
            text_help: qsTr('The channel you created is not recoverable from seed.')
            + ' ' + qsTr('To prevent fund losses, please save this backup on another device.')
            + ' ' + qsTr('It may be imported in another Electrum wallet with the same seed.')
        })
        sharedialog.open()
    }
}
