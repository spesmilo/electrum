import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root
    padding: 0

    ColumnLayout {
        id: layout
        width: parent.width
        height: parent.height
        spacing: 0

        GridLayout {
            id: summaryLayout
            Layout.preferredWidth: parent.width
            Layout.topMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            columns: 2

            Heading {
                Layout.columnSpan: 2
                text: qsTr('Lightning Channel Backups')
            }
        }

        Frame {
            id: channelsFrame
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingMedium
            Layout.rightMargin: constants.paddingMedium

            verticalPadding: 0
            horizontalPadding: 0
            background: PaneInsetBackground {}

            ColumnLayout {
                spacing: 0
                anchors.fill: parent

                ListView {
                    id: listview
                    Layout.preferredWidth: parent.width
                    Layout.fillHeight: true
                    clip: true
                    model: Daemon.currentWallet.channelModel.filterModelBackups()

                    delegate: ChannelDelegate {
                        onClicked: {
                            app.stack.push(Qt.resolvedUrl('ChannelDetails.qml'), { channelid: model.cid })
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }

                    Label {
                        visible: listview.model.count == 0
                        anchors.centerIn: parent
                        width: listview.width * 4/5
                        font.pixelSize: constants.fontSizeXXLarge
                        color: constants.mutedForeground
                        text: qsTr('No Lightning channel backups present')
                        wrapMode: Text.Wrap
                        horizontalAlignment: Text.AlignHCenter
                    }
                }
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Import channel backup')
            onClicked: {
                var dialog = importChannelBackupDialog.createObject(root)
                dialog.open()
            }
            icon.source: '../../icons/file.png'
        }

    }

    Connections {
        target: Daemon.currentWallet
        function onImportChannelBackupFailed(message) {
            var dialog = app.messageDialog.createObject(root, { title: qstr('Error'), text: message })
            dialog.open()
        }
    }

    Component {
        id: importChannelBackupDialog
        ImportChannelBackupDialog {
            onClosed: destroy()
        }
    }

}
