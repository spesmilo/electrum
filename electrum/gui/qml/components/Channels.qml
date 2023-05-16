import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root
    objectName: 'Channels'

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
                text: qsTr('Lightning Channels')
            }

            Label {
                Layout.columnSpan: 2
                text: qsTr('You have %1 open channels').arg(Daemon.currentWallet.channelModel.numOpenChannels)
                color: Material.accentColor
            }

            Label {
                text: qsTr('You can send') + ':'
                color: Material.accentColor
            }

            FormattedAmount {
                amount: Daemon.currentWallet.lightningCanSend
            }

            Label {
                text: qsTr('You can receive') + ':'
                color: Material.accentColor
            }

            FormattedAmount {
                amount: Daemon.currentWallet.lightningCanReceive
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
                    model: Daemon.currentWallet.channelModel

                    section.property: 'is_backup'
                    section.criteria: ViewSection.FullString
                    section.delegate: RowLayout {
                        width: ListView.view.width
                        required property string section
                        Label {
                            visible: section == 'true'
                            text: qsTr('Channel backups')
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: constants.paddingLarge
                            font.pixelSize: constants.fontSizeSmall
                            color: Material.accentColor
                        }
                    }

                    delegate: ChannelDelegate {
                        onClicked: {
                            app.stack.push(Qt.resolvedUrl('ChannelDetails.qml'), { 'channelid': model.cid })
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }

                    Label {
                        visible: listview.model.count == 0
                        anchors.centerIn: parent
                        width: listview.width * 4/5
                        font.pixelSize: constants.fontSizeXXLarge
                        color: constants.mutedForeground
                        text: qsTr('No Lightning channels yet in this wallet')
                        wrapMode: Text.Wrap
                        horizontalAlignment: Text.AlignHCenter
                    }
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Swap');
                enabled: Daemon.currentWallet.lightningCanSend.satsInt > 0 || Daemon.currentWallet.lightningCanReceive.satInt > 0
                icon.source: Qt.resolvedUrl('../../icons/update.png')
                onClicked: app.startSwap()
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                enabled: Daemon.currentWallet.confirmedBalance.satsInt > 0
                text: qsTr('Open Channel')
                onClicked: {
                    var dialog = openChannelDialog.createObject(root)
                    dialog.open()
                }
                icon.source: '../../icons/lightning.png'
            }

        }

    }

    Component {
        id: openChannelDialog
        OpenChannelDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: importChannelBackupDialog
        ImportChannelBackupDialog {
            onClosed: destroy()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onImportChannelBackupFailed(message) {
            var dialog = app.messageDialog.createObject(root, { title: qsTr('Error'), text: message })
            dialog.open()
        }
    }

}
