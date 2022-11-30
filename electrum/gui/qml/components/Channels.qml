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

            Label {
                Layout.columnSpan: 2
                text: qsTr('Lightning Channels')
                font.pixelSize: constants.fontSizeLarge
                color: Material.accentColor
            }

            Rectangle {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                height: 1
                color: Material.accentColor
            }

            Label {
                Layout.columnSpan: 2
                text: qsTr('You have %1 open channels').arg(Daemon.currentWallet.channelModel.numOpenChannels)
                color: Material.accentColor
            }

            Label {
                text: qsTr('You can send:')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                Label {
                    text: Config.formatSats(Daemon.currentWallet.lightningCanSend)
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
                Label {
                    text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(Daemon.currentWallet.lightningCanSend) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                }
            }

            Label {
                text: qsTr('You can receive:')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                Label {
                    text: Config.formatSats(Daemon.currentWallet.lightningCanReceive)
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
                Label {
                    text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(Daemon.currentWallet.lightningCanReceive) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                }
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

                    delegate: ChannelDelegate {
                        onClicked: {
                            app.stack.push(Qt.resolvedUrl('ChannelDetails.qml'), { 'channelid': model.cid })
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }
                }
            }
        }


        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Swap');
            visible: Daemon.currentWallet.lightningCanSend.satsInt > 0 || Daemon.currentWallet.lightningCanReceive.satInt > 0
            icon.source: '../../icons/status_waiting.png'
            onClicked: {
                var dialog = swapDialog.createObject(root)
                dialog.open()
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Open Channel')
            onClicked: {
                var dialog = openChannelDialog.createObject(root)
                dialog.open()
            }
            icon.source: '../../icons/lightning.png'
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
            var dialog = app.messageDialog.createObject(root, { text: message })
            dialog.open()
        }
    }

    Component {
        id: swapDialog
        SwapDialog {
            onClosed: destroy()
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

}
