import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root
    width: parent.width
    height: parent.height

    property string channelid

    property string title: qsTr("Channel details")

    property QtObject menu: Menu {
        id: menu
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Backup');
                enabled: false
                onTriggered: {}
                icon.source: '../../icons/file.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Close channel');
                enabled: channeldetails.canClose
                onTriggered: {
                    var dialog = closechannel.createObject(root, { 'channelid': channelid })
                    dialog.open()
                }
                icon.source: '../../icons/closebutton.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Delete channel');
                enabled: channeldetails.canDelete
                onTriggered: {
                    var dialog = app.messageDialog.createObject(root,
                            {
                                'text': qsTr('Are you sure you want to delete this channel? This will purge associated transactions from your wallet history.'),
                                'yesno': true
                            }
                    )
                    dialog.yesClicked.connect(function() {
                        channeldetails.deleteChannel()
                        app.stack.pop()
                        Daemon.currentWallet.historyModel.init_model() // needed here?
                        Daemon.currentWallet.channelModel.remove_channel(channelid)
                    })
                    dialog.open()
                }
                icon.source: '../../icons/delete.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                enabled: channeldetails.isOpen
                text: channeldetails.frozenForSending ? qsTr('Unfreeze (for sending)') : qsTr('Freeze (for sending)')
                onTriggered: channeldetails.freezeForSending()
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                enabled: channeldetails.isOpen
                text: channeldetails.frozenForReceiving ? qsTr('Unfreeze (for receiving)') : qsTr('Freeze (for receiving)')
                onTriggered: channeldetails.freezeForReceiving()
            }
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height
        clip:true
        interactive: height < contentHeight

        GridLayout {
            id: rootLayout
            width: parent.width
            columns: 2

            Label {
                text: qsTr('Channel name')
                color: Material.accentColor
            }

            Label {
                text: channeldetails.name
            }

            Label {
                text: qsTr('Short channel ID')
                color: Material.accentColor
            }

            Label {
                text: channeldetails.short_cid
            }

            Label {
                text: qsTr('State')
                color: Material.accentColor
            }

            Label {
                text: channeldetails.state
            }

            Label {
                text: qsTr('Initiator')
                color: Material.accentColor
            }

            Label {
                text: channeldetails.initiator
            }

            Label {
                text: qsTr('Capacity')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    font.family: FixedFont
                    text: Config.formatSats(channeldetails.capacity)
                }
                Label {
                    color: Material.accentColor
                    text: Config.baseUnit
                }
                Label {
                    text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(channeldetails.capacity) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                }
            }

            Label {
                text: qsTr('Can send')
                color: Material.accentColor
            }

            RowLayout {
                visible: !channeldetails.frozenForSending && channeldetails.isOpen
                Label {
                    font.family: FixedFont
                    text: Config.formatSats(channeldetails.canSend)
                }
                Label {
                    color: Material.accentColor
                    text: Config.baseUnit
                }
                Label {
                    text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(channeldetails.canSend) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                }
            }
            Label {
                visible: channeldetails.frozenForSending && channeldetails.isOpen
                text: qsTr('n/a (frozen)')
            }
            Label {
                visible: !channeldetails.isOpen
                text: qsTr('n/a (channel not open)')
            }

            Label {
                text: qsTr('Can Receive')
                color: Material.accentColor
            }

            RowLayout {
                visible: !channeldetails.frozenForReceiving && channeldetails.isOpen
                Label {
                    font.family: FixedFont
                    text: Config.formatSats(channeldetails.canReceive)
                }
                Label {
                    color: Material.accentColor
                    text: Config.baseUnit
                }
                Label {
                    text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(channeldetails.canReceive) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                }
            }
            Label {
                visible: channeldetails.frozenForReceiving && channeldetails.isOpen
                text: qsTr('n/a (frozen)')
            }
            Label {
                visible: !channeldetails.isOpen
                text: qsTr('n/a (channel not open)')
            }

            Label {
                text: qsTr('Channel type')
                color: Material.accentColor
            }

            Label {
                text: channeldetails.channelType
            }

            Label {
                text: qsTr('Remote node ID')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

                RowLayout {
                    width: parent.width
                    Label {
                        text: channeldetails.pubkey
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: 'transparent'
                        onClicked: {
                            var dialog = share.createObject(root, { 'title': qsTr('Channel node ID'), 'text': channeldetails.pubkey })
                            dialog.open()
                        }
                    }
                }
            }

        }
    }

    ChannelDetails {
        id: channeldetails
        wallet: Daemon.currentWallet
        channelid: root.channelid
    }

    Component {
        id: share
        GenericShareDialog {}
    }

    Component {
        id: closechannel
        CloseChannelDialog {}
    }
}
