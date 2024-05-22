import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "controls"

Pane {
    id: root
    objectName: 'NetworkOverview'

    padding: 0

    property string title: qsTr("Network")

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            contentHeight: contentLayout.height
            clip: true
            interactive: height < contentHeight

            GridLayout {
                id: contentLayout
                width: parent.width
                columns: 2
                Heading {
                    Layout.columnSpan: 2
                    text: qsTr('On-chain')
                }
                Label {
                    text: qsTr('Network') + ':'
                    color: Material.accentColor
                }
                Label {
                    text: Network.networkName
                }
                Label {
                    text: qsTr('Status') + ':'
                    color: Material.accentColor
                }
                Label {
                    text: Network.status
                }
                Label {
                    text: qsTr('Server') + ':'
                    color: Material.accentColor
                }
                Label {
                    text: Network.serverWithStatus
                    wrapMode: Text.WrapAnywhere
                    Layout.fillWidth: true
                }
                Label {
                    text: qsTr('Local Height:');
                    color: Material.accentColor
                }
                Label {
                    text: Network.height
                }
                Label {
                    text: qsTr('Server Height:');
                    color: Material.accentColor
                    visible: Network.serverHeight != 0 && Network.serverHeight != Network.height
                }
                Label {
                    text: Network.serverHeight + " " + (Network.serverHeight < Network.height ? "(lagging)" : "(syncing...)")
                    visible: Network.serverHeight != 0 && Network.serverHeight != Network.height
                }
                Heading {
                    Layout.columnSpan: 2
                    text: qsTr('Mempool fees')
                }
                Item {
                    id: histogramRoot
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    implicitHeight: histogramLayout.height

                    ColumnLayout {
                        id: histogramLayout
                        width: parent.width
                        spacing: 0
                        RowLayout {
                            Layout.fillWidth: true
                            height: 28
                            spacing: 0
                            Repeater {
                                model: Network.feeHistogram.histogram
                                Rectangle {
                                    Layout.preferredWidth: 300 * (modelData[1] / Network.feeHistogram.total)
                                    Layout.fillWidth: true
                                    height: parent.height
                                    color: Qt.hsva(2/3-(2/3*(Math.log(Math.min(600, modelData[0]))/Math.log(600))), 0.8, 1, 1)
                                    ToolTip.text: (qsTr("%1 around depth %2")
                                        .arg(modelData[0] + " " + UI_UNIT_NAME.FEERATE_SAT_PER_VB)
                                        .arg((modelData[2]/1000000).toFixed(2) + " " + UI_UNIT_NAME.MEMPOOL_MB)
                                    )
                                    ToolTip.visible: ma.containsMouse
                                    MouseArea {
                                        id: ma
                                        anchors.fill: parent
                                        hoverEnabled: true
                                    }
                                }
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            height: 3
                            spacing: 0

                            Repeater {
                                model: Network.feeHistogram.total / 1000000
                                RowLayout {
                                    height: parent.height
                                    spacing: 0
                                    Rectangle {
                                        Layout.preferredWidth: 1
                                        Layout.fillWidth: false
                                        height: parent.height
                                        width: 1
                                        color: 'white'
                                    }
                                    Item {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: parent.height
                                    }
                                }
                            }
                            Rectangle {
                                Layout.preferredWidth: 1
                                Layout.fillWidth: false
                                height: parent.height
                                width: 1
                                color: 'white'
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Label {
                                text: '<-- ' + Math.ceil(Network.feeHistogram.max_fee) + " " + UI_UNIT_NAME.FEERATE_SAT_PER_VB
                                font.pixelSize: constants.fontSizeXSmall
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                horizontalAlignment: Text.AlignRight
                                text: Math.floor(Network.feeHistogram.min_fee) + " " + UI_UNIT_NAME.FEERATE_SAT_PER_VB + ' -->'
                                font.pixelSize: constants.fontSizeXSmall
                                color: Material.accentColor
                            }
                        }
                    }
                }

                Heading {
                    Layout.columnSpan: 2
                    text: qsTr('Lightning')
                }

                Label {
                    text: (Config.useGossip ? qsTr('Gossip') : qsTr('Trampoline')) + ':'
                    color: Material.accentColor
                }
                ColumnLayout {
                    visible: Config.useGossip
                    Label {
                        text: qsTr('%1 peers').arg(Network.gossipInfo.peers)
                    }
                    Label {
                        text: qsTr('%1 channels to fetch').arg(Network.gossipInfo.unknown_channels)
                    }
                    Label {
                        text: qsTr('%1 nodes, %2 channels').arg(Network.gossipInfo.db_nodes).arg(Network.gossipInfo.db_channels)
                    }
                }
                Label {
                    text: qsTr('enabled');
                    visible: !Config.useGossip
                }

                Label {
                    visible: Daemon.currentWallet.isLightning
                    text: qsTr('Channel peers:');
                    color: Material.accentColor
                }
                Label {
                    visible: Daemon.currentWallet.isLightning
                    text: Daemon.currentWallet.lightningNumPeers
                }

                Heading {
                    Layout.columnSpan: 2
                    text: qsTr('Proxy')
                }

                Label {
                    text: qsTr('Proxy') + ':'
                    color: Material.accentColor
                }
                Label {
                    text: 'mode' in Network.proxy ? qsTr('enabled') : qsTr('disabled')
                }

                Label {
                    visible: 'mode' in Network.proxy
                    text: qsTr('Proxy server:');
                    color: Material.accentColor
                }
                Label {
                    visible: 'mode' in Network.proxy
                    text: Network.proxy['host'] ? Network.proxy['host'] + ':' + Network.proxy['port'] : ''
                }

                Label {
                    visible: 'mode' in Network.proxy
                    text: qsTr('Proxy type:');
                    color: Material.accentColor
                }
                RowLayout {
                    Image {
                        visible: Network.isProxyTor
                        Layout.preferredWidth: constants.iconSizeMedium
                        Layout.preferredHeight: constants.iconSizeMedium
                        source: '../../icons/tor_logo.png'
                    }
                    Label {
                        visible: 'mode' in Network.proxy
                        text: Network.isProxyTor ? 'TOR' : (Network.proxy['mode'] || '')
                    }
                }

            }

        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Server Settings');
                icon.source: '../../icons/network.png'
                onClicked: {
                    var dialog = serverConfig.createObject(root)
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Proxy Settings');
                icon.source: '../../icons/status_connected_proxy.png'
                onClicked: {
                    var dialog = proxyConfig.createObject(root)
                    dialog.open()
                }
            }
        }
    }

    Component {
        id: serverConfig
        ServerConfigDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: proxyConfig
        ProxyConfigDialog {
            onClosed: destroy()
        }
    }
}
