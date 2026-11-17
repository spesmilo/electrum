import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Network" of the Material 3 GUI (route app.routes.networkOverview: the overflow menu, the Settings tab and the
// network chips of the Wallet tab; replaces the classic NetworkOverview). Opens without a wallet too (the menu of
// the Wallets root).
// repeats: components/NetworkOverview.qml:8-338 @ e6df7e1c8: the title; _getFeerateColor() (the colors of the
// fee histogram are data, kept as they are, R-19); on-chain: Network.networkName, status, serverWithStatus,
// height, the server height with "(lagging)" / "(syncing...)" when it differs, the chain tips when more than one
// (fading in); the mempool fee histogram of Network.feeHistogram (bars by share of the total, tooltips, a tick per
// MB, max / min fee); Lightning: Gossip (peers, channels to fetch, nodes and channels, only from
// Network.gossipInfo) or Trampoline "enabled" by Config.useGossip, the channel peers of a Lightning wallet; the
// proxy (enabled, server, type with TOR); the Server / Proxy / Nostr settings dialogs, each created on a tap and
// destroyed when closed.
// Differences: the details are M3DetailRow rows in groups; the chain tips show the account_tree glyph instead of
// the classic status indicator (OnchainNetworkStatusIndicator, R-13); TOR is a word with the vpn_lock glyph
// instead of the Tor logo; the three settings are list rows at the end of the page, not bottom buttons (M2-MAP
// F-3, R-18); Nostr without its brand icon (R-15); the wallet values are read only while a wallet is open (the
// classic page reads Daemon.currentWallet unguarded); the histogram ticks are drawn in m3.surfaceVariantOn
// instead of white, so they show in the light theme.
// Strings keep the translation context of the classic file (qsTranslate('NetworkOverview', ...)); the classic
// labels that end with ':' are shown without it.
M3Page {
    id: root
    objectName: 'NetworkOverview'

    title: qsTranslate('NetworkOverview', 'Network')

    // NetworkOverview.qml:16-30
    function _getFeerateColor(sat_per_vbyte) {
        // To display a nice quickly graspable view of the mempool fee histogram, we map
        // feerates to fixed colors. E.g. when the histogram is full of red, the user can
        // instantly see fees are high.
        // In the 1-600 s/b range, play with hue:
        var hsv_hue = (2/3-(2/3*(
            Math.log(
                Math.min(600, Math.max(sat_per_vbyte, 1))
            )
            /Math.log(600))
        ))
        // In the 0-1 s/b range, play with value:
        var hsv_value = Math.min(sat_per_vbyte, 1)
        return Qt.hsva(hsv_hue, 0.8, hsv_value, 1)
    }

    // a classic label without its trailing colon ('Local Height:' -> 'Local Height'), also when translated
    function _label(text) {
        return text.replace(/\s*[:\uFF1A]\s*$/, '')
    }

    readonly property bool _lightningWallet: Daemon.currentWallet != null && Daemon.currentWallet.isLightning

    Flickable {
        id: flickable
        anchors.fill: parent
        clip: true
        contentHeight: content.implicitHeight + 2 * m3.space16
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds
        ScrollIndicator.vertical: ScrollIndicator {}

        ColumnLayout {
            id: content
            readonly property int margin: m3.screenMargin(root.width)
            x: Math.max(margin, (flickable.width - width) / 2)
            y: m3.space8
            width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
            spacing: 0

            // ---------------------------------------------------------------- On-chain (:51-113)
            M3SectionHeader {
                Layout.fillWidth: true
                text: qsTranslate('NetworkOverview', 'On-chain')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3DetailRow {
                    label: qsTranslate('NetworkOverview', 'Network')
                    text: Network.networkName
                }
                M3DetailRow {
                    label: qsTranslate('NetworkOverview', 'Status')
                    text: Network.status
                }
                M3DetailRow {
                    label: qsTranslate('NetworkOverview', 'Server')
                    text: Network.serverWithStatus
                }
                M3DetailRow {
                    label: root._label(qsTranslate('NetworkOverview', 'Local Height:'))
                    text: Network.height
                }
                M3DetailRow {
                    visible: Network.serverHeight != 0 && Network.serverHeight != Network.height
                    label: root._label(qsTranslate('NetworkOverview', 'Server Height:'))
                    text: Network.serverHeight + " " + (Network.serverHeight < Network.height ? "(lagging)" : "(syncing...)")
                }
                M3DetailRow {
                    visible: opacity > 0
                    opacity: Network.chaintips > 1 ? 1 : 0
                    Behavior on opacity { NumberAnimation { duration: 1000 } }
                    label: root._label(qsTranslate('NetworkOverview', 'Chain tips:'))
                    text: Network.chaintips
                    valueColor: m3.error
                    actions: [
                        M3Icon {
                            source: Qt.resolvedUrl('../../icons/m3/account_tree.png')
                            color: m3.error
                        }
                    ]
                }
            }

            // ---------------------------------------------------------------- Mempool fees (:114-200)
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('NetworkOverview', 'Mempool fees')
            }

            M3ListGroup {
                Layout.fillWidth: true

                Item {
                    id: histogramRoot
                    Layout.fillWidth: true
                    implicitHeight: histogramLayout.height + 2 * m3.space16

                    ColumnLayout {
                        id: histogramLayout
                        x: m3.space16
                        y: m3.space16
                        width: parent.width - 2 * m3.space16
                        spacing: 0
                        RowLayout {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 28
                            spacing: 0
                            Repeater {
                                model: Network.feeHistogram.histogram
                                Rectangle {
                                    Layout.preferredWidth: 300 * (modelData[1] / Network.feeHistogram.total)
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    color: root._getFeerateColor(modelData[0])
                                    ToolTip.text: (qsTranslate('NetworkOverview', "%1 around depth %2")
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
                        // a tick per MB of the mempool
                        RowLayout {
                            // M3: ticks and fee labels only with a histogram (the classic page shows "NaN sat/vB")
                            visible: Network.feeHistogram.total > 0
                            Layout.fillWidth: true
                            Layout.preferredHeight: 3
                            spacing: 0

                            Repeater {
                                model: Network.feeHistogram.total / 1000000
                                RowLayout {
                                    Layout.fillHeight: true
                                    spacing: 0
                                    Rectangle {
                                        Layout.preferredWidth: 1
                                        Layout.fillWidth: false
                                        Layout.fillHeight: true
                                        color: m3.surfaceVariantOn
                                    }
                                    Item {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                    }
                                }
                            }
                            Rectangle {
                                Layout.preferredWidth: 1
                                Layout.fillWidth: false
                                Layout.fillHeight: true
                                color: m3.surfaceVariantOn
                            }
                        }
                        RowLayout {
                            visible: Network.feeHistogram.total > 0
                            Layout.fillWidth: true
                            Layout.topMargin: m3.space4
                            M3Text {
                                role: 'labelSmall'
                                color: m3.surfaceVariantOn
                                text: '<-- ' + Math.ceil(Network.feeHistogram.max_fee) + " " + UI_UNIT_NAME.FEERATE_SAT_PER_VB
                            }
                            M3Text {
                                Layout.fillWidth: true
                                role: 'labelSmall'
                                color: m3.surfaceVariantOn
                                horizontalAlignment: Text.AlignRight
                                text: Math.floor(Network.feeHistogram.min_fee) + " " + UI_UNIT_NAME.FEERATE_SAT_PER_VB + ' -->'
                            }
                        }
                    }
                }
            }

            // ---------------------------------------------------------------- Lightning (:202-234)
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('NetworkOverview', 'Lightning')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3DetailRow {
                    visible: Config.useGossip
                    label: qsTranslate('NetworkOverview', 'Gossip')
                    text: [
                        qsTranslate('NetworkOverview', '%1 peers').arg(Network.gossipInfo.peers),
                        qsTranslate('NetworkOverview', '%1 channels to fetch').arg(Network.gossipInfo.unknown_channels),
                        qsTranslate('NetworkOverview', '%1 nodes, %2 channels').arg(Network.gossipInfo.db_nodes).arg(Network.gossipInfo.db_channels)
                    ].join('\n')
                }
                M3DetailRow {
                    visible: !Config.useGossip
                    label: qsTranslate('NetworkOverview', 'Trampoline')
                    text: qsTranslate('NetworkOverview', 'enabled')
                }
                M3DetailRow {
                    visible: root._lightningWallet
                    label: root._label(qsTranslate('NetworkOverview', 'Channel peers:'))
                    text: root._lightningWallet ? Daemon.currentWallet.lightningNumPeers : ''
                }
            }

            // ---------------------------------------------------------------- Proxy (:236-277)
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('NetworkOverview', 'Proxy')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3DetailRow {
                    label: qsTranslate('NetworkOverview', 'Proxy')
                    text: Network.proxy.enabled ? qsTranslate('NetworkOverview', 'enabled') : qsTranslate('NetworkOverview', 'disabled')
                }
                M3DetailRow {
                    visible: Network.proxy.enabled
                    label: root._label(qsTranslate('NetworkOverview', 'Proxy server:'))
                    text: Network.proxy.host ? Network.proxy.host + ':' + Network.proxy.port : ''
                }
                M3DetailRow {
                    visible: Network.proxy.enabled
                    label: root._label(qsTranslate('NetworkOverview', 'Proxy type:'))
                    text: Network.isProxyTor ? 'TOR' : (Network.proxy.mode || '')
                    actions: [
                        M3Icon {
                            visible: Network.isProxyTor
                            source: Qt.resolvedUrl('../../icons/m3/vpn_lock.png')
                            color: m3.surfaceVariantOn
                        }
                    ]
                }
            }

            // ---------------------------------------------------------------- Settings (:281-315)
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                text: qsTranslate('WalletMainView', 'Settings')
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3ListItem {
                    headline: qsTranslate('NetworkOverview', 'Server Settings')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/dns.png')
                    trailing: chevron
                    onClicked: {
                        var dialog = serverConfig.createObject(root)
                        dialog.open()
                    }
                }
                M3ListItem {
                    headline: qsTranslate('NetworkOverview', 'Proxy Settings')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/vpn_lock.png')
                    trailing: chevron
                    onClicked: {
                        var dialog = proxyConfig.createObject(root)
                        dialog.open()
                    }
                }
                M3ListItem {
                    headline: qsTranslate('NetworkOverview', 'Nostr Settings')
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/key.png')
                    trailing: chevron
                    onClicked: {
                        var dialog = nostrConfig.createObject(root)
                        dialog.open()
                    }
                }
            }
        }
    }

    Component {
        id: chevron
        M3Icon {
            source: Qt.resolvedUrl('../../icons/m3/chevron_right.png')
            color: m3.surfaceVariantOn
        }
    }

    // NetworkOverview.qml:319-338
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

    Component {
        id: nostrConfig
        NostrConfigDialog {
            onClosed: destroy()
        }
    }
}
