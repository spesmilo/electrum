import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Balance details of the Material 3 GUI (route app.routes.balanceDetails, opened from the balance on the Wallet tab;
// replaces the classic BalanceDetails).
// repeats: components/BalanceDetails.qml:10-257: the notice while the wallet is not synchronized or not
// connected, the pie chart of Daemon.currentWallet.getBalancesForPiechart() (six slices: Lightning, On-chain,
// On-chain (frozen), Unconfirmed, Unmatured, Frozen Lightning; shown when the total is not zero; updated on
// balanceChanged), the amounts and their conditions (Total, Lightning, its Frozen part, On-chain, its Frozen part,
// Unconfirmed), the Lightning liquidity (Can send, Can receive), Lightning swap (app.startSwap()) and Open Channel
// with their conditions. Open Channel goes through the factory app.openChannelDialog (the classic page
// declares its own OpenChannelDialog component, without the first-channel warning of the Channels path, as here).
// Colors of the slices: existing Material 3 roles, no new theme roles; every one has a contrast of
// at least 4.3:1 against m3.surface in both themes: Lightning tertiary, Frozen Lightning tertiaryContainerOn (the
// classic darker orange), On-chain primary, frozen outline (the classic gray), Unconfirmed primaryContainerOn (the
// classic darker accent), Unmatured success; Total is a ring in primary. The slices are rebuilt on a theme switch.
// Layout: the amounts are rows of M3ListGroup with the color of their slice; the two actions are
// buttons below the content.
// Strings keep the translation context of the classic file (qsTranslate('BalanceDetails', ...)).
M3Page {
    id: rootItem
    objectName: 'BalanceDetails'

    title: qsTranslate('BalanceDetails', 'Wallet balance')

    // the colors of the slices and of the rows (see the header comment)
    readonly property color _colorLightning: m3.tertiary
    readonly property color _colorLightningFrozen: m3.tertiaryContainerOn
    readonly property color _colorOnchain: m3.primary
    readonly property color _colorFrozen: m3.outline
    readonly property color _colorUnconfirmed: m3.primaryContainerOn
    readonly property color _colorUnmatured: m3.success
    readonly property color _colorTotal: m3.primary

    // one amount row: the swatch of its slice (a ring for Total), the label and the amount (a classic Label +
    // FormattedAmount pair); `indented` for the frozen parts, as the classic left margin
    component BalanceRow: Item {
        id: row
        property string label
        property var amount
        property color swatch
        property bool ring: false
        property bool indented: false

        Layout.fillWidth: true
        implicitHeight: Math.max(56, rowLayout.implicitHeight + 2 * m3.space8)

        RowLayout {
            id: rowLayout
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: m3.space16 + (row.indented ? m3.space24 : 0)
            anchors.rightMargin: m3.space16
            anchors.verticalCenter: parent.verticalCenter
            spacing: m3.space16

            Rectangle {
                Layout.alignment: Qt.AlignVCenter
                implicitWidth: 16
                implicitHeight: 16
                radius: row.ring ? 8 : m3.radiusXS
                color: row.ring ? 'transparent' : row.swatch
                border.width: row.ring ? 2 : 0
                border.color: row.swatch
            }
            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                elide: Text.ElideRight
                text: row.label
            }
            M3Amount {
                Layout.alignment: Qt.AlignVCenter | Qt.AlignRight
                amount: row.amount
                role: 'bodyLarge'
                fiatBelow: true
            }
        }
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
                spacing: m3.space16

                // BalanceDetails.qml:38-46
                M3InfoText {
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet.synchronizing || !Network.isConnected
                    text: Daemon.currentWallet.synchronizing
                              ? qsTranslate('BalanceDetails', 'Your wallet is not synchronized. The displayed balance may be inaccurate.')
                              : qsTranslate('BalanceDetails', 'Your wallet is not connected to an Electrum server. The displayed balance may be outdated.')
                    iconStyle: M3InfoText.IconStyle.Warn
                }

                // BalanceDetails.qml:52-79
                M3Piechart {
                    id: piechart

                    property real total: 0

                    visible: total > 0
                    Layout.fillWidth: true
                    Layout.preferredHeight: 220
                    implicitHeight: 220
                    innerOffset: 6
                    function updateSlices() {
                        var p = Daemon.currentWallet.getBalancesForPiechart()
                        total = p['total']
                        piechart.slices = [
                            { v: p['lightning']/total,
                                color: rootItem._colorLightning, text: qsTranslate('BalanceDetails', 'Lightning') },
                            { v: p['confirmed']/total,
                                color: rootItem._colorOnchain, text: qsTranslate('BalanceDetails', 'On-chain') },
                            { v: p['frozen']/total,
                                color: rootItem._colorFrozen, text: qsTranslate('BalanceDetails', 'On-chain (frozen)') },
                            { v: p['unconfirmed']/total,
                                color: rootItem._colorUnconfirmed, text: qsTranslate('BalanceDetails', 'Unconfirmed') },
                            { v: p['unmatured']/total,
                                color: rootItem._colorUnmatured, text: qsTranslate('BalanceDetails', 'Unmatured') },
                            { v: p['f_lightning']/total,
                                color: rootItem._colorLightningFrozen, text: qsTranslate('BalanceDetails', 'Frozen Lightning') },
                        ]
                    }
                }

                // BalanceDetails.qml:81-183
                M3ListGroup {
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet

                    BalanceRow {
                        label: qsTranslate('BalanceDetails', 'Total')
                        amount: Daemon.currentWallet.totalBalance
                        swatch: rootItem._colorTotal
                        ring: true
                    }
                    BalanceRow {
                        visible: Daemon.currentWallet.isLightning
                        label: qsTranslate('BalanceDetails', 'Lightning')
                        amount: Daemon.currentWallet.lightningBalance
                        swatch: rootItem._colorLightning
                    }
                    BalanceRow {
                        visible: Daemon.currentWallet.isLightning && !Daemon.currentWallet.lightningBalanceFrozen.isEmpty
                        label: qsTranslate('BalanceDetails', 'Frozen')
                        amount: Daemon.currentWallet.lightningBalanceFrozen
                        swatch: rootItem._colorLightningFrozen
                        indented: true
                    }
                    BalanceRow {
                        visible: Daemon.currentWallet.isLightning || !Daemon.currentWallet.frozenBalance.isEmpty
                        label: qsTranslate('BalanceDetails', 'On-chain')
                        amount: Daemon.currentWallet.confirmedBalance
                        swatch: rootItem._colorOnchain
                    }
                    BalanceRow {
                        visible: !Daemon.currentWallet.frozenBalance.isEmpty
                        label: qsTranslate('BalanceDetails', 'Frozen')
                        amount: Daemon.currentWallet.frozenBalance
                        swatch: rootItem._colorFrozen
                        indented: true
                    }
                    BalanceRow {
                        visible: !Daemon.currentWallet.unconfirmedBalance.isEmpty
                        label: qsTranslate('BalanceDetails', 'Unconfirmed')
                        amount: Daemon.currentWallet.unconfirmedBalance
                        swatch: rootItem._colorUnconfirmed
                    }
                }

                // BalanceDetails.qml:185-205
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    visible: Daemon.currentWallet.isLightning
                    text: qsTranslate('BalanceDetails', 'Lightning Liquidity')
                }
                M3ListGroup {
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet && Daemon.currentWallet.isLightning

                    Item {
                        Layout.fillWidth: true
                        implicitHeight: Math.max(56, sendRow.implicitHeight + 2 * m3.space8)
                        RowLayout {
                            id: sendRow
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space16
                            anchors.verticalCenter: parent.verticalCenter
                            M3Text {
                                Layout.fillWidth: true
                                role: 'bodyLarge'
                                text: qsTranslate('BalanceDetails', 'Can send')
                            }
                            M3Amount {
                                amount: Daemon.currentWallet.lightningCanSend
                            }
                        }
                    }
                    Item {
                        Layout.fillWidth: true
                        implicitHeight: Math.max(56, receiveRow.implicitHeight + 2 * m3.space8)
                        RowLayout {
                            id: receiveRow
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space16
                            anchors.verticalCenter: parent.verticalCenter
                            M3Text {
                                Layout.fillWidth: true
                                role: 'bodyLarge'
                                text: qsTranslate('BalanceDetails', 'Can receive')
                            }
                            M3Amount {
                                amount: Daemon.currentWallet.lightningCanReceive
                            }
                        }
                    }
                }
            }
        }

        // --- Lightning swap and Open Channel (BalanceDetails.qml:210-235): below the content ---
        Rectangle {
            Layout.fillWidth: true
            visible: Daemon.currentWallet.isLightning
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            // side by side when both labels fit, else one above the other (narrow screens, long translations)
            GridLayout {
                id: actions
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                // (the two columns are equally wide)
                columns: 2 * Math.max(swapButton.implicitWidth, channelButton.implicitWidth) + columnSpacing <= width ? 2 : 1
                rowSpacing: m3.space8
                columnSpacing: m3.space8

                M3Button {
                    id: swapButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    size: 56
                    text: qsTranslate('BalanceDetails', 'Lightning swap');
                    visible: Daemon.currentWallet.isLightning
                    enabled: Daemon.currentWallet.lightningCanSend.satsInt > 0 || Daemon.currentWallet.lightningCanReceive.satsInt > 0
                    icon.source: Qt.resolvedUrl('../../icons/m3/swap_horiz.png')
                    onClicked: app.startSwap()
                }

                M3Button {
                    id: channelButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'filled'
                    size: 56
                    text: qsTranslate('BalanceDetails', 'Open Channel')
                    visible: Daemon.currentWallet.isLightning
                    enabled: Daemon.currentWallet.confirmedBalance.satsInt > 0
                    onClicked: {
                        var dialog = app.openChannelDialog.createObject(rootItem)
                        dialog.open()
                    }
                    icon.source: Qt.resolvedUrl('../../icons/m3/bolt.png')
                }
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            piechart.updateSlices()
        }
    }

    // M3: the colors of the slices follow the theme
    Connections {
        target: m3
        function onDarkChanged() {
            piechart.updateSlices()
        }
    }

    Component.onCompleted: {
        piechart.updateSlices()
    }
}
