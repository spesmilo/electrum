import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Channels tab: summary of the Lightning channels until the Material 3 channels screen.
// repeats: components/Channels.qml:31-58 (number of open channels, what can be sent / received) @ 4f36c4489.
// The classic Channels.qml opens full screen (embedded in the tab it would bring its own heading and a
// second bottom button row above the navigation bar). Wallets without Lightning get a note, as the
// classic wallet menu hides Channels for them.
Item {
    id: root

    readonly property bool _lightning: Daemon.currentWallet !== null && Daemon.currentWallet.isLightning
    readonly property bool _canEnable: Daemon.currentWallet !== null && !_lightning && Daemon.currentWallet.canHaveLightning

    Flickable {
        anchors.fill: parent
        contentHeight: Math.max(height, column.implicitHeight + 2 * m3.space16)
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: column
            y: Math.max(m3.space16, (parent.height - implicitHeight) / 3)
            width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: m3.space16

            M3Icon {
                Layout.alignment: Qt.AlignHCenter
                source: Qt.resolvedUrl('../../icons/m3/hub.png')
                size: 48
                color: m3.surfaceVariantOn
            }

            // ------------------------------------------------ no Lightning
            M3Text {
                Layout.fillWidth: true
                visible: !root._lightning
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                role: 'titleMedium'
                text: qsTr('This wallet has no Lightning')
            }
            // the wallet can have Lightning: the classic Wallet details page has "Enable Lightning"
            M3Text {
                Layout.fillWidth: true
                visible: root._canEnable
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                text: qsTr('Lightning can be enabled in Wallet details.')
            }
            M3Button {
                Layout.alignment: Qt.AlignHCenter
                visible: root._canEnable
                variant: 'tonal'
                text: qsTranslate('WalletMainView', 'Wallet details')
                onClicked: app.pushPageOnRoot(app.routes.walletDetails)
            }

            // ------------------------------------------------ Lightning
            M3Text {
                Layout.fillWidth: true
                visible: root._lightning
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                role: 'titleMedium'
                text: root._lightning
                    ? qsTranslate('Channels', 'You have %1 open channels').arg(Daemon.currentWallet.channelModel.numOpenChannels)
                    : ''
            }

            M3ListGroup {
                Layout.fillWidth: true
                visible: root._lightning

                ChannelsAmountRow {
                    title: qsTranslate('Channels', 'You can send')
                    amount: root._lightning ? Daemon.currentWallet.lightningCanSend : null
                }
                ChannelsAmountRow {
                    title: qsTranslate('Channels', 'You can receive')
                    amount: root._lightning ? Daemon.currentWallet.lightningCanReceive : null
                }
            }

            M3Button {
                Layout.alignment: Qt.AlignHCenter
                visible: root._lightning
                variant: 'tonal'
                text: qsTranslate('Channels', 'Lightning Channels')
                onClicked: app.pushPageOnRoot(app.routes.channels)
            }
        }
    }

    // a title and an amount (with fiat, as the classic FormattedAmount) in one row
    component ChannelsAmountRow: RowLayout {
        id: amountRow
        property string title
        property var amount

        Layout.fillWidth: true
        Layout.leftMargin: m3.space16
        Layout.rightMargin: m3.space16
        Layout.topMargin: m3.space12
        Layout.bottomMargin: m3.space12
        spacing: m3.space16

        M3Text {
            Layout.fillWidth: true
            role: 'bodyLarge'
            wrapMode: Text.Wrap
            text: amountRow.title
        }
        Loader {
            Layout.alignment: Qt.AlignRight
            active: amountRow.amount !== null && amountRow.amount !== undefined
            sourceComponent: M3Amount {
                amount: amountRow.amount
                role: 'titleMedium'
                unitRole: 'bodyMedium'
                fiatRole: 'bodySmall'
            }
        }
    }
}
