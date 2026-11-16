import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../components" as Classic
import "controls"

// Wallet tab. Placeholder until the Material 3 home screen: the classic history list (with the
// balance) in a dark classic island, and the Receive / Send actions of the classic WalletMainView.
Item {
    id: root

    property QtObject paymentFlow

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // classic island: classic controls use the classic dark theme and `constants` colors
        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            // the window keeps the classic theme; copy it (the M3 page around sets its own)
            Material.theme: app.Material.theme
            Material.primary: app.Material.primary
            Material.accent: app.Material.accent

            Classic.History {
                id: history
                anchors.fill: parent
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.margins: m3.space16
            spacing: m3.space12

            M3Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                variant: 'tonal'
                shape: 'large'
                size: 56
                text: qsTr('Receive')
                onClicked: root.paymentFlow.openReceiveDetailsDialog()
                onPressAndHold: {
                    Config.userKnowsPressAndHold = true
                    Daemon.currentWallet.deleteExpiredRequests()
                    app.stack.push(Qt.resolvedUrl('../components/ReceiveRequests.qml'))
                    AppController.haptic()
                }
            }
            M3Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                variant: 'filled'
                shape: 'large'
                size: 56
                text: qsTr('Send')
                enabled: root.paymentFlow
                    && !root.paymentFlow.invoiceParser.busy
                    && !root.paymentFlow.piResolver.busy
                    && !root.paymentFlow.requestDetails.busy
                onClicked: root.paymentFlow.openSendDialog()
                onPressAndHold: {
                    Config.userKnowsPressAndHold = true
                    app.stack.push(Qt.resolvedUrl('../components/Invoices.qml'))
                    AppController.haptic()
                }
            }
        }
    }
}
