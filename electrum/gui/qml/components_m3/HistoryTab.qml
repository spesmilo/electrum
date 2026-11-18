import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// History tab: the full wallet history, M3HistoryDelegate rows under date sections (controls/M3HistoryList).
// repeats: components/History.qml:51-75 (sections), :94-103 (empty note), :150-176 (height updates,
// delegate reset on a new wallet, model refresh when shown) @ 4f36c4489.
// The model is lazy (it rebuilds only when dirty): initModel() runs when the tab is created, when a
// wallet is loaded and whenever the tab becomes visible again (tab switch, back from a pushed page).
// The "no transactions" note shows only after that first initModel() of the current model.
Item {
    id: root

    readonly property QtObject backingModel: Daemon.currentWallet ? Daemon.currentWallet.historyModel : null
    property QtObject _initializedModel: null
    readonly property bool modelReady: backingModel !== null && _initializedModel === backingModel

    function initModel() {
        if (!backingModel)
            return
        backingModel.initModel()
        _initializedModel = backingModel
    }

    // the list with its date sections (controls/M3HistoryList); the model is initialized here
    M3HistoryList {
        id: listview
        anchors.fill: parent
        model: root.backingModel
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
        spacing: m3.space16
        // "No transactions" only when up to date (as History.qml); offline the server status instead of
        // an empty screen (a wallet without a server is never up to date)
        visible: root.modelReady && root.backingModel.count == 0
            && (!Daemon.currentWallet.synchronizing || !Network.isConnected)

        M3Icon {
            Layout.alignment: Qt.AlignHCenter
            source: Qt.resolvedUrl(!Daemon.currentWallet || !Daemon.currentWallet.synchronizing
                ? '../../icons/m3/history.png'
                : '../../icons/m3/cloud_off.png')
            size: 48
            color: m3.surfaceVariantOn
        }
        M3Text {
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
            role: 'bodyLarge'
            color: m3.surfaceVariantOn
            text: !Daemon.currentWallet || !Daemon.currentWallet.synchronizing
                ? qsTranslate('History', 'No transactions in this wallet yet')
                : Network.serverStatus
        }
    }

    Connections {
        target: Network
        function onHeightChanged(height) {
            // the Wallet tab shows the same model: one update per block is enough for both
            if (root.backingModel)
                root.backingModel.updateBlockchainHeight(height)
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            root.initModel()
            listview.positionViewAtBeginning()
        }
    }

    onVisibleChanged: {
        if (visible)
            root.initModel()
    }

    Component.onCompleted: root.initModel()
}
