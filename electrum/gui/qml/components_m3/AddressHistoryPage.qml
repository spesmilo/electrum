import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Transaction history of one address in the Material 3 GUI (route app.routes.addressHistory, opened from the address
// details; replaces the classic AddressHistory).
// repeats: components/AddressHistory.qml:10-59 (the page contract: required `address` and
// `backingModel`, the history model of the address; the heading and the address above the list) and, for the list,
// components/History.qml:150-176 as the classic History embedded there runs it: the block height
// update of the model and initModel() of the (lazy) model whenever the page becomes visible. The rows and the date
// sections are those of the History tab (controls/M3HistoryList).
// Strings carried over from AddressHistory.qml keep its translation context.
M3Page {
    id: root

    required property string address
    required property QtObject backingModel

    title: qsTr('Address history')

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // AddressHistory.qml:23-42: the address
        M3ListGroup {
            readonly property int margin: m3.screenMargin(root.width)
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            Layout.maximumWidth: m3.maxContentWidth - 2 * margin
            Layout.leftMargin: margin
            Layout.rightMargin: margin
            Layout.topMargin: m3.space16

            M3DetailRow {
                label: qsTranslate('AddressHistory', 'Transaction history for address:')
                text: root.address
                monospace: true
            }
        }

        M3HistoryList {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: root.backingModel
        }
    }

    // History.qml:150-156
    Connections {
        target: Network
        function onHeightChanged(height) {
            if (root.backingModel)
                root.backingModel.updateBlockchainHeight(height)
        }
    }

    // History.qml:169-176: refresh the model when the page becomes visible and the model is dirty
    StackView.onVisibleChanged: {
        if (StackView.visible && root.backingModel)
            root.backingModel.initModel()
    }
}
