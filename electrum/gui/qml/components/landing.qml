import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQml 2.6

Item {
    property string title: 'Network'

    property QtObject menu: Menu {
        MenuItem { text: 'Wallets'; onTriggered: stack.push(Qt.resolvedUrl('Wallets.qml')) }
        MenuItem { text: 'Network'; onTriggered: stack.push(Qt.resolvedUrl('NetworkStats.qml')) }
    }

    Column {
        width: parent.width

        Button {
            text: 'Scan QR Code'
            onClicked: app.stack.push(Qt.resolvedUrl('Scan.qml'))
        }

        Button {
            text: 'Send'
            onClicked: app.stack.push(Qt.resolvedUrl('Send.qml'))
        }

        Button {
            text: 'Show TX History'
            onClicked: app.stack.push(Qt.resolvedUrl('History.qml'))
        }

    }

}

