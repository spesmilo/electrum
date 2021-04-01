import QtQuick 2.6
import QtQuick.Controls 1.4
import QtQml 2.6
import QtMultimedia 5.6

ApplicationWindow
{
    id: app
    visible: true
    width: 480
    height: 800
    color: '#dddddd'

    property alias stack: mainStackView

    StackView {
        id: mainStackView
        anchors.fill: parent

        initialItem: Qt.resolvedUrl('splash.qml')
    }

    Timer {
        id: splashTimer
        interval: 400
        onTriggered: {
            mainStackView.push(Qt.resolvedUrl('landing.qml'))
        }
    }

    Component.onCompleted: {
        Daemon.load_wallet()
        splashTimer.start()
    }
}
