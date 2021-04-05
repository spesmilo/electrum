import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import QtQml 2.6
import QtMultimedia 5.6

ApplicationWindow
{
    id: app
    visible: true
    width: 480
    height: 800

    Material.theme: Material.Dark
    Material.primary: Material.Indigo
    Material.accent: Material.LightBlue

    property alias stack: mainStackView

    header: ToolBar {
        id: toolbar
        RowLayout {
            anchors.fill: parent
            ToolButton {
                text: qsTr("‹")
                enabled: stack.currentItem.StackView.index > 0
                onClicked: stack.pop()
            }
            Label {
                text: stack.currentItem.title
                elide: Label.ElideRight
                horizontalAlignment: Qt.AlignHCenter
                verticalAlignment: Qt.AlignVCenter
                Layout.fillWidth: true
            }
            ToolButton {
                text: qsTr("⋮")
                onClicked: {
                    stack.currentItem.menu.open()
                    // position the menu to the right
                    stack.currentItem.menu.x = toolbar.width - stack.currentItem.menu.width
                }
            }
        }
    }

    StackView {
        id: mainStackView
        anchors.fill: parent

        initialItem: Qt.resolvedUrl('landing.qml')
    }

    Timer {
        id: splashTimer
        interval: 1000
        onTriggered: {
            splash.opacity = 0
        }
    }

    Splash {
        id: splash
        anchors.top: header.top
        anchors.bottom: app.contentItem.bottom
        width: app.width
        z: 1000

        Behavior on opacity {
            NumberAnimation { duration: 300 }
        }
    }

    Component.onCompleted: {
        Daemon.load_wallet()
        splashTimer.start()
    }
}
