import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

Rectangle {
    id: root

    property alias text: textItem.text

    property bool hide: true

    color: Qt.lighter(Material.background, 1.5)
    radius: constants.paddingXLarge

    width: root.parent.width * 2/3
    height: layout.height
    x: (root.parent.width - width) / 2
    y: -height

    states: [
        State {
            name: 'expanded'; when: !hide
            PropertyChanges { target: root; y: 100 }
        }
    ]

    transitions: [
        Transition {
            from: ''; to: 'expanded'; reversible: true
            NumberAnimation { properties: 'y'; duration: 300; easing.type: Easing.InOutQuad }
        }
    ]

    RowLayout {
        id: layout
        width: parent.width
        Text {
            id: textItem
            Layout.alignment: Qt.AlignHCenter
            font.pixelSize: constants.fontSizeLarge
            color: Material.foreground
        }
    }

    Timer {
        id: closetimer
        interval: 5000
        repeat: false
        onTriggered: hide = true
    }

    Component.onCompleted: {
        hide = false
        closetimer.start()
    }
}
