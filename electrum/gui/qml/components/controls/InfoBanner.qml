import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

Item {
    id: root

    property string message
    property bool autohide: false
    property color color: constants.colorAlpha(constants.colorWarning, 0.1)
    property url icon: Qt.resolvedUrl('../../../icons/warning.png')
    property alias font: messageLabel.font

    property bool _hide: true
    property var _clicked_fn

    clip:true
    z: 1
    layer.enabled: height > 0
    layer.effect: ElevationEffect {
        elevation: constants.paddingXLarge
        fullWidth: true
    }

    state: 'hidden'

    states: [
        State {
            name: 'hidden'; when: _hide
            PropertyChanges { target: root; implicitHeight: 0 }
        },
        State {
            name: 'expanded'; when: !_hide
            PropertyChanges { target: root; implicitHeight: layout.implicitHeight }
        }
    ]

    transitions: [
        Transition {
            from: 'hidden'; to: 'expanded'
            SequentialAnimation {
                PropertyAction  { target: root; property: 'visible'; value: true }
                NumberAnimation { target: root; properties: 'implicitHeight'; duration: 300; easing.type: Easing.OutQuad }
            }
        },
        Transition {
            from: 'expanded'; to: 'hidden'
            SequentialAnimation {
                NumberAnimation { target: root; properties: 'implicitHeight'; duration: 100; easing.type: Easing.OutQuad }
                PropertyAction  { target: root; property: 'visible'; value: false }
            }
        }
    ]

    function show(message, on_clicked=undefined) {
        root.message = message
        root._clicked_fn = on_clicked
        root._hide = false
        if (autohide)
            closetimer.start()
    }

    function hide() {
        closetimer.stop()
        root._hide = true
    }

    Rectangle {
        id: rect
        width: root.width
        height: layout.height
        color: root.color
        anchors.bottom: root.bottom

        ColumnLayout {
            id: layout
            width: parent.width
            spacing: 0

            RowLayout {
                Layout.margins: constants.paddingLarge
                spacing: constants.paddingSmall

                Image {
                    source: root.icon
                    Layout.preferredWidth: constants.iconSizeLarge
                    Layout.preferredHeight: constants.iconSizeLarge
                }

                Label {
                    id: messageLabel
                    Layout.fillWidth: true
                    font.pixelSize: constants.fontSizeSmall
                    color: Material.foreground
                    wrapMode: Text.Wrap
                    text: root.message
                }
            }
            Rectangle {
                Layout.preferredHeight: 2
                Layout.fillWidth: true
                color: Material.accentColor
            }
        }
    }

    MouseArea {
        anchors.fill: parent
        onClicked: {
            if (root._clicked_fn)
                root._clicked_fn()
        }
    }

    Timer {
        id: closetimer
        interval: 5000
        repeat: false
        onTriggered: _hide = true
    }

}
