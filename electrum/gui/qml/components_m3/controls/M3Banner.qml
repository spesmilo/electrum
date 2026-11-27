import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 banner with the API of the classic controls/InfoBanner.qml (app.infobanner):
// show(message, on_clicked), hide(), message, autohide
Item {
    id: root

    property string message
    property bool autohide: false
    property url icon: Qt.resolvedUrl('../../../icons/m3/warning.png')

    property bool _hide: true
    property var _clicked_fn

    clip: true
    z: 1
    visible: false
    implicitHeight: 0

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.foreground: m3.tertiaryContainerOn

    states: [
        State {
            name: 'hidden'; when: root._hide
            PropertyChanges { target: root; implicitHeight: 0 }
        },
        State {
            name: 'expanded'; when: !root._hide
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
        width: root.width
        height: layout.implicitHeight
        anchors.bottom: root.bottom
        color: m3.tertiaryContainer

        RowLayout {
            id: layout
            width: parent.width
            spacing: m3.space16

            M3Icon {
                Layout.leftMargin: m3.space16
                Layout.topMargin: m3.space16
                Layout.alignment: Qt.AlignTop
                source: root.icon
                color: m3.tertiaryContainerOn
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.topMargin: m3.space16
                Layout.bottomMargin: root._clicked_fn ? 0 : m3.space16
                Layout.rightMargin: m3.space16
                spacing: 0

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyMedium'
                    wrapMode: Text.Wrap
                    lineHeightMode: Text.ProportionalHeight
                    lineHeight: 1.0
                    color: m3.tertiaryContainerOn
                    text: root.message
                }

                M3Button {
                    Layout.alignment: Qt.AlignRight
                    visible: !!root._clicked_fn
                    variant: 'text'
                    contentColor: m3.tertiary
                    text: qsTr('Details')
                    onClicked: root._clicked_fn()
                }
            }
        }
    }

    Timer {
        id: closetimer
        interval: 5000
        repeat: false
        onTriggered: root.hide()
    }
}
