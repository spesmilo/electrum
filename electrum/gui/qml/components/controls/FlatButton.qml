import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Controls.impl
import QtQuick.Controls.Material.impl

TabButton {
    id: control
    checkable: false

    property bool textUnderIcon: true
    property bool pressAndHoldIndicator: false

    font.pixelSize: constants.fontSizeSmall
    icon.width: constants.iconSizeMedium
    icon.height: constants.iconSizeMedium
    display: textUnderIcon ? IconLabel.TextUnderIcon : IconLabel.TextBesideIcon

    contentItem: IconLabel {
        spacing: control.spacing
        mirrored: control.mirrored
        display: control.display

        icon: control.icon
        text: control.text
        font: control.font
        color: !control.enabled ? control.Material.hintTextColor : control.down || control.checked ? control.Material.accentColor : control.Material.foreground
    }

    Rectangle {
        id: indicator
        anchors.top: control.top
        anchors.horizontalCenter: control.horizontalCenter
        width: 0
        opacity: 0
        height: 3
        color: control.Material.accentColor

        states: State {
            name: 'pressing'
            when: pressAndHoldIndicator && control.pressed
            PropertyChanges {
                target: indicator
                width: control.width
                opacity: 1
            }
        }

        transitions: Transition {
            to: 'pressing'
            SequentialAnimation {
                PauseAnimation {
                    duration: 200
                }
                ParallelAnimation {
                    NumberAnimation {
                        target: indicator
                        property: "width"
                        duration: 600
                    }
                    NumberAnimation {
                        target: indicator
                        property: "opacity"
                        duration: 600
                    }
                }
            }
        }
    }
}
