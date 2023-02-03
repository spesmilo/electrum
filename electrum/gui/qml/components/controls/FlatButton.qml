import QtQuick 2.6
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15
import QtQuick.Controls.impl 2.15
import QtQuick.Controls.Material.impl 2.15

TabButton {
    id: control
    checkable: false

    property bool textUnderIcon: true

    font.pixelSize: constants.fontSizeSmall
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
}
