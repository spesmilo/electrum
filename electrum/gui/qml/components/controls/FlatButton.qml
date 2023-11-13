import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Controls.impl
import QtQuick.Controls.Material.impl

TabButton {
    id: control
    checkable: false

    property bool textUnderIcon: true

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
}
