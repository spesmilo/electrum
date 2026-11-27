import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Base of every Material 3 page (and of the root of the stack): a light or dark Material 3
// "island" inside the dark application window. Standard Qt controls inside pick up the colors.
Page {
    id: root

    readonly property bool m3Page: true
    // color of the strip under the Android navigation bar (drawn by main.qml, its only owner)
    property color navigationBarBackgroundColor: m3.surface

    // return true when the page consumed the Android back button (see main.qml onClosing)
    function handleBack() {
        return false
    }

    padding: 0
    font.pixelSize: m3.textStyle('bodyMedium').size

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.primary: m3.primary
    // Material.background/foreground are deliberately not set here: they propagate to children, and a
    // classic island inside an M3 page (Wallet/Channels tab) must get the theme default of the dark
    // theme back, which Qt 6.10 does not allow once an ancestor set an explicit value.

    background: Rectangle {
        color: m3.surface
    }
}
