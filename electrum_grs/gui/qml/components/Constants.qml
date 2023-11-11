import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

Item {
    readonly property int paddingXXSmall: 4
    readonly property int paddingXSmall: 6
    readonly property int paddingSmall: 8
    readonly property int paddingMedium: 12
    readonly property int paddingLarge: 16
    readonly property int paddingXLarge: 20
    readonly property int paddingXXLarge: 28

    readonly property int fontSizeXSmall: 10
    readonly property int fontSizeSmall: 12
    readonly property int fontSizeMedium: 15
    readonly property int fontSizeLarge: 18
    readonly property int fontSizeXLarge: 22
    readonly property int fontSizeXXLarge: 28

    readonly property int iconSizeXSmall: 12
    readonly property int iconSizeSmall: 16
    readonly property int iconSizeMedium: 24
    readonly property int iconSizeLarge: 32
    readonly property int iconSizeXLarge: 48
    readonly property int iconSizeXXLarge: 64

    readonly property int fingerWidth: 64 // TODO: determine finger width from screen dimensions and resolution

    property color mutedForeground: 'gray' //Qt.lighter(Material.background, 2)
    property color darkerBackground: Qt.darker(Material.background, 1.20)
    property color lighterBackground: Qt.lighter(Material.background, 1.10)
    property color darkerDialogBackground: Qt.darker(Material.dialogColor, 1.20)
    property color notificationBackground: Qt.lighter(Material.background, 1.5)

    property color colorCredit: "#ff80ff80"
    property color colorDebit: "#ffff8080"

    property color colorInfo: Material.accentColor
    property color colorWarning: 'yellow'
    property color colorError: '#ffff8080'
    property color colorProgress: '#ffffff80'
    property color colorDone: '#ff80ff80'
    property color colorValidBackground: '#ff008000'
    property color colorInvalidBackground: '#ff800000'
    property color colorAcceptable: '#ff8080ff'

    property color colorLightningLocal: "#6060ff"
    property color colorLightningLocalReserve: "#0000a0"
    property color colorLightningRemote: "yellow"
    property color colorLightningRemoteReserve: Qt.darker(colorLightningRemote, 1.5)
    property color colorChannelOpen: "#ff80ff80"

    property color colorPiechartTotal: Material.accentColor
    property color colorPiechartOnchain: Qt.darker(Material.accentColor, 1.50)
    property color colorPiechartFrozen: 'gray'
    property color colorPiechartLightning: 'orange'
    property color colorPiechartLightningFrozen: Qt.darker('orange', 1.20)
    property color colorPiechartUnconfirmed: Qt.darker(Material.accentColor, 2.00)
    property color colorPiechartUnmatured: 'magenta'

    property color colorPiechartParticipant: 'gray'
    property color colorPiechartSignature: 'yellow'

    property color colorAddressExternal: "#8af296" //Qt.rgba(0,1,0,0.5)
    property color colorAddressInternal: "#ffff00" //Qt.rgba(1,0.93,0,0.75)
    property color colorAddressUsed: Qt.rgba(0.5,0.5,0.5,1)
    property color colorAddressUsedWithBalance: Qt.rgba(0.75,0.75,0.75,1)
    property color colorAddressFrozen: Qt.rgba(0.5,0.5,1,1)
    property color colorAddressBilling: "#8cb3f2"

    function colorAlpha(baseColor, alpha) {
        return Qt.rgba(baseColor.r, baseColor.g, baseColor.b, alpha)
    }
}
