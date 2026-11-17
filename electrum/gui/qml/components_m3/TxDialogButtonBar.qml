import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "controls"

// Bar with the main button of a transaction dialog of the Material 3 GUI (BumpFeeDialog, CpfpDialog,
// CancelTxDialog, ConfirmTxDialog): below the scrolled content and above the keyboard (the dialog shrinks with
// the keyboard), one filled 56 dp button as wide as the content column. The Material 3 form of the classic
// DialogButtonContainer + FlatButton (components/RbfBumpFeeDialog.qml:227-238 @ e6df7e1c8 and the others).
Rectangle {
    id: root

    property alias text: button.text
    property alias icon: button.icon
    signal clicked()

    implicitHeight: button.implicitHeight + 2 * m3.space16
    color: m3.surface

    M3Button {
        id: button
        readonly property int margin: m3.screenMargin(root.width)
        x: Math.max(margin, (root.width - width) / 2)
        anchors.verticalCenter: parent.verticalCenter
        width: Math.min(m3.maxContentWidth, root.width - 2 * margin)
        variant: 'filled'
        size: 56
        enabled: root.enabled
        onClicked: root.clicked()
    }
}
