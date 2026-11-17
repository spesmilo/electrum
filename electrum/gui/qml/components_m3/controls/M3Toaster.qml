import QtQuick
import QtQuick.Controls

// Short confirmation above an item ("Copied!"), Material 3 look (inverse surface, as a snackbar).
// repeats: components/controls/Toaster.qml:1-50 @ e6df7e1c8 (show(item, text): placed centered above `item`
// in the coordinates of the parent, shown 1 s, then rises and fades out in 1 s). Differences: colors and type
// from `m3` (inverseSurface / inverseSurfaceOn, bodyMedium, radius S), the gap above the item is m3.space16.
// Declare it as a child of the page or dialog that holds `item` (it maps `item` into its parent).
Item {
    id: toaster
    width: rect.width
    height: rect.height
    visible: false
    z: 100

    property int _y
    property string _text

    function show(item, text) {
        _text = text
        var r = item.mapToItem(parent, 0, 0)
        x = r.x + 0.5*(item.width - toaster.width)
        y = r.y - toaster.height - m3.space16
        toaster._y = y - toaster.height
        ani.restart()
    }

    SequentialAnimation {
        id: ani
        running: false
        PropertyAction { target: toaster; property: 'visible'; value: true }
        PropertyAction { target: toaster; property: 'opacity'; value: 1 }
        PauseAnimation { duration: 1000}
        ParallelAnimation {
            NumberAnimation { target: toaster; property: 'y'; to: toaster._y; duration: 1000; easing.type: Easing.InQuad }
            NumberAnimation { target: toaster; property: 'opacity'; to: 0; duration: 1000 }
        }
        PropertyAction { target: toaster; property: 'visible'; value: false }
    }

    Rectangle {
        id: rect
        width: label.implicitWidth
        height: label.implicitHeight
        radius: m3.radiusS
        color: m3.inverseSurface

        M3Text {
            id: label
            leftPadding: m3.space16
            rightPadding: m3.space16
            topPadding: m3.space12
            bottomPadding: m3.space12
            role: 'bodyMedium'
            color: m3.inverseSurfaceOn
            text: toaster._text
        }
    }
}
