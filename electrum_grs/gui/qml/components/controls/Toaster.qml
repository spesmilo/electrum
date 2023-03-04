import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import ".."

Item {
    id: toaster
    width: contentItem.implicitWidth
    height: rect.height
    visible: false

    property int _y
    property string _text

    function show(item, text) {
        _text = text
        var r = item.mapToItem(parent, item.x, item.y)
        x = r.x + 0.5*(item.width - toaster.width)
        y = r.y - toaster.height - constants.paddingLarge
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
        width: contentItem.width
        height: contentItem.height
        color: constants.colorAlpha(Material.background, 0.90)

        RowLayout {
            id: contentItem
            Label {
                Layout.margins: 10
                text: toaster._text
                onTextChanged: {
                    // hack. ref implicitWidth so it gets recalculated
                    var _ = contentItem.implicitWidth
                }
            }
        }
    }
}
