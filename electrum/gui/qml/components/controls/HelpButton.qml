import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

ToolButton {
    id: root
    property string heading
    property string helptext

    icon.source: Qt.resolvedUrl('../../../icons/info.png')
    icon.color: 'transparent'
    onClicked: {
        var dialog = app.helpDialog.createObject(app, {
            heading: root.heading,
            text: root.helptext
        })
        dialog.open()
    }
}
