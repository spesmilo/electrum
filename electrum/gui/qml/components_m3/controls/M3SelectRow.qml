import QtQuick
import QtQuick.Controls

// List row showing the current choice as supporting text; a tap opens M3OptionsDialog.
// model: [{ text, value }] or an array of strings; selected(value) on user choice.
M3ListItem {
    id: root

    property var model: []
    property var currentValue
    property string dialogTitle: headline
    signal selected(var value)

    function _textOf(value) {
        for (var i = 0; i < model.length; i++) {
            var o = model[i]
            if (typeof o === 'string' ? o === value : o.value === value)
                return typeof o === 'string' ? o : o.text
        }
        return ''
    }

    supporting: _textOf(currentValue)

    onClicked: {
        var dialog = optionsDialog.createObject(app, {
            title: root.dialogTitle,
            model: root.model,
            currentValue: root.currentValue
        })
        dialog.selected.connect(function(value) {
            root.selected(value)
        })
        dialog.open()
    }

    Component {
        id: optionsDialog
        M3OptionsDialog {
            onClosed: destroy()
        }
    }
}
