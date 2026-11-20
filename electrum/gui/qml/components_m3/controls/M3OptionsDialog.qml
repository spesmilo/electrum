import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Single choice dialog: a scrollable list of radio rows. model: [{ text, value }] or strings.
// selected(value) on user choice, then the dialog closes. Cancel closes without a choice.
M3Dialog {
    id: dialog

    property var model: []
    property var currentValue
    signal selected(var value)

    function _value(o) { return typeof o === 'string' ? o : o.value }
    function _text(o) { return typeof o === 'string' ? o : o.text }

    leftPadding: 0
    rightPadding: 0
    topPadding: m3.space16
    bottomPadding: 0

    contentItem: ListView {
        id: list
        clip: true
        implicitHeight: Math.min(contentHeight, dialog.parent ? dialog.parent.height * 0.6 : 400)
        boundsBehavior: Flickable.StopAtBounds
        model: dialog.model
        ScrollIndicator.vertical: ScrollIndicator {}

        delegate: RadioDelegate {
            required property var modelData
            width: ListView.view.width
            leftPadding: m3.space24
            rightPadding: m3.space24
            text: dialog._text(modelData)
            checked: dialog._value(modelData) === dialog.currentValue
            font.pixelSize: m3.textStyle('bodyLarge').size
            onClicked: {
                dialog.selected(dialog._value(modelData))
                dialog.doAccept()
            }
        }

        Component.onCompleted: {
            for (var i = 0; i < dialog.model.length; i++)
                if (dialog._value(dialog.model[i]) === dialog.currentValue)
                    positionViewAtIndex(i, ListView.Center)
        }
    }

    buttons: [
        M3Button {
            variant: 'text'
            text: qsTr('Cancel')
            onClicked: dialog.doReject()
        }
    ]
}
