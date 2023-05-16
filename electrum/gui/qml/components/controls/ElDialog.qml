import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3

Dialog {
    id: abstractdialog

    property bool allowClose: true
    property string iconSource
    property bool resizeWithKeyboard: true

    property bool _result: false

    // called to finally close dialog after checks by onClosing handler in main.qml
    function doClose() {
        doReject()
    }

    // avoid potential multiple signals, only emit once
    function doAccept() {
        if (_result)
            return
        _result = true
        accept()
    }

    // avoid potential multiple signals, only emit once
    function doReject() {
        if (_result)
            return
        _result = true
        reject()
    }

    parent: resizeWithKeyboard ? Overlay.overlay.children[0] : Overlay.overlay
    modal: true
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    closePolicy: allowClose
        ? Popup.CloseOnEscape | Popup.CloseOnPressOutside
        : Popup.NoAutoClose

    onOpenedChanged: {
        if (opened) {
            app.activeDialogs.push(abstractdialog)
        } else {
            if (app.activeDialogs.indexOf(abstractdialog) < 0) {
                console.log('dialog should exist in activeDialogs!')
                app.activeDialogs.pop()
                return
            }
            app.activeDialogs.splice(app.activeDialogs.indexOf(abstractdialog),1)
        }
    }

    header: ColumnLayout {
        spacing: 0

        RowLayout {
            spacing: 0

            Image {
                visible: iconSource
                source: iconSource
                Layout.preferredWidth: constants.iconSizeXLarge
                Layout.preferredHeight: constants.iconSizeXLarge
                Layout.leftMargin: constants.paddingMedium
                Layout.topMargin: constants.paddingMedium
                Layout.bottomMargin: constants.paddingMedium
            }

            Label {
                text: title
                wrapMode: Text.Wrap
                elide: Label.ElideRight
                Layout.fillWidth: true
                leftPadding: constants.paddingXLarge
                topPadding: constants.paddingXLarge
                bottomPadding: constants.paddingXLarge
                rightPadding: constants.paddingXLarge
                font.bold: true
                font.pixelSize: constants.fontSizeMedium
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXXSmall
            Layout.rightMargin: constants.paddingXXSmall
            height: 1
            color: Qt.rgba(0,0,0,0.5)
        }
    }

}
