import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3

Dialog {
    id: abstractdialog

    property bool allowClose: true
    property string iconSource

    function doClose() {
        close()
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
