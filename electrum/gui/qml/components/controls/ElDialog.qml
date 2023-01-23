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

    onOpenedChanged: {
        if (opened) {
            app.activeDialogs.push(abstractdialog)
        } else {
            app.activeDialogs.pop()
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
