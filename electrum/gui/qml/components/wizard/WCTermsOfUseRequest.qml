import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

WizardComponent {
    valid: true
    last: true

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height
        clip: true
        interactive: height < contentHeight

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: constants.paddingLarge

            Image {
                Layout.fillWidth: true
                fillMode: Image.PreserveAspectFit
                source: Qt.resolvedUrl('../../../icons/electrum_presplash.png')
                // reduce spacing a bit
                Layout.topMargin: -100
                Layout.bottomMargin: -200
            }

            Label {
                Layout.fillWidth: true
                text: qsTr("Terms of Use")
                font.pixelSize: constants.fontSizeLarge
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
            }

            Label {
                Layout.fillWidth: true
                text: wiz.termsOfUseText
                wrapMode: Text.WordWrap
                font.pixelSize: constants.fontSizeMedium
                padding: constants.paddingSmall
            }
        }
    }
}
