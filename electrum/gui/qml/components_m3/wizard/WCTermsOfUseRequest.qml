import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Material 3 page: terms of use.
// repeats: components/wizard/WCTermsOfUseRequest.qml:7-47 @ e6df7e1c8 (valid, last, the logo, the heading and
// wiz.termsOfUseText in a Flickable). Differences: the logo is cut to the word mark and the atom (the classic
// hides the empty margins of the image by negative layout margins), the text sits in a card.
WizardComponent {
    valid: true
    last: true

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            Image {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: m3.space16
                Layout.preferredWidth: Math.min(parent.width, 240)
                Layout.preferredHeight: Layout.preferredWidth * sourceClipRect.height / sourceClipRect.width
                fillMode: Image.PreserveAspectFit
                source: Qt.resolvedUrl('../../../icons/electrum_presplash.png')
                // the word mark and the atom of the 512x512 image
                sourceClipRect: Qt.rect(96, 76, 320, 236)
            }

            M3Text {
                Layout.fillWidth: true
                role: 'headlineSmall'
                horizontalAlignment: Text.AlignHCenter
                text: qsTranslate('WCTermsOfUseRequest', 'Terms of Use')
            }

            M3Card {
                Layout.fillWidth: true

                M3Text {
                    width: parent.width
                    role: 'bodyMedium'
                    wrapMode: Text.WordWrap
                    lineHeightMode: Text.ProportionalHeight
                    lineHeight: 1.0
                    text: wiz.termsOfUseText
                }
            }
        }
    }
}
