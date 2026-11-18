import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "controls"

// "About Electrum" of the Material 3 GUI (route app.routes.about, from the overflow menu and the Settings tab;
// replaces the classic About).
// repeats: components/About.qml:6-97: the title, the logo, the versions BUILD.electrum_version,
// protocol_version, qt_version, pyqt_version, the license, the homepage https://electrum.org opened by
// Qt.openUrlExternally, the developers and the distributor. Only the look differs.
// Layout: the logo is the word mark and atom of the same image as the Terms of Use
// (wizard/WCTermsOfUseRequest.qml); the details are M3DetailRow rows; the homepage is a list row with the
// open_in_new glyph (Material 3 labels are plain text, no links).
// Strings keep the translation context of the classic file (qsTranslate('About', ...)).
M3Page {
    id: root
    objectName: 'About'

    title: qsTranslate('About', 'About Electrum')

    Flickable {
        id: flickable
        anchors.fill: parent
        clip: true
        contentHeight: content.implicitHeight + 2 * m3.space16
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: content
            readonly property int margin: m3.screenMargin(root.width)
            x: Math.max(margin, (flickable.width - width) / 2)
            y: m3.space16
            width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
            spacing: m3.space16

            Image {
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: Math.min(parent.width, 240)
                Layout.preferredHeight: Layout.preferredWidth * sourceClipRect.height / sourceClipRect.width
                fillMode: Image.PreserveAspectFit
                source: Qt.resolvedUrl('../../icons/electrum_presplash.png')
                // the word mark and the atom of the 512x512 image, as wizard/WCTermsOfUseRequest.qml
                sourceClipRect: Qt.rect(96, 76, 320, 236)
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3DetailRow {
                    label: qsTranslate('About', 'Version')
                    text: BUILD.electrum_version
                }
                M3DetailRow {
                    label: qsTranslate('About', 'Protocol version')
                    text: BUILD.protocol_version
                }
                M3DetailRow {
                    label: qsTranslate('About', 'Qt Version')
                    text: BUILD.qt_version
                }
                M3DetailRow {
                    label: qsTranslate('About', 'PyQt Version')
                    text: BUILD.pyqt_version
                }
                M3DetailRow {
                    label: qsTranslate('About', 'License')
                    text: qsTranslate('About', 'MIT License')
                }
                M3DetailRow {
                    label: qsTranslate('About', 'Developers')
                    text: 'Thomas Voegtlin\nSomberNight\nSander van Grieken\nFelix B.'
                }
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3ListItem {
                    headline: qsTranslate('About', 'Homepage')
                    supporting: 'https://electrum.org'
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/public.png')
                    trailing: Component {
                        M3Icon {
                            source: Qt.resolvedUrl('../../icons/m3/open_in_new.png')
                            color: m3.surfaceVariantOn
                        }
                    }
                    onClicked: Qt.openUrlExternally('https://electrum.org')
                }
            }

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                text: qsTranslate('About', 'Distributed by Electrum Technologies GmbH')
            }
        }
    }
}
