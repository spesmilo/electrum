import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Header of the multisig cosigner pages: the master public key to share with the
// cosigners and the number of the cosigner. Hidden while `cosigner` is 0.
// repeats: components/wizard/WCHaveSeed.qml:112-162 (the same block is in WCHaveMasterKey.qml:66-114
// and WCCosignerKeystore.qml:34-76): the text, the key in the fixed font, the share button with
// app.genericShareDialog, the divider, "Cosigner #%1 of %2".
ColumnLayout {
    id: root

    property string pubkey
    property int cosigner: 0
    property int participants: 0

    visible: cosigner
    spacing: m3.space12

    M3Text {
        Layout.fillWidth: true
        role: 'bodyLarge'
        wrapMode: Text.Wrap
        text: qsTranslate('WCHaveSeed', 'Here is your master public key. Please share it with your cosigners')
    }

    M3Card {
        Layout.fillWidth: true
        rightPadding: m3.space4

        RowLayout {
            width: parent.width
            spacing: m3.space8
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                font.family: FixedFont
                wrapMode: Text.WrapAnywhere
                text: root.pubkey
            }
            M3IconButton {
                Layout.alignment: Qt.AlignTop
                tooltip: qsTranslate('WCHaveSeed', 'Master public key')
                icon.source: Qt.resolvedUrl('../../../icons/m3/share.png')
                onClicked: {
                    var dialog = app.genericShareDialog.createObject(app,
                        { title: qsTranslate('WCHaveSeed', 'Master public key'), text: root.pubkey }
                    )
                    dialog.open()
                }
            }
        }
    }

    Rectangle {
        Layout.fillWidth: true
        Layout.preferredHeight: 1
        Layout.topMargin: m3.space4
        Layout.bottomMargin: m3.space4
        color: m3.outlineVariant
    }

    M3Text {
        Layout.fillWidth: true
        role: 'titleSmall'
        text: qsTranslate('WCHaveSeed', 'Cosigner #%1 of %2').arg(root.cosigner).arg(root.participants)
    }
}
