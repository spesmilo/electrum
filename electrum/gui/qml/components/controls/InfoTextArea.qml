import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

TextHighlightPane {
    enum IconStyle {
        None,
        Info,
        Warn,
        Error
    }

    property alias text: infotext.text
    property int iconStyle: InfoTextArea.IconStyle.Info
    property alias textFormat: infotext.textFormat

    borderColor: iconStyle == InfoTextArea.IconStyle.Info
        ? constants.colorInfo
        : iconStyle == InfoTextArea.IconStyle.Warn
            ? constants.colorWarning
            : iconStyle == InfoTextArea.IconStyle.Error
                ? constants.colorError
                : constants.colorInfo
    padding: constants.paddingXLarge

    RowLayout {
        width: parent.width
        spacing: constants.paddingLarge

        Image {
            source: iconStyle == InfoTextArea.IconStyle.Info
                ? "../../../icons/info.png"
                : iconStyle == InfoTextArea.IconStyle.Warn
                    ? "../../../icons/warning.png"
                    : iconStyle == InfoTextArea.IconStyle.Error
                        ? "../../../icons/expired.png"
                        : ""
            Layout.preferredWidth: constants.iconSizeMedium
            Layout.preferredHeight: constants.iconSizeMedium
        }

        Label {
            id: infotext
            Layout.fillWidth: true
            width: parent.width
            wrapMode: Text.Wrap
        }
    }
}
