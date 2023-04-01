import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

TextHighlightPane {
    enum IconStyle {
        None,
        Info,
        Warn,
        Error,
        Progress,
        Pending,
        Done
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
                : iconStyle == InfoTextArea.IconStyle.Progress
                    ? constants.colorProgress
                    : iconStyle == InfoTextArea.IconStyle.Done
                        ? constants.colorDone
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
                        : iconStyle == InfoTextArea.IconStyle.Progress
                            ? "../../../icons/unconfirmed.png"
                            : iconStyle == InfoTextArea.IconStyle.Pending
                                ? "../../../icons/unpaid.png"
                                : iconStyle == InfoTextArea.IconStyle.Done
                                    ? "../../../icons/confirmed.png"
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
