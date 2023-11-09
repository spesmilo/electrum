import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

TextHighlightPane {
    enum IconStyle {
        None,
        Info,
        Warn,
        Error,
        Progress,
        Pending,
        Done,
        Spinner
    }

    property alias text: infotext.text
    property int iconStyle: InfoTextArea.IconStyle.Info
    property alias textFormat: infotext.textFormat
    property bool compact: false

    borderColor: iconStyle == InfoTextArea.IconStyle.Info
        ? constants.colorInfo
        : iconStyle == InfoTextArea.IconStyle.Warn
            ? constants.colorWarning
            : iconStyle == InfoTextArea.IconStyle.Error
                ? constants.colorError
                : iconStyle == InfoTextArea.IconStyle.Progress || iconStyle == InfoTextArea.IconStyle.Spinner
                    ? constants.colorProgress
                    : iconStyle == InfoTextArea.IconStyle.Done
                        ? constants.colorDone
                        : constants.colorInfo
    padding: compact ? constants.paddingMedium : constants.paddingXLarge

    RowLayout {
        width: parent.width
        spacing: compact ? constants.paddingMedium : constants.paddingLarge

        Image {
            Layout.preferredWidth: compact ? constants.iconSizeSmall : constants.iconSizeMedium
            Layout.preferredHeight: compact ? constants.iconSizeSmall : constants.iconSizeMedium
            visible: iconStyle != InfoTextArea.IconStyle.Spinner && iconStyle != InfoTextArea.IconStyle.None
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
        }

        Item {
            Layout.preferredWidth: compact ? constants.iconSizeSmall : constants.iconSizeMedium
            Layout.preferredHeight: compact ? constants.iconSizeSmall : constants.iconSizeMedium
            visible: iconStyle == InfoTextArea.IconStyle.Spinner

            BusyIndicator {
                anchors.centerIn: parent
                scale: 0.66
                smooth: true
                running: visible
            }
        }

        Label {
            id: infotext
            Layout.fillWidth: true
            width: parent.width
            wrapMode: Text.Wrap
        }
    }
}
