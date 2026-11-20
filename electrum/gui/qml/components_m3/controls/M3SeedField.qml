import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

// Seed input of the Material 3 GUI: an outlined multi-line field (FixedFont, bold,
// at least 3 lines) and, below it, the indicator line (icon + `indicatorText`, m3.success when `indicatorValid`,
// else m3.error), shown while the field and `indicatorText` are not empty. The words are typed with
// M3SeedKeyboard (target: this field), which reads `suggestions`.
// repeats: classic controls/SeedTextArea.qml:13-66, 151-153 (text, placeholderText, indicatorText,
// indicatorValid, the suggestions of bitcoin.mnemonicsFor for the last word, the TextArea that is read-only on
// Android (no system keyboard; on the desktop a physical keyboard types), its input method hints, the work-around
// for spurious textChanged and the cursor kept at the end).
// Differences: the indicator is a line below the field, not a red/green badge in the corner; the suggestions
// and the keys are not part of the field (M3SeedKeyboard: pinned to the bottom of the page).
ColumnLayout {
    id: root

    property string text
    property alias placeholderText: seedtextarea.placeholderText
    property string indicatorText
    property bool indicatorValid
    property alias textArea: seedtextarea
    readonly property var suggestions: _suggestions

    property var _suggestions: []

    spacing: m3.space4

    onTextChanged: {
        if (seedtextarea.text != text)
            seedtextarea.text = text
    }

    TextArea {
        id: seedtextarea
        Layout.fillWidth: true
        Layout.minimumHeight: fontMetrics.lineSpacing * 3 + topPadding + bottomPadding

        Material.containerStyle: Material.Outlined
        Material.accent: m3.primary
        color: m3.surfaceOn
        wrapMode: TextInput.WordWrap
        font.bold: true
        font.pixelSize: m3.textStyle('bodyLarge').size
        font.family: FixedFont
        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhLowercaseOnly | Qt.ImhNoPredictiveText
        readOnly: AppController.isAndroid()

        onTextChanged: {
            // work around Qt issue, TextArea fires spurious textChanged events
            // NOTE: might be Qt virtual keyboard, or Qt upgrade from 5.15.2 to 5.15.7
            if (root.text != text)
                root.text = text

            // update suggestions
            _suggestions = bitcoin.mnemonicsFor(seedtextarea.text.split(' ').pop())
            // TODO: cursorPosition only on suggestion apply
            cursorPosition = text.length
        }
    }

    RowLayout {
        Layout.fillWidth: true
        Layout.leftMargin: m3.space16
        Layout.rightMargin: m3.space16
        visible: root.text !== '' && root.indicatorText !== ''
        spacing: m3.space8

        M3Icon {
            Layout.alignment: Qt.AlignTop
            size: 18
            source: Qt.resolvedUrl(root.indicatorValid
                ? '../../../icons/m3/check_circle.png'
                : '../../../icons/m3/error.png')
            color: root.indicatorValid ? m3.success : m3.error
        }
        M3Text {
            Layout.fillWidth: true
            role: 'bodyMedium'
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            color: root.indicatorValid ? m3.success : m3.error
            text: root.indicatorText
        }
    }

    FontMetrics {
        id: fontMetrics
        font: seedtextarea.font
    }

    Bitcoin {
        id: bitcoin
    }
}
