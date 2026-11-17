import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// Notice block of the Material 3 GUI (the "M3Notice" of the onboarding design, DESIGN-M2-onboarding.md 7.4):
// a tonal container (radius 12, padding 16, compact 12) with a 20 dp icon and bodyMedium text.
// API: `text`, `tone` ('info' | 'warn' | 'error' | 'success' | 'progress'), `textFormat` (PlainText by default),
// `compact`; plus the properties of the classic InfoTextArea that classic screens use, so a screen moves over
// verbatim: `iconStyle` (M3InfoText.IconStyle, same values as InfoTextArea.IconStyle; it sets `tone` unless
// `tone` is set explicitly: Info -> info, Warn -> warn, Error -> error, Done -> success,
// Progress / Pending / Spinner -> progress; None hides the icon), `horizontalAlignment`, `backgroundColor`,
// `borderColor` (default: the colors of the tone).
// repeats: components/controls/InfoTextArea.qml:6-79 @ e6df7e1c8 (the IconStyle enum and the properties);
// the look is Material 3 (no colored classic icons, no border by default).
Pane {
    id: root

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
    property int iconStyle: M3InfoText.IconStyle.Info
    property string tone: _toneOf(iconStyle)
    property alias textFormat: infotext.textFormat
    property alias horizontalAlignment: infotext.horizontalAlignment
    property bool compact: false

    readonly property var _tones: ({
        'info':     { bg: m3.secondaryContainer,   fg: m3.secondaryContainerOn, icon: 'info' },
        'warn':     { bg: m3.tertiaryContainer,    fg: m3.tertiaryContainerOn,  icon: 'warning' },
        'error':    { bg: m3.errorContainer,       fg: m3.errorContainerOn,     icon: 'error' },
        'success':  { bg: m3.successContainer,     fg: m3.successContainerOn,   icon: 'check_circle' },
        'progress': { bg: m3.surfaceContainerHigh, fg: m3.surfaceVariantOn,     icon: '' }
    })
    readonly property var _t: tone in _tones ? _tones[tone] : _tones['info']

    property color backgroundColor: _t.bg
    property color borderColor: 'transparent'
    property color textColor: _t.fg

    function _toneOf(style) {
        switch (style) {
        case M3InfoText.IconStyle.Warn: return 'warn'
        case M3InfoText.IconStyle.Error: return 'error'
        case M3InfoText.IconStyle.Done: return 'success'
        case M3InfoText.IconStyle.Progress:
        case M3InfoText.IconStyle.Pending:
        case M3InfoText.IconStyle.Spinner: return 'progress'
        default: return 'info'
        }
    }

    readonly property bool _showIcon: iconStyle !== M3InfoText.IconStyle.None

    padding: compact ? m3.space12 : m3.space16

    background: Rectangle {
        color: root.backgroundColor
        border.width: root.borderColor.a > 0 ? 1 : 0
        border.color: root.borderColor
        radius: m3.radiusM
    }

    contentItem: RowLayout {
        spacing: compact ? m3.space8 : m3.space12

        Item {
            visible: root._showIcon
            Layout.alignment: Qt.AlignTop
            Layout.preferredWidth: 20
            Layout.preferredHeight: 20

            M3Icon {
                visible: root.tone !== 'progress'
                anchors.centerIn: parent
                size: 20
                source: root._t.icon !== '' ? Qt.resolvedUrl('../../../icons/m3/' + root._t.icon + '.png') : ''
                color: root.textColor
            }
            BusyIndicator {
                visible: root.tone === 'progress'
                running: visible
                anchors.centerIn: parent
                width: 28
                height: 28
                padding: 2
            }
        }

        M3Text {
            id: infotext
            Layout.fillWidth: true
            role: 'bodyMedium'
            color: root.textColor
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            verticalAlignment: Text.AlignTop
        }
    }
}
