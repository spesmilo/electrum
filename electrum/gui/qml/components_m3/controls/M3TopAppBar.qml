import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 top app bar, used as the window header for every page (Material 3 or classic).
// Left: back arrow when `showBack`, otherwise the optional `leading` item.
// Right: the optional `actions` items and the overflow button (signal overflowClicked).
ToolBar {
    id: root

    property string title
    property string subtitle
    property bool showBack: false
    property bool showOverflow: true
    property Component leading
    property list<Item> actions
    property alias overflowButton: overflowButton

    signal backClicked()
    signal overflowClicked()

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.primary: m3.primary
    Material.background: m3.surface
    Material.foreground: m3.surfaceOn

    // Add top margin for status bar on Android when using edge-to-edge
    topPadding: app.statusBarHeight
    leftPadding: 4
    rightPadding: 4
    // the bar is 64 high below the status bar; the implicit height of the row (48) would make it
    // only max(64, 48 + statusBarHeight) high
    contentHeight: m3.topAppBarHeight

    background: Rectangle {
        implicitHeight: m3.topAppBarHeight
        color: m3.surface
    }

    RowLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        height: m3.topAppBarHeight
        spacing: 0

        M3IconButton {
            visible: root.showBack
            tooltip: qsTr('Back')
            icon.source: Qt.resolvedUrl('../../../icons/m3/arrow_back.png')
            icon.color: m3.surfaceOn
            onClicked: root.backClicked()
        }

        Loader {
            visible: !root.showBack && root.leading
            active: !root.showBack && root.leading
            sourceComponent: root.leading
            Layout.leftMargin: 8
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.leftMargin: root.showBack ? 4 : 12
            spacing: 0

            // with action buttons a title too long for titleLarge takes titleMedium and, still too long,
            // wraps into two lines (a page without actions keeps one titleLarge line, as before)
            M3Text {
                id: titleText
                readonly property bool _compact: actionsRow.implicitWidth > 0
                    && titleMetrics.advanceWidth > width
                Layout.fillWidth: true
                role: _compact ? 'titleMedium' : 'titleLarge'
                text: root.title
                elide: Text.ElideRight
                wrapMode: _compact && !root.subtitle ? Text.WordWrap : Text.NoWrap
                maximumLineCount: _compact && !root.subtitle ? 2 : 1
                lineHeight: _compact ? 20 : _style.line
            }
            TextMetrics {
                id: titleMetrics
                font.family: titleText.font.family
                font.pixelSize: m3.textStyle('titleLarge').size
                font.weight: m3.textStyle('titleLarge').weight
                font.letterSpacing: m3.textStyle('titleLarge').tracking
                text: root.title
            }
            M3Text {
                Layout.fillWidth: true
                visible: root.subtitle
                role: 'bodySmall'
                color: m3.surfaceVariantOn
                text: root.subtitle
                elide: Text.ElideRight
            }
        }

        Row {
            id: actionsRow
            Layout.alignment: Qt.AlignVCenter
            children: root.actions
        }

        M3IconButton {
            id: overflowButton
            visible: root.showOverflow
            tooltip: qsTr('More options')
            icon.source: Qt.resolvedUrl('../../../icons/m3/more_vert.png')
            onClicked: root.overflowClicked()
        }
    }
}
