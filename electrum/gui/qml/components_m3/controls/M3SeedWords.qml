import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// The words of a seed as a numbered grid (DESIGN-M2-onboarding.md 3.3, owner fork R-O4 a): a card on
// surfaceContainerLow, radius 16, cells "n. word" (number labelMedium surfaceVariantOn, word FixedFont titleMedium).
// Shows what the read-only SeedTextArea of the classic controls/SeedTextArea.qml @ e6df7e1c8 showed: `text` is the
// seed, words separated by spaces. No copy action (as the classic: "Do not store it electronically").
// Columns by the width of the card: 2 below 400, 3 below 560, else 4. The words run left to right, row by row,
// so the first words keep their place when the screen is unfolded (2 -> 4 columns) while the seed is written down.
M3Card {
    id: root

    property string text
    readonly property var words: text.trim() === '' ? [] : text.trim().split(/\s+/)
    readonly property int columns: width < 400 ? 2 : width < 560 ? 3 : 4

    padding: m3.space16
    // the content is the grid (a page may add more children, e.g. a busy indicator)
    contentHeight: grid.implicitHeight

    GridLayout {
        id: grid
        width: parent.width
        columns: root.columns
        columnSpacing: m3.space16
        rowSpacing: m3.space8

        Repeater {
            model: root.words

            RowLayout {
                required property int index
                required property string modelData
                Layout.fillWidth: true
                Layout.preferredWidth: 1  // equal columns
                spacing: m3.space8

                M3Text {
                    Layout.preferredWidth: numberMetrics.advanceWidth('00.')
                    role: 'labelMedium'
                    color: m3.surfaceVariantOn
                    horizontalAlignment: Text.AlignRight
                    text: (index + 1) + '.'
                }
                M3Text {
                    Layout.fillWidth: true
                    role: 'titleMedium'
                    font.family: FixedFont
                    elide: Text.ElideRight
                    text: modelData
                }
            }
        }
    }

    FontMetrics {
        id: numberMetrics
        font.pixelSize: m3.textStyle('labelMedium').size
    }
}
