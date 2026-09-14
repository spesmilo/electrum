import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Controls.Material

import "."

// This "TextArea" type shadows the built-in QML "TextArea" type,
// for .qml files that import this directory (e.g. 'import "controls"' or 'import "."')

Controls.TextArea {
    textFormat: TextEdit.PlainText
}
