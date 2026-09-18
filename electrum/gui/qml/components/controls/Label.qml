import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Controls.Material

import "."

// This "Label" type shadows the built-in QML "Label" type,
// for .qml files that import this directory (e.g. 'import "controls"' or 'import "."')

Controls.Label {
    textFormat: Text.PlainText
}
