import QtQuick as QtQuick

import "."

// This "TextEdit" type shadows the built-in QML "TextEdit" type,
// for .qml files that import this directory (e.g. 'import "controls"' or 'import "."')

QtQuick.TextEdit {
    textFormat: TextEdit.PlainText
}
