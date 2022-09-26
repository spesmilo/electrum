import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3

Dialog {
    id: abstractdialog

    property bool allowClose: true

    onOpenedChanged: {
        if (opened) {
            app.activeDialogs.push(abstractdialog)
        } else {
            app.activeDialogs.pop()
        }
    }
}
