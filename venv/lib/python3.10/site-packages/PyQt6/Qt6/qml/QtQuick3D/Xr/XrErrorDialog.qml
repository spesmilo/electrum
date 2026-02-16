// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick.Dialogs

Item {
    function run(title, message) {
        var w = win.createObject();
        w.messageTitle = title;
        w.messageText = message;
        w.run();
    }

    Component {
        id: win
        Window {
            property alias messageTitle: msg.title
            property alias messageText: msg.text
            function run() { msg.open() }
            visible: true
            visibility: Window.Maximized
            MessageDialog {
                id: msg
                buttons: MessageDialog.Ok
                onAccepted: Qt.quit()
                onRejected: Qt.quit()
            }
        }
    }
}
