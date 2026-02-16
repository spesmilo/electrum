// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Window
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.ApplicationWindow {
    id: window

    background: NinePatchImage {
        width: window.width
        height: window.height

        source: Imagine.url + "applicationwindow-background"
        NinePatchImageSelector on source {
            states: [
                {"active": window.active}
            ]
        }
    }
}
