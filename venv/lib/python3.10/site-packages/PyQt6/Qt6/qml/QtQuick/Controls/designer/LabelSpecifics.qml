// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import HelperWidgets
import QtQuick.Layouts

Column {
    width: parent.width

    StandardTextSection {
        width: parent.width
        showIsWrapping: true
        showFormatProperty: true
        showVerticalAlignment: true
    }

    Section {
        anchors.left: parent.left
        anchors.right: parent.right
        caption: qsTr("Text Color")

        ColorEditor {
            caption: qsTr("Text Color")
            backendValue: backendValues.color
            supportGradient: false
        }
    }

    Section {
        anchors.left: parent.left
        anchors.right: parent.right
        caption: qsTr("Style Color")

        ColorEditor {
            caption: qsTr("Style Color")
            backendValue: backendValues.styleColor
            supportGradient: false
        }
    }

    FontSection {
        width: parent.width
    }

    PaddingSection {
        width: parent.width
    }

    InsetSection {
        width: parent.width
    }
}
