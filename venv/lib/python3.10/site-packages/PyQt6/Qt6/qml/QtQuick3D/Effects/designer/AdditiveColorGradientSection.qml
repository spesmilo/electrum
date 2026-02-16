// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0

Section {
    caption: qsTr("Additive Color Gradient")
    width: parent.width

    SectionLayout {
        PropertyLabel { text: qsTr("Top Color") }

        ColorEditor {
            backendValue: backendValues.topColor
            supportGradient: false
            isVector3D: true
        }

        PropertyLabel { text: qsTr("Bottom Color") }

        ColorEditor {
            backendValue: backendValues.bottomColor
            supportGradient: false
            isVector3D: true
        }
    }
}
