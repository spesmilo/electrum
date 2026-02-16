// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Instance Repeater")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Instancing Table")
            tooltip: qsTr("Sets the instance table used by the repeater.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Instancing"
                backendValue: backendValues.instancingTable
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
