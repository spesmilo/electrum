// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Effect")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Passes")
            tooltip: qsTr("Sets the render passes of the effect.")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.passes
                model: backendValues.passes.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Pass"

                onAdd: function(value) { backendValues.passes.idListAdd(value) }
                onRemove: function(idx) { backendValues.passes.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.passes.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }
    }
}
