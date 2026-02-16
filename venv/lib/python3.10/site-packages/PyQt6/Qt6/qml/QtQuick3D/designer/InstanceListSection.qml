// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0

Section {
    caption: qsTr("Instance List")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Instances")
            tooltip: qsTr("Sets the list of instance definitions. Modifying this list, or any of its elements, will cause the instance table to be updated.")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.instances
                model: backendValues.instances.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.InstanceListEntry"

                onAdd: function(value) { backendValues.instances.idListAdd(value) }
                onRemove: function(idx) { backendValues.instances.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.instances.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }
    }
}
