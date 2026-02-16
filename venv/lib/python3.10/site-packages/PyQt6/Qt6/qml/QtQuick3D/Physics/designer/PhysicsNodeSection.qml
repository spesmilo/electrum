// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Physics Node")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Collision Shapes")
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 5
            }

            SecondColumnLayout {
                EditableListView {
                    backendValue: backendValues.collisionShapes
                    model: backendValues.collisionShapes.expressionAsList
                    Layout.fillWidth: true
                    typeFilter: "QtQuick3D.Physics.CollisionShape"

                    onAdd: function(value) { backendValues.collisionShapes.idListAdd(value) }
                    onRemove: function(idx) { backendValues.collisionShapes.idListRemove(idx) }
                    onReplace: function (idx, value) { backendValues.collisionShapes.idListReplace(idx, value) }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Receive Contact Reports")
                tooltip: qsTr("Determines whether this body will receive contact reports when colliding with other bodies.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.receiveContactReports.valueToString
                    backendValue: backendValues.receiveContactReports
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Send Contact Reports")
                tooltip: qsTr("Determines whether this body will send contact reports when colliding with other bodies.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.sendContactReports.valueToString
                    backendValue: backendValues.sendContactReports
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Receive Trigger Reports")
                tooltip: qsTr("Determines whether this body will receive reports when entering or leaving a trigger body.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.receiveTriggerReports.valueToString
                    backendValue: backendValues.receiveTriggerReports
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Send Trigger Reports")
                tooltip: qsTr("Determines whether this body will send contact reports when colliding with other bodies.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.sendTriggerReports.valueToString
                    backendValue: backendValues.sendTriggerReports
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
