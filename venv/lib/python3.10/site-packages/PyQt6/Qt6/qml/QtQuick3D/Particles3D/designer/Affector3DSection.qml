// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Particle Affector")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("System")
            tooltip: qsTr("Sets the ParticleSystem3D for the affector. If system is direct parent of the affector, this property does not need to be defined.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Particles3D.ParticleSystem3D"
                backendValue: backendValues.system
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Particles")
            tooltip: qsTr("Sets which logical particles will be affected. When empty, all particles in the system are affected.")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.particles
                model: backendValues.particles.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Particles3D.Particle3D"

                onAdd: function(value) { backendValues.particles.idListAdd(value) }
                onRemove: function(idx) { backendValues.particles.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.particles.idListReplace(idx, value) }
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Enabled")
            tooltip: qsTr("If set to false, this affector will not alter any particles. Usually this is used to conditionally turn an affector on or off.")
        }

        SecondColumnLayout {
            CheckBox {
                id: enabledCheckBox
                text: backendValues.enabled.valueToString
                backendValue: backendValues.enabled
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
