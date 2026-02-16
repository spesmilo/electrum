// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Particle Emitter")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("System")
                tooltip: qsTr("Sets the ParticleSystem3D for the emitter. If system is direct parent of the emitter, this property does not need to be defined.")
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
                text: qsTr("Emit Bursts")
                tooltip: qsTr("Sets a list of EmitBurst3D elements to declaratively define bursts.")
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: 5
            }

            SecondColumnLayout {
                EditableListView {
                    backendValue: backendValues.emitBursts
                    model: backendValues.emitBursts.expressionAsList
                    Layout.fillWidth: true
                    typeFilter: "QtQuick3D.Particles3D.EmitBurst3D"

                    onAdd: function(value) { backendValues.emitBursts.idListAdd(value) }
                    onRemove: function(idx) { backendValues.emitBursts.idListRemove(idx) }
                    onReplace: function (idx, value) { backendValues.emitBursts.idListReplace(idx, value) }
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Velocity")
                tooltip: qsTr("Sets a starting velocity for emitted particles.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QQuick3DParticleDirection"
                    backendValue: backendValues.velocity
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Particle")
                tooltip: qsTr("Sets the logical particle which this emitter emits.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Particles3D.Particle3D"
                    backendValue: backendValues.particle
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Enabled")
                tooltip: qsTr("If enabled is set to false, this emitter will not emit any particles.")
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

            PropertyLabel {
                text: qsTr("Shape")
                tooltip: qsTr("Sets optional shape for the emitting area.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QQuick3DParticleAbstractShape"
                    backendValue: backendValues.shape
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Emit Rate")
                tooltip: qsTr("Sets the constant emitting rate in particles per second.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.emitRate
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Life Span")
                tooltip: qsTr("Sets the lifespan of a single particle in milliseconds.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 999999
                    decimals: 0
                    backendValue: backendValues.lifeSpan
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Life Span Variation")
                tooltip: qsTr("Sets the lifespan variation of a single particle in milliseconds.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 0
                    backendValue: backendValues.lifeSpanVariation
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Particle Scale")
                tooltip: qsTr("Sets the scale multiplier of the particles at the beginning")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.particleScale
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Particle End Scale")
                tooltip: qsTr("Sets the scale multiplier of the particles at the end of particle lifeSpan.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.particleEndScale
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Scale Variation")
                tooltip: qsTr("Sets the scale variation of the particles.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.particleScaleVariation
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("End Scale Variation")
                tooltip: qsTr("Sets the scale variation of the particles in the end.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.particleEndScaleVariation
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Depth Bias")
                tooltip: qsTr("Sets the depth bias of the emitter. Depth bias is added to the object distance from camera when sorting objects.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -999999
                    maximumValue: 999999
                    decimals: 2
                    backendValue: backendValues.depthBias
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        width: parent.width
        caption: qsTr("Particle Rotation")

        ColumnLayout {
            spacing: StudioTheme.Values.transform3DSectionSpacing

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Rotation")
                    tooltip: qsTr("Sets the rotation of the particles in the beginning. Rotation is defined as degrees in euler angles.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotation_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotation_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotation_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Variation")
                    tooltip: qsTr("Sets the rotation variation of the particles in the beginning. Rotation variation is defined as degrees in euler angles.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVariation_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVariation_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVariation_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Velocity")
                    tooltip: qsTr("Sets the rotation velocity of the particles in the beginning. Rotation velocity is defined as degrees per second in euler angles.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVelocity_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVelocity_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVelocity_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Velocity Variation")
                    tooltip: qsTr("Sets the rotation velocity variation of the particles. Rotation velocity variation is defined as degrees per second in euler angles.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVelocityVariation_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVelocityVariation_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.particleRotationVelocityVariation_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }
        }
    }
}
