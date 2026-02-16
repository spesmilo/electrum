// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Runtime Loader")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Source")
                tooltip: qsTr("Sets the URL of the 3D asset to import at runtime.")
            }

            SecondColumnLayout {
                UrlChooser {
                    backendValue: backendValues.source
                    filter: "*.*"
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Instancing")
                tooltip: qsTr("If this property is set, the imported model will not be rendered normally. Instead, a number of instances of the model will be rendered, as defined by the instance table.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Instancing"
                    backendValue: backendValues.instancing
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
