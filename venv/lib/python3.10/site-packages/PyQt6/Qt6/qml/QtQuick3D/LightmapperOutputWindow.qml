// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Pane {
    id: root
    anchors.fill: parent

    property double totalProgress: 0
    property int totalTimeRemaining: -1
    property string stage : "Preparing..."

    function clearText() {
        textArea.clear();
    }

    function update(payload) {
        if ("message" in payload && typeof payload.message === "string" && payload.message) {
            textArea.insert(textArea.length, payload.message + "\n");
        }

        if ("totalProgress" in payload && typeof payload.totalProgress === "number") {
            root.totalProgress = payload.totalProgress;
        }

        if ("totalTimeRemaining" in payload && typeof payload.totalTimeRemaining === "number") {
            root.totalTimeRemaining = payload.totalTimeRemaining;
        }

        if ("stage" in payload && typeof payload.stage === "string") {
            root.stage = payload.stage;
        }
    }

    function formatDuration(milliseconds, showMilliseconds = true) {
        if (milliseconds < 0)
            return " Estimating..."
        const partSeconds = Math.floor(milliseconds / 1000) % 60;
        const partMinutes = Math.floor(milliseconds / 60000) % 60;
        const partHours = Math.floor(milliseconds / 3600000) % 60;

        if (partHours > 0) {
            return partHours + "h " + partMinutes + "m " + partSeconds + "s";
        }
        if (partMinutes > 0) {
            return partMinutes + "m " + partSeconds + "s";
        }
        if (partSeconds > 0) {
            return partSeconds + "s";
        }
        return "0s";
    }

    ColumnLayout {
        anchors.fill: parent

        RowLayout {
            Label {
                padding: 0
                text: root.stage
            }
            Item {
                Layout.fillWidth: true
            }
            Label {
                padding: 0
                text: (root.totalProgress * 100).toFixed(0) + "%"
            }
        }

        ProgressBar {
            Layout.fillWidth: true
            value: root.totalProgress
        }

        RowLayout {
            Label {
                padding: 0
                text: totalTimeRemaining > 0 ? "Remaining: " + root.formatDuration(root.totalTimeRemaining) : ""
            }
            Item {
                Layout.fillWidth: true
            }
        }

        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            ScrollView {
                width: parent.width
                height: parent.height
                id: scroll
                TextArea {
                    id: textArea
                    width: parent.width
                    height: parent.height
                    readOnly: true
                    placeholderText: qsTr("Qt Lightmapper")
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
            }
        }

        Button {
            objectName: "cancelButton"
            Layout.fillWidth: true
            text: "Cancel"
        }
    }
}
