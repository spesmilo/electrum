// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

pragma Singleton
import QtQml

Timer {
    property list<QtObject> testCases
    property QtObject currentTest: null

    running: testCases.length > 0 && !currentTest
    interval: 1
    repeat: true

    onTriggered: {
        if (currentTest) {
            console.error("Interleaved test execution detected. This shouldn't happen")
            return;
        }

        try {
            currentTest = testCases.shift()
            currentTest.qtest_run()
        } finally {
            currentTest = null
        }
    }

}
