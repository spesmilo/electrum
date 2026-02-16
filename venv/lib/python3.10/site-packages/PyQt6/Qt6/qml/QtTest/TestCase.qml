// Copyright (C) 2016 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick 2.0
import QtQuick.Window 2.0 // used for qtest_verifyItem
import QtTest 1.2
import "testlogger.js" as TestLogger

/*!
    \qmltype TestCase
    \inqmlmodule QtTest
    \brief Represents a unit test case.
    \since 4.8
    \ingroup qtquicktest

    \section1 Introduction to QML Test Cases

    Test cases are written as JavaScript functions within a TestCase
    type:

    \code
    import QtQuick 2.0
    import QtTest 1.2

    TestCase {
        name: "MathTests"

        function test_math() {
            compare(2 + 2, 4, "2 + 2 = 4")
        }

        function test_fail() {
            compare(2 + 2, 5, "2 + 2 = 5")
        }
    }
    \endcode

    Functions whose names start with "test_" are treated as test cases
    to be executed.  The \l name property is used to prefix the functions
    in the output:

    \code
    ********* Start testing of MathTests *********
    Config: Using QTest library 4.7.2, Qt 4.7.2
    PASS   : MathTests::initTestCase()
    FAIL!  : MathTests::test_fail() 2 + 2 = 5
       Actual (): 4
       Expected (): 5
       Loc: [/home/.../tst_math.qml(12)]
    PASS   : MathTests::test_math()
    PASS   : MathTests::cleanupTestCase()
    Totals: 3 passed, 1 failed, 0 skipped
    ********* Finished testing of MathTests *********
    \endcode

    Because of the way JavaScript properties work, the order in which the
    test functions are found is unpredictable.  To assist with predictability,
    the test framework will sort the functions on ascending order of name.
    This can help when there are two tests that must be run in order.

    Multiple TestCase types can be supplied.  The test program will exit
    once they have all completed.  If a test case doesn't need to run
    (because a precondition has failed), then \l optional can be set to true.

    \section1 Data-driven Tests

    Table data can be provided to a test using a function name that ends
    with "_data". Alternatively, the \c init_data() function can be used
    to provide default test data for all test functions without a matching
    "_data" function in a TestCase type:


    \code
    import QtQuick 2.0
    import QtTest 1.2

    TestCase {
        name: "DataTests"

        function init_data() {
          return [
               {tag:"init_data_1", a:1, b:2, answer: 3},
               {tag:"init_data_2", a:2, b:4, answer: 6}
          ];
        }

        function test_table_data() {
            return [
                {tag: "2 + 2 = 4", a: 2, b: 2, answer: 4 },
                {tag: "2 + 6 = 8", a: 2, b: 6, answer: 8 },
            ]
        }

        function test_table(data) {
            //data comes from test_table_data
            compare(data.a + data.b, data.answer)
        }

        function test_default_table(data) {
            //data comes from init_data
            compare(data.a + data.b, data.answer)
        }
    }
    \endcode

    The test framework will iterate over all of the rows in the table
    and pass each row to the test function.  As shown, the columns can be
    extracted for use in the test.  The \c tag column is special - it is
    printed by the test framework when a row fails, to help the reader
    identify which case failed amongst a set of otherwise passing tests.

    \section1 Benchmarks

    Functions whose names start with "benchmark_" will be run multiple
    times with the Qt benchmark framework, with an average timing value
    reported for the runs.  This is equivalent to using the \c{QBENCHMARK}
    macro in the C++ version of QTestLib.

    \code
    TestCase {
        id: top
        name: "CreateBenchmark"

        function benchmark_create_component() {
            let component = Qt.createComponent("item.qml")
            let obj = component.createObject(top)
            obj.destroy()
            component.destroy()
        }
    }

    RESULT : CreateBenchmark::benchmark_create_component:
         0.23 msecs per iteration (total: 60, iterations: 256)
    PASS   : CreateBenchmark::benchmark_create_component()
    \endcode

    To get the effect of the \c{QBENCHMARK_ONCE} macro, prefix the test
    function name with "benchmark_once_".

    \section1 Simulating Keyboard and Mouse Events

    The keyPress(), keyRelease(), and keyClick() methods can be used
    to simulate keyboard events within unit tests.  The events are
    delivered to the currently focused QML item. You can pass either
    a Qt.Key enum value or a latin1 char (string of length one)

    \code
    Rectangle {
        width: 50; height: 50
        focus: true

        TestCase {
            name: "KeyClick"
            when: windowShown

            function test_key_click() {
                keyClick(Qt.Key_Left)
                keyClick("a")
                ...
            }
        }
    }
    \endcode

    The mousePress(), mouseRelease(), mouseClick(), mouseDoubleClickSequence()
    and mouseMove() methods can be used to simulate mouse events in a
    similar fashion.

    If your test creates other windows, it's possible that those windows
    become active, stealing the focus from the TestCase's window. To ensure
    that the TestCase's window is active, use the following code:

    \code
    testCase.Window.window.requestActivate()
    tryCompare(testCase.Window.window, "active", true)
    \endcode

    \b{Note:} keyboard and mouse events can only be delivered once the
    main window has been shown.  Attempts to deliver events before then
    will fail.  Use the \l when and windowShown properties to track
    when the main window has been shown.

    \section1 Managing Dynamically Created Test Objects

    A typical pattern with QML tests is to
    \l {Dynamic QML Object Creation from JavaScript}{dynamically create}
    an item and then destroy it at the end of the test function:

    \code
    TestCase {
        id: testCase
        name: "MyTest"
        when: windowShown

        function test_click() {
            let item = Qt.createQmlObject("import QtQuick 2.0; Item {}", testCase);
            verify(item);

            // Test item...

            item.destroy();
        }
    }
    \endcode

    The problem with this pattern is that any failures in the test function
    will cause the call to \c item.destroy() to be skipped, leaving the item
    hanging around in the scene until the test case has finished. This can
    result in interference with future tests; for example, by blocking input
    events or producing unrelated debug output that makes it difficult to
    follow the code's execution.

    By calling \l createTemporaryQmlObject() instead, the object is guaranteed
    to be destroyed at the end of the test function:

    \code
    TestCase {
        id: testCase
        name: "MyTest"
        when: windowShown

        function test_click() {
            let item = createTemporaryQmlObject("import QtQuick 2.0; Item {}", testCase);
            verify(item);

            // Test item...

            // Don't need to worry about destroying "item" here.
        }
    }
    \endcode

    For objects that are created via the \l {Component::}{createObject()} function
    of \l Component, the \l createTemporaryObject() function can be used.

    \sa {QtTest::SignalSpy}{SignalSpy}, {Qt Quick Test}

    \section1 Separating Tests from Application Logic

    In most cases, you would want to separate your tests from the application
    logic by splitting them into different projects and linking them.

    For example, you could have the following project structure:

    \badcode
    .
    | — CMakeLists.txt
    | — main.cpp
    | - main.qml
    | — MyModule
        | — MyButton.qml
        | — CMakeLists.txt
    | — tests
        | — tst_testqml.qml
        | — main.cpp
        | — setup.cpp
        | — setup.h
    \endcode

    Now, to test \c MyModule/MyButton.qml, create a library for
    \c MyModule in \c MyModule/CMakeLists.txt and link it to your
    test project, \c tests/UnitQMLTests/CMakeLists.txt:

    \if defined(onlinedocs)
        \tab {build-qt-app}{tab-cmake-add-library}{MyModule/CMakeLists.txt}{checked}
        \tab {build-qt-app}{tab-cmake-link-against-library}{tests/CMakeLists.txt}{}
        \tab {build-qt-app}{tab-tests_main}{tests/main.cpp}{}
        \tab {build-qt-app}{tab-tests-setup-cpp}{tests/setup.cpp}{}
        \tab
        {build-qt-app}{tab-tests-setup-h}{tests/setup.h}{}
        \tab {build-qt-app}{tab-project-cmake}{CMakeLists.txt}{}
        \tabcontent {tab-cmake-add-library}
    \else
        \section2 Add Library
    \endif
    \dots
    \snippet testApp/MyModule/CMakeLists.txt add library
    \dots
    \if defined(onlinedocs)
        \endtabcontent
        \tabcontent {tab-cmake-link-against-library}
    \else
        \section2 Link Against Library
    \endif
    \dots
    \snippet testApp/tests/CMakeLists.txt link against library
    \dots
    \if defined(onlinedocs)
        \endtabcontent
        \tabcontent {tab-tests_main}
    \else
        \section2 Test main.cpp
    \endif
    \snippet testApp/tests/main.cpp main
    \if defined(onlinedocs)
        \endtabcontent
        \tabcontent {tab-tests-setup-cpp}
    \else
        \section2 Test Setup C++
    \endif
    \snippet testApp/tests/setup.cpp setup
    \if defined(onlinedocs)
        \endtabcontent
        \tabcontent {tab-tests-setup-h}
    \else
        \section2 Test Setup Header
    \endif
    \snippet testApp/tests/setup.h setup
    \if defined(onlinedocs)
        \endtabcontent
        \tabcontent {tab-project-cmake}
    \else
        \section2 Project CMakeLists
    \endif
    \dots
    \snippet testApp/CMakeLists.txt project-cmake
    \dots
    \if defined(onlinedocs)
        \endtabcontent
    \endif


    Then, in \c tests/tst_testqml.qml, you can import
    \c MyModule/MyButton.qml:

    \if defined(onlinedocs)
        \tab {test-qml}{tab-qml-import}{tests/tst_testqml.qml}{checked}
        \tab {test-qml}{tab-qml-my-button}{MyModule/MyButton.qml}{}
        \tabcontent {tab-qml-import}
    \else
        \section2 Import QML
    \endif
    \snippet testApp/tests/tst_testqml.qml import
    \if defined(onlinedocs)
        \endtabcontent
        \tabcontent {tab-qml-my-button}
    \else
        \section2 Define QML Button
    \endif
    \snippet testApp/MyModule/MyButton.qml define
    \if defined(onlinedocs)
        \endtabcontent
    \endif
*/


Item {
    id: testCase
    visible: false
    TestUtil {
        id:util
    }

    /*!
        \qmlproperty string TestCase::name

        This property defines the name of the test case for result reporting.
        The default value is an empty string.

        \code
        TestCase {
            name: "ButtonTests"
            ...
        }
        \endcode
    */
    property string name

    /*!
        \qmlproperty bool TestCase::when

        This property should be set to true when the application wants
        the test cases to run.  The default value is true.  In the following
        example, a test is run when the user presses the mouse button:

        \code
        Rectangle {
            id: foo
            width: 640; height: 480
            color: "cyan"

            MouseArea {
                id: area
                anchors.fill: parent
            }

            property bool bar: true

            TestCase {
                name: "ItemTests"
                when: area.pressed
                id: test1

                function test_bar() {
                    verify(bar)
                }
            }
        }
        \endcode

        The test application will exit once all \l TestCase types
        have been triggered and have run.  The \l optional property can
        be used to exclude a \l TestCase type.

        \sa optional, completed
    */
    property bool when: true

    /*!
        \qmlproperty bool TestCase::completed

        This property will be set to true once the test case has completed
        execution.  Test cases are only executed once.  The initial value
        is false.

        \sa running, when
    */
    property bool completed: false

    /*!
        \qmlproperty bool TestCase::running

        This property will be set to true while the test case is running.
        The initial value is false, and the value will become false again
        once the test case completes.

        \sa completed, when
    */
    property bool running: false

    /*!
        \qmlproperty bool TestCase::optional

        Multiple \l TestCase types can be supplied in a test application.
        The application will exit once they have all completed.  If a test case
        does not need to run (because a precondition has failed), then this
        property can be set to true.  The default value is false.

        \code
        TestCase {
            when: false
            optional: true
            function test_not_run() {
                verify(false)
            }
        }
        \endcode

        \sa when, completed
    */
    property bool optional: false

    /*!
        \qmlproperty bool TestCase::windowShown

        This property will be set to true after the QML viewing window has
        been displayed.  Normally test cases run as soon as the test application
        is loaded and before a window is displayed.  If the test case involves
        visual types and behaviors, then it may need to be delayed until
        after the window is shown.

        \code
        Button {
            id: button
            onClicked: text = "Clicked"
            TestCase {
                name: "ClickTest"
                when: windowShown
                function test_click() {
                    button.clicked();
                    compare(button.text, "Clicked");
                }
            }
        }
        \endcode
    */
    property bool windowShown: QTestRootObject.windowShown

    // Internal private state.  Identifiers prefixed with qtest are reserved.
    /*! \internal */
    property bool qtest_prevWhen: true
    /*! \internal */
    property int qtest_testId: -1
    /*! \internal */
    property bool qtest_componentCompleted : false
    /*! \internal */
    property var qtest_testCaseResult
    /*! \internal */
    property var qtest_results: qtest_results_normal
    /*! \internal */
    TestResult { id: qtest_results_normal }
    /*! \internal */
    property var qtest_events: qtest_events_normal
    TestEvent { id: qtest_events_normal }
    /*! \internal */
    property var qtest_temporaryObjects: []

    /*!
        \qmlmethod TestCase::fail(message = "")

        Fails the current test case, with the optional \a message.
        Similar to \c{QFAIL(message)} in C++.
    */
    function fail(msg) {
        if (msg === undefined)
            msg = "";
        qtest_results.fail(msg, util.callerFile(), util.callerLine())
        throw new Error("QtQuickTest::fail")
    }

    /*! \internal */
    function qtest_fail(msg, frame) {
        if (msg === undefined)
            msg = "";
        qtest_results.fail(msg, util.callerFile(frame), util.callerLine(frame))
        throw new Error("QtQuickTest::fail")
    }

    /*!
        \qmlmethod TestCase::verify(condition, message = "")

        Fails the current test case if \a condition is false, and
        displays the optional \a message.  Similar to \c{QVERIFY(condition)}
        or \c{QVERIFY2(condition, message)} in C++.
    */
    function verify(cond, msg, ...args) {
        if (args.length > 0)
            qtest_fail("More than two arguments given to verify(). Did you mean tryVerify() or tryCompare()?", 1)

        if (msg === undefined)
            msg = "";
        if (!qtest_results.verify(cond, msg, util.callerFile(), util.callerLine()))
            throw new Error("QtQuickTest::fail")
    }

    /*!
        \since 5.8
        \qmlmethod TestCase::tryVerify(function, timeout = 5000, message = "")

        Fails the current test case if \a function does not evaluate to
        \c true before the specified \a timeout (in milliseconds) has elapsed.
        The function is evaluated multiple times until the timeout is
        reached. An optional \a message is displayed upon failure.

        This function is intended for testing applications where a condition
        changes based on asynchronous events. Use verify() for testing
        synchronous condition changes, and tryCompare() for testing
        asynchronous property changes.

        For example, in the code below, it's not possible to use tryCompare(),
        because the \c currentItem property might be \c null for a short period
        of time:

        \code
        tryCompare(listView.currentItem, "text", "Hello");
        \endcode

        Instead, we can use tryVerify() to first check that \c currentItem
        isn't \c null, and then use a regular compare afterwards:

        \code
        tryVerify(function(){ return listView.currentItem })
        compare(listView.currentItem.text, "Hello")
        \endcode

        \sa verify(), compare(), tryCompare(), SignalSpy::wait()
    */
    function tryVerify(expressionFunction, timeout, msg) {
        if (!expressionFunction || !(expressionFunction instanceof Function)) {
            qtest_results.fail("First argument must be a function", util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }

        if (timeout && typeof(timeout) !== "number") {
            qtest_results.fail("timeout argument must be a number", util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }

        if (msg && typeof(msg) !== "string") {
            qtest_results.fail("message argument must be a string", util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }

        if (!timeout)
            timeout = 5000

        if (msg === undefined)
            msg = "function returned false"

        if (!expressionFunction())
            wait(0)

        let i = 0
        while (i < timeout && !expressionFunction()) {
            wait(50)
            i += 50
        }

        if (!qtest_results.verify(expressionFunction(), msg, util.callerFile(), util.callerLine()))
            throw new Error("QtQuickTest::fail")
    }

    /*!
        \since 5.13
        \qmlmethod bool TestCase::isPolishScheduled(object itemOrWindow)

        If \a itemOrWindow is an \l Item, this function returns \c true if
        \l {QQuickItem::}{updatePolish()} has not been called on it since the
        last call to \l {QQuickItem::}{polish()}, otherwise returns \c false.

        Since Qt 6.5, if \a itemOrWindow is a \l Window, this function returns
        \c true if \l {QQuickItem::}{updatePolish()} has not been called on any
        item it manages since the last call to \l {QQuickItem::}{polish()} on
        those items, otherwise returns \c false.

        When assigning values to properties in QML, any layouting the item
        must do as a result of the assignment might not take effect immediately,
        but can instead be postponed until the item is polished. For these cases,
        you can use this function to ensure that items have been polished
        before the execution of the test continues. For example:

        \code
            verify(isPolishScheduled(item))
            verify(waitForItemPolished(item))
        \endcode

        Without the call to \c isPolishScheduled() above, the
        call to \c waitForItemPolished() might see that no polish
        was scheduled and therefore pass instantly, assuming that
        the item had already been polished. This function
        makes it obvious why an item wasn't polished and allows tests to
        fail early under such circumstances.

        \sa waitForPolish(), QQuickItem::polish(), QQuickItem::updatePolish()
    */
    function isPolishScheduled(itemOrWindow) {
        if (!itemOrWindow || typeof itemOrWindow !== "object") {
            qtest_results.fail("Argument must be a valid Item or Window; actual type is " + typeof itemOrWindow,
                util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }

        return qtest_results.isPolishScheduled(itemOrWindow)
    }

    /*!
        \since 5.13
        \deprecated [6.5] Use \l waitForPolish() instead.
        \qmlmethod bool waitForItemPolished(object item, int timeout = 5000)

        Waits for \a timeout milliseconds or until
        \l {QQuickItem::}{updatePolish()} has been called on \a item.

        Returns \c true if \c updatePolish() was called on \a item within
        \a timeout milliseconds, otherwise returns \c false.

        \sa isPolishScheduled(), QQuickItem::polish(), QQuickItem::updatePolish()
    */
    function waitForItemPolished(item, timeout) {
        return waitForPolish(item, timeout)
    }

    /*!
        \since 6.5
        \qmlmethod bool waitForPolish(object windowOrItem, int timeout = 5000)

        If \a windowOrItem is an Item, this functions waits for \a timeout
        milliseconds or until \c isPolishScheduled(windowOrItem) returns \c false.
        Returns \c true if \c isPolishScheduled(windowOrItem) returns \c false within
        \a timeout milliseconds, otherwise returns \c false.

        If \c windowOrItem is a Window, this functions waits for \c timeout
        milliseconds or until \c isPolishScheduled() returns \c false for
        all items managed by the window. Returns \c true if
        \c isPolishScheduled() returns \c false for all items within
        \a timeout milliseconds, otherwise returns \c false.

        \sa isPolishScheduled(), QQuickItem::polish(), QQuickItem::updatePolish()
    */
    function waitForPolish(windowOrItem, timeout) {
        if (!windowOrItem || typeof windowOrItem !== "object") {
            qtest_results.fail("First argument must be a valid Item or Window; actual type is " + typeof windowOrItem,
                util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }

        if (timeout !== undefined && typeof(timeout) !== "number") {
            qtest_results.fail("Second argument must be a number; actual type is " + typeof timeout,
                util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }

        if (!timeout)
            timeout = 5000

        return qtest_results.waitForPolish(windowOrItem, timeout)
    }

    /*!
        \since 5.9
        \qmlmethod object TestCase::createTemporaryQmlObject(string qml, object parent, string filePath)

        This function dynamically creates a QML object from the given \a qml
        string with the specified \a parent. The returned object will be
        destroyed (if it was not already) after \l cleanup() has finished
        executing, meaning that objects created with this function are
        guaranteed to be destroyed after each test, regardless of whether or
        not the tests fail.

        If there was an error while creating the object, \c null will be
        returned.

        If \a filePath is specified, it will be used for error reporting for
        the created object.

        This function calls
        \l {QtQml::Qt::createQmlObject()}{Qt.createQmlObject()} internally.

        \sa {Managing Dynamically Created Test Objects}
    */
    function createTemporaryQmlObject(qml, parent, filePath) {
        if (typeof qml !== "string") {
            qtest_results.fail("First argument must be a string of QML; actual type is " + typeof qml,
                util.callerFile(), util.callerLine());
            throw new Error("QtQuickTest::fail");
        }

        if (!parent || typeof parent !== "object") {
            qtest_results.fail("Second argument must be a valid parent object; actual type is " + typeof parent,
                util.callerFile(), util.callerLine());
            throw new Error("QtQuickTest::fail");
        }

        if (filePath !== undefined && typeof filePath !== "string") {
            qtest_results.fail("Third argument must be a file path string; actual type is " + typeof filePath,
                util.callerFile(), util.callerLine());
            throw new Error("QtQuickTest::fail");
        }

        let object = Qt.createQmlObject(qml, parent, filePath);
        qtest_temporaryObjects.push(object);
        return object;
    }

    /*!
        \since 5.9
        \qmlmethod object TestCase::createTemporaryObject(Component component, object parent, object properties)

        This function dynamically creates a QML object from the given
        \a component with the specified optional \a parent and \a properties.
        The returned object will be destroyed (if it was not already) after
        \l cleanup() has finished executing, meaning that objects created with
        this function are guaranteed to be destroyed after each test,
        regardless of whether or not the tests fail.

        If there was an error while creating the object, \c null will be
        returned.

        This function calls
        \l {QtQml::Component::createObject()}{component.createObject()}
        internally.

        \sa {Managing Dynamically Created Test Objects}
    */
    function createTemporaryObject(component, parent, properties) {
        if (typeof component !== "object") {
            qtest_results.fail("First argument must be a Component; actual type is " + typeof component,
                util.callerFile(), util.callerLine());
            throw new Error("QtQuickTest::fail");
        }

        if (properties && typeof properties !== "object") {
            qtest_results.fail("Third argument must be an object; actual type is " + typeof properties,
                util.callerFile(), util.callerLine());
            throw new Error("QtQuickTest::fail");
        }

        if (parent === undefined)
            parent = null

        let object = component.createObject(parent, properties ? properties : ({}));
        qtest_temporaryObjects.push(object);
        return object;
    }

    /*!
        \internal

        Destroys all temporary objects that still exist.
    */
    function qtest_destroyTemporaryObjects() {
        for (let i = 0; i < qtest_temporaryObjects.length; ++i) {
            let temporaryObject = qtest_temporaryObjects[i];
            // ### the typeof check can be removed when QTBUG-57749 is fixed
            if (temporaryObject && typeof temporaryObject.destroy === "function")
                temporaryObject.destroy();
        }
        qtest_temporaryObjects = [];
    }

    /*! \internal */
    // Determine what is o.
    // Discussions and reference: http://philrathe.com/articles/equiv
    // Test suites: http://philrathe.com/tests/equiv
    // Author: Philippe Rathé <prathe@gmail.com>
    function qtest_typeof(o) {
        if (typeof o === "undefined") {
            return "undefined";

        // consider: typeof null === object
        } else if (o === null) {
            return "null";

        } else if (o.constructor === String) {
            return "string";

        } else if (o.constructor === Boolean) {
            return "boolean";

        } else if (o.constructor === Number) {

            if (isNaN(o)) {
                return "nan";
            } else {
                return "number";
            }
        // consider: typeof [] === object
        } else if (o instanceof Array) {
            return "array";

        // consider: typeof new Date() === object
        } else if (o instanceof Date) {
            return "date";

        // consider: /./ instanceof Object;
        //           /./ instanceof RegExp;
        //          typeof /./ === "function"; // => false in IE and Opera,
        //                                          true in FF and Safari
        } else if (o instanceof RegExp) {
            return "regexp";

        } else if (typeof o === "object") {
            if ("mapFromItem" in o && "mapToItem" in o) {
                return "declarativeitem";  // @todo improve detection of declarative items
            } else if ("x" in o && "y" in o && "z" in o) {
                return "vector3d"; // Qt 3D vector
            }
            return "object";
        } else if (o instanceof Function) {
            return "function";
        } else {
            return undefined;
        }
    }

    /*! \internal */
    // Test for equality
    // Large parts contain sources from QUnit or http://philrathe.com
    // Discussions and reference: http://philrathe.com/articles/equiv
    // Test suites: http://philrathe.com/tests/equiv
    // Author: Philippe Rathé <prathe@gmail.com>
    function qtest_compareInternal(act, exp) {
        let success = false;
        if (act === exp) {
            success = true; // catch the most you can
        } else if (act === null || exp === null || typeof act === "undefined" || typeof exp === "undefined") {
            success = false; // don't lose time with error prone cases
        } else {
            let typeExp = qtest_typeof(exp), typeAct = qtest_typeof(act)
            if (typeExp !== typeAct) {
                // allow object vs string comparison (e.g. for colors)
                // else break on different types
                if ((typeExp === "string" && (typeAct === "object") || typeAct === "declarativeitem")
                 || ((typeExp === "object" || typeExp === "declarativeitem") && typeAct === "string")) {
                    success = (act == exp) // @disable-check M126
                }
            } else if (typeExp === "string" || typeExp === "boolean" ||
                       typeExp === "null" || typeExp === "undefined") {
                if (exp instanceof act.constructor || act instanceof exp.constructor) {
                    // to catch short annotaion VS 'new' annotation of act declaration
                    // e.g. let i = 1;
                    //      let j = new Number(1);
                    success = (act == exp) // @disable-check M126
                } else {
                    success = (act === exp)
                }
            } else if (typeExp === "nan") {
                success = isNaN(act);
            } else if (typeExp === "number") {
                // Use act fuzzy compare if the two values are floats
                if (Math.abs(act - exp) <= 0.00001) {
                    success = true
                }
            } else if (typeExp === "array") {
                success = qtest_compareInternalArrays(act, exp)
            } else if (typeExp === "object") {
                success = qtest_compareInternalObjects(act, exp)
            } else if (typeExp === "declarativeitem") {
                success = qtest_compareInternalObjects(act, exp) // @todo improve comparison of declarative items
            } else if (typeExp === "vector3d") {
                success = (Math.abs(act.x - exp.x) <= 0.00001 &&
                           Math.abs(act.y - exp.y) <= 0.00001 &&
                           Math.abs(act.z - exp.z) <= 0.00001)
            } else if (typeExp === "date") {
                success = (act.valueOf() === exp.valueOf())
            } else if (typeExp === "regexp") {
                success = (act.source === exp.source && // the regex itself
                           act.global === exp.global && // and its modifers (gmi) ...
                           act.ignoreCase === exp.ignoreCase &&
                           act.multiline === exp.multiline)
            }
        }
        return success
    }

    /*! \internal */
    function qtest_compareInternalObjects(act, exp) {
        let i;
        let eq = true; // unless we can proove it
        let aProperties = [], bProperties = []; // collection of strings

        // comparing constructors is more strict than using instanceof
        if (act.constructor !== exp.constructor) {
            return false;
        }

        for (i in act) { // be strict: don't ensures hasOwnProperty and go deep
            aProperties.push(i); // collect act's properties
            if (!qtest_compareInternal(act[i], exp[i])) {
                eq = false;
                break;
            }
        }

        for (i in exp) {
            bProperties.push(i); // collect exp's properties
        }

        if (aProperties.length === 0 && bProperties.length === 0) { // at least a special case for QUrl
            return eq && (JSON.stringify(act) === JSON.stringify(exp));
        }

        // Ensures identical properties name
        return eq && qtest_compareInternal(aProperties.sort(), bProperties.sort());

    }

    /*! \internal */
    function qtest_compareInternalArrays(actual, expected) {
        if (actual.length !== expected.length) {
            return false
        }

        for (let i = 0, len = actual.length; i < len; i++) {
            if (!qtest_compareInternal(actual[i], expected[i])) {
                return false
            }
        }

        return true
    }

    /*!
        \qmlmethod TestCase::compare(actual, expected, message = "")

        Fails the current test case if \a actual is not the same as
        \a expected, and displays the optional \a message.  Similar
        to \c{QCOMPARE(actual, expected)} in C++.

        \sa tryCompare(), fuzzyCompare
    */
    function compare(actual, expected, msg) {
        let act = qtest_results.stringify(actual)
        let exp = qtest_results.stringify(expected)

        let success = qtest_compareInternal(actual, expected)
        if (msg === undefined) {
            if (success)
                msg = "COMPARE()"
            else
                msg = "Compared values are not the same"
        }
        if (!qtest_results.compare(success, msg, act, exp, util.callerFile(), util.callerLine())) {
            throw new Error("QtQuickTest::fail")
        }
    }

    /*!
        \qmlmethod TestCase::fuzzyCompare(actual, expected, delta, message = "")

        Fails the current test case if the difference betwen \a actual and \a expected
        is greater than \a delta, and displays the optional \a message.  Similar
        to \c{qFuzzyCompare(actual, expected)} in C++ but with a required \a delta value.

        This function can also be used for color comparisons if both the \a actual and
        \a expected values can be converted into color values. If any of the differences
        for RGBA channel values are greater than \a delta, the test fails.

        \sa tryCompare(), compare()
    */
    function fuzzyCompare(actual, expected, delta, msg) {
        if (delta === undefined)
            qtest_fail("A delta value is required for fuzzyCompare", 2)

        let success = qtest_results.fuzzyCompare(actual, expected, delta)
        if (msg === undefined) {
            if (success)
                msg = "FUZZYCOMPARE()"
            else
                msg = "Compared values are not the same with delta(" + delta + ")"
        }

        if (!qtest_results.compare(success, msg, actual, expected, util.callerFile(), util.callerLine())) {
            throw new Error("QtQuickTest::fail")
        }
    }

    /*!
        \qmlmethod object TestCase::grabImage(item)

        Returns a snapshot image object of the given \a item.

        The returned image object has the following properties:
        \list
        \li width Returns the width of the underlying image (since 5.10)
        \li height Returns the height of the underlying image (since 5.10)
        \li size Returns the size of the underlying image (since 5.10)
        \endlist

        Additionally, the returned image object has the following methods:
        \list
        \li \c {red(x, y)} Returns the red channel value of the pixel at \e x, \e y position
        \li \c {green(x, y)} Returns the green channel value of the pixel at \e x, \e y position
        \li \c {blue(x, y)} Returns the blue channel value of the pixel at \e x, \e y position
        \li \c {alpha(x, y)} Returns the alpha channel value of the pixel at \e x, \e y position
        \li \c {pixel(x, y)} Returns the color value of the pixel at \e x, \e y position
        \li \c {equals(image)} Returns \c true if this image is identical to \e image -
            see \l QImage::operator== (since 5.6)

        For example:

        \code
        let image = grabImage(rect);
        compare(image.red(10, 10), 255);
        compare(image.pixel(20, 20), Qt.rgba(255, 0, 0, 255));

        rect.width += 10;
        let newImage = grabImage(rect);
        verify(!newImage.equals(image));
        \endcode

        \li \c {save(path)} Saves the image to the given \e path. If the image cannot
        be saved, an exception will be thrown. (since 5.10)

        This can be useful to perform postmortem analysis on failing tests, for
        example:

        \code
        let image = grabImage(rect);
        try {
            compare(image.width, 100);
        } catch (ex) {
            image.save("debug.png");
            throw ex;
        }
        \endcode

        \endlist
    */
    function grabImage(item) {
        return qtest_results.grabImage(item);
    }

    /*!
        \since 5.4
        \qmlmethod QtObject TestCase::findChild(parent, objectName)

        Returns the first child of \a parent with \a objectName, or \c null if
        no such item exists. Both visual and non-visual children are searched
        recursively, with visual children being searched first.

        \code
        compare(findChild(item, "childObject"), expectedChildObject);
        \endcode
    */
    function findChild(parent, objectName) {
        // First, search the visual item hierarchy.
        let child = qtest_findVisualChild(parent, objectName);
        if (child)
            return child;

        // If it's not a visual child, it might be a QObject child.
        return qtest_results.findChild(parent, objectName);
    }

    /*! \internal */
    function qtest_findVisualChild(parent, objectName) {
        if (!parent || parent.children === undefined)
            return null;

        for (let i = 0; i < parent.children.length; ++i) {
            // Is this direct child of ours the child we're after?
            let child = parent.children[i];
            if (child.objectName === objectName)
                return child;
        }

        for (let i = 0; i < parent.children.length; ++i) {
            // Try the direct child's children.
            let child = qtest_findVisualChild(parent.children[i], objectName);
            if (child)
                return child;
        }
        return null;
    }

    /*!
        \qmlmethod TestCase::tryCompare(obj, property, expected, timeout = 5000, message = "")

        Fails the current test case if the specified \a property on \a obj
        is not the same as \a expected, and displays the optional \a message.
        The test will be retried multiple times until the
        \a timeout (in milliseconds) is reached.

        This function is intended for testing applications where a property
        changes value based on asynchronous events.  Use compare() for testing
        synchronous property changes.

        \code
        tryCompare(img, "status", BorderImage.Ready)
        compare(img.width, 120)
        compare(img.height, 120)
        compare(img.horizontalTileMode, BorderImage.Stretch)
        compare(img.verticalTileMode, BorderImage.Stretch)
        \endcode

        SignalSpy::wait() provides an alternative method to wait for a
        signal to be emitted.

        \sa compare(), SignalSpy::wait()
    */
    function tryCompare(obj, prop, ...args) {
        if (typeof(prop) !== "string" && typeof(prop) !== "number") {
            qtest_results.fail("A property name as string or index is required for tryCompare",
                        util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }
        if (args.length === 0) {
            qtest_results.fail("A value is required for tryCompare",
                        util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }
        let [value, timeout, msg] = args
        if (timeout !== undefined && typeof(timeout) !== "number") {
            qtest_results.fail("timeout should be a number",
                        util.callerFile(), util.callerLine())
            throw new Error("QtQuickTest::fail")
        }
        if (!timeout)
            timeout = 5000
        if (msg === undefined)
            msg = "property " + prop
        if (!qtest_compareInternal(obj[prop], value))
            wait(0)
        let i = 0
        while (i < timeout && !qtest_compareInternal(obj[prop], value)) {
            wait(50)
            i += 50
        }
        let actual = obj[prop]
        let act = qtest_results.stringify(actual)
        let exp = qtest_results.stringify(value)
        let success = qtest_compareInternal(actual, value)
        if (!qtest_results.compare(success, msg, act, exp, util.callerFile(), util.callerLine()))
            throw new Error("QtQuickTest::fail")
    }

    /*!
        \qmlmethod TestCase::skip(message = "")

        Skips the current test case and prints the optional \a message.
        If this is a data-driven test, then only the current row is skipped.
        Similar to \c{QSKIP(message)} in C++.
    */
    function skip(msg) {
        if (msg === undefined)
            msg = ""
        qtest_results.skip(msg, util.callerFile(), util.callerLine())
        throw new Error("QtQuickTest::skip")
    }

    /*!
        \qmlmethod TestCase::expectFail(tag, message)

        In a data-driven test, marks the row associated with \a tag as
        expected to fail.  When the fail occurs, display the \a message,
        abort the test, and mark the test as passing.  Similar to
        \c{QEXPECT_FAIL(tag, message, Abort)} in C++.

        If the test is not data-driven, then \a tag must be set to
        an empty string.

        \sa expectFailContinue()
    */
    function expectFail(tag, msg) {
        if (tag === undefined) {
            warn("tag argument missing from expectFail()")
            tag = ""
        }
        if (msg === undefined) {
            warn("message argument missing from expectFail()")
            msg = ""
        }
        if (!qtest_results.expectFail(tag, msg, util.callerFile(), util.callerLine()))
            throw new Error("QtQuickTest::expectFail")
    }

    /*!
        \qmlmethod TestCase::expectFailContinue(tag, message)

        In a data-driven test, marks the row associated with \a tag as
        expected to fail.  When the fail occurs, display the \a message,
        and then continue the test.  Similar to
        \c{QEXPECT_FAIL(tag, message, Continue)} in C++.

        If the test is not data-driven, then \a tag must be set to
        an empty string.

        \sa expectFail()
    */
    function expectFailContinue(tag, msg) {
        if (tag === undefined) {
            warn("tag argument missing from expectFailContinue()")
            tag = ""
        }
        if (msg === undefined) {
            warn("message argument missing from expectFailContinue()")
            msg = ""
        }
        if (!qtest_results.expectFailContinue(tag, msg, util.callerFile(), util.callerLine()))
            throw new Error("QtQuickTest::expectFail")
    }

    /*!
        \qmlmethod TestCase::warn(message)

        Prints \a message as a warning message.  Similar to
        \c{qWarning(message)} in C++.

        \sa ignoreWarning()
    */
    function warn(msg) {
        if (msg === undefined)
            msg = ""
        qtest_results.warn(msg, util.callerFile(), util.callerLine());
    }

    /*!
        \qmlmethod TestCase::ignoreWarning(message)

        Marks \a message as an ignored warning message.  When it occurs,
        the warning will not be printed and the test passes.  If the message
        does not occur, then the test will fail.  Similar to
        \c{QTest::ignoreMessage(QtWarningMsg, message)} in C++.

        Since Qt 5.12, \a message can be either a string, or a regular
        expression providing a pattern of messages to ignore.

        For example, the following snippet will ignore a string warning message:
        \qml
        ignoreWarning("Something sort of bad happened")
        \endqml

        And the following snippet will ignore a regular expression matching a
        number of possible warning messages:
        \qml
        ignoreWarning(new RegExp("[0-9]+ bad things happened"))
        \endqml

        \note Despite being a JavaScript RegExp object, it will not be
        interpreted as such; instead, the pattern will be passed to
        \l QRegularExpression.

        \sa warn()
    */
    function ignoreWarning(msg) {
        if (msg === undefined)
            msg = ""
        qtest_results.ignoreWarning(msg)
    }

    /*!
        \qmlmethod TestCase::failOnWarning(message)
        \since 6.3

        Appends a test failure to the test log for each warning that matches
        \a message. The test function will continue execution when a failure
        is added.

        \a message can be either a string, or a regular expression providing a
        pattern of messages. In the latter case, for each warning encountered,
        the first pattern that matches will cause a failure, and the remaining
        patterns will be ignored.

        All patterns are cleared at the end of each test function.

        For example, the following snippet will fail a test if a warning with
        the text "Something bad happened" is produced:
        \qml
        failOnWarning("Something bad happened")
        \endqml

        The following snippet will fail a test if any warning matching the
        given pattern is encountered:
        \qml
        failOnWarning(/[0-9]+ bad things happened/)
        \endqml

        To fail every test that triggers a given warning, pass a suitable regular
        expression to this function in \l init():

        \qml
        function init() {
            failOnWarning(/.?/)
        }
        \endqml

        \note Despite being a JavaScript RegExp object, it will not be
        interpreted as such; instead, the pattern will be passed to \l
        QRegularExpression.

        \note ignoreMessage() takes precedence over this function, so any
        warnings that match a pattern given to both \c ignoreMessage() and \c
        failOnWarning() will be ignored.

        \sa QTest::failOnWarning(), warn()
    */
    function failOnWarning(msg) {
        if (msg === undefined)
            msg = ""
        qtest_results.failOnWarning(msg)
    }

    /*!
        \qmlmethod TestCase::wait(ms)

        Waits for \a ms milliseconds while processing Qt events.

        \note This methods uses a precise timer to do the actual waiting. The
              event you are waiting for may not. In particular, any animations as
              well as the \l{Timer} QML type can use either precise or coarse
              timers, depending on various factors. For a coarse timer you have
              to expect a drift of around 5% in relation to the precise timer used
              by TestCase::wait(). Qt cannot give hard guarantees on the drift,
              though, because the operating system usually doesn't offer hard
              guarantees on timers.

        \sa sleep(), waitForRendering(), Qt::TimerType
    */
    function wait(ms) {
        qtest_results.wait(ms)
    }

    /*!
        \qmlmethod TestCase::waitForRendering(item, timeout = 5000)

        Waits for \a timeout milliseconds or until the \a item is rendered by the renderer.
        Returns true if \c item is rendered in \a timeout milliseconds, otherwise returns false.
        The default \a timeout value is 5000.

        \sa sleep(), wait()
    */
    function waitForRendering(item, timeout) {
        if (timeout === undefined)
            timeout = 5000
        if (!qtest_verifyItem(item, "waitForRendering"))
            return
        return qtest_results.waitForRendering(item, timeout)
    }

    /*!
        \qmlmethod TestCase::sleep(ms)

        Sleeps for \a ms milliseconds without processing Qt events.

        \sa wait(), waitForRendering()
    */
    function sleep(ms) {
        qtest_results.sleep(ms)
    }

    /*!
        \qmlmethod TestCase::keyPress(key, modifiers = Qt.NoModifier, delay = -1)

        Simulates pressing a \a key with optional \a modifiers on the currently
        focused item.  If \a delay is larger than 0, the test will wait for
        \a delay milliseconds.

        The event will be sent to the TestCase window or, in case of multiple windows,
        to the current active window. See \l QGuiApplication::focusWindow() for more details.

        \b{Note:} At some point you should release the key using keyRelease().

        \sa keyRelease(), keyClick()
    */
    function keyPress(key, modifiers, delay) {
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (typeof(key) === "string" && key.length === 1) {
            if (!qtest_events.keyPressChar(key, modifiers, delay))
                qtest_fail("window not shown", 2)
        } else {
            if (!qtest_events.keyPress(key, modifiers, delay))
                qtest_fail("window not shown", 2)
        }
    }

    /*!
        \qmlmethod TestCase::keyRelease(key, modifiers = Qt.NoModifier, delay = -1)

        Simulates releasing a \a key with optional \a modifiers on the currently
        focused item.  If \a delay is larger than 0, the test will wait for
        \a delay milliseconds.

        The event will be sent to the TestCase window or, in case of multiple windows,
        to the current active window. See \l QGuiApplication::focusWindow() for more details.

        \sa keyPress(), keyClick()
    */
    function keyRelease(key, modifiers, delay) {
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (typeof(key) === "string" && key.length === 1) {
            if (!qtest_events.keyReleaseChar(key, modifiers, delay))
                qtest_fail("window not shown", 2)
        } else {
            if (!qtest_events.keyRelease(key, modifiers, delay))
                qtest_fail("window not shown", 2)
        }
    }

    /*!
        \qmlmethod TestCase::keyClick(key, modifiers = Qt.NoModifier, delay = -1)

        Simulates clicking of \a key with optional \a modifiers on the currently
        focused item.  If \a delay is larger than 0, the test will wait for
        \a delay milliseconds.

        The event will be sent to the TestCase window or, in case of multiple windows,
        to the current active window. See \l QGuiApplication::focusWindow() for more details.

        \sa keyPress(), keyRelease()
    */
    function keyClick(key, modifiers, delay) {
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (typeof(key) === "string" && key.length === 1) {
            if (!qtest_events.keyClickChar(key, modifiers, delay))
                qtest_fail("window not shown", 2)
        } else {
            if (!qtest_events.keyClick(key, modifiers, delay))
                qtest_fail("window not shown", 2)
        }
    }

    /*!
        \since 5.10
        \qmlmethod TestCase::keySequence(keySequence)

        Simulates typing of \a keySequence. The key sequence can be set
        to one of the \l{QKeySequence::StandardKey}{standard keyboard shortcuts}, or
        it can be described with a string containing a sequence of up to four key
        presses.

        Each event shall be sent to the TestCase window or, in case of multiple windows,
        to the current active window. See \l QGuiApplication::focusWindow() for more details.

        \sa keyPress(), keyRelease(), {GNU Emacs Style Key Sequences},
        {QtQuick::Shortcut::sequence}{Shortcut.sequence}
    */
    function keySequence(keySequence) {
        if (!qtest_events.keySequence(keySequence))
            qtest_fail("window not shown", 2)
    }

    /*!
        \qmlmethod TestCase::mousePress(item, x = item.width / 2, y = item.height / 2, button = Qt.LeftButton, modifiers = Qt.NoModifier, delay = -1)

        Simulates pressing a mouse \a button with optional \a modifiers
        on an \a item.  The position is defined by \a x and \a y.
        If \a x or \a y are not defined the position will be the center of \a item.
        If \a delay is specified, the test will wait for the specified amount of
        milliseconds before the press.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        \sa mouseRelease(), mouseClick(), mouseDoubleClickSequence(), mouseMove(), mouseDrag(), mouseWheel()
    */
    function mousePress(item, x, y, button, modifiers, delay) {
        if (!qtest_verifyItem(item, "mousePress"))
            return

        if (button === undefined)
            button = Qt.LeftButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (x === undefined)
            x = item.width / 2
        if (y === undefined)
            y = item.height / 2
        if (!qtest_events.mousePress(item, x, y, button, modifiers, delay))
            qtest_fail("window not shown", 2)
    }

    /*!
        \qmlmethod TestCase::mouseRelease(item, x = item.width / 2, y = item.height / 2, button = Qt.LeftButton, modifiers = Qt.NoModifier, delay = -1)

        Simulates releasing a mouse \a button with optional \a modifiers
        on an \a item.  The position of the release is defined by \a x and \a y.
        If \a x or \a y are not defined the position will be the center of \a item.
        If \a delay is specified, the test will wait for the specified amount of
        milliseconds before releasing the button.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        \sa mousePress(), mouseClick(), mouseDoubleClickSequence(), mouseMove(), mouseDrag(), mouseWheel()
    */
    function mouseRelease(item, x, y, button, modifiers, delay) {
        if (!qtest_verifyItem(item, "mouseRelease"))
            return

        if (button === undefined)
            button = Qt.LeftButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (x === undefined)
            x = item.width / 2
        if (y === undefined)
            y = item.height / 2
        if (!qtest_events.mouseRelease(item, x, y, button, modifiers, delay))
            qtest_fail("window not shown", 2)
    }

    /*!
        \qmlmethod TestCase::mouseDrag(item, x, y, dx, dy, button = Qt.LeftButton, modifiers = Qt.NoModifier, delay = -1)

        Simulates dragging the mouse on an \a item with \a button pressed and optional \a modifiers
        The initial drag position is defined by \a x and \a y,
        and drag distance is defined by \a dx and \a dy. If \a delay is specified,
        the test will wait for the specified amount of milliseconds before releasing the button.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        \sa mousePress(), mouseClick(), mouseDoubleClickSequence(), mouseMove(), mouseRelease(), mouseWheel()
    */
    function mouseDrag(item, x, y, dx, dy, button, modifiers, delay) {
        if (!qtest_verifyItem(item, "mouseDrag"))
            return

        if (item.x === undefined || item.y === undefined)
            return
        if (button === undefined)
            button = Qt.LeftButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        let moveDelay = Math.max(1, delay === -1 ? qtest_events.defaultMouseDelay : delay)

        // Divide dx and dy to have intermediate mouseMove while dragging
        // Fractions of dx/dy need be superior to the dragThreshold
        // to make the drag works though
        let intermediateDx = Math.round(dx/3)
        if (Math.abs(intermediateDx) < (util.dragThreshold + 1))
            intermediateDx = 0
        let intermediateDy = Math.round(dy/3)
        if (Math.abs(intermediateDy) < (util.dragThreshold + 1))
            intermediateDy = 0

        mousePress(item, x, y, button, modifiers, delay)

        // Trigger dragging by dragging past the drag threshold, but making sure to only drag
        // along a certain axis if a distance greater than zero was given for that axis.
        let dragTriggerXDistance = dx > 0 ? (util.dragThreshold + 1) : 0
        let dragTriggerYDistance = dy > 0 ? (util.dragThreshold + 1) : 0
        mouseMove(item, x + dragTriggerXDistance, y + dragTriggerYDistance, moveDelay, button, modifiers)
        if (intermediateDx !== 0 || intermediateDy !== 0) {
            mouseMove(item, x + intermediateDx, y + intermediateDy, moveDelay, button, modifiers)
            mouseMove(item, x + 2*intermediateDx, y + 2*intermediateDy, moveDelay, button, modifiers)
        }
        mouseMove(item, x + dx, y + dy, moveDelay, button, modifiers)
        mouseRelease(item, x + dx, y + dy, button, modifiers, delay)
    }

    /*!
        \qmlmethod TestCase::mouseClick(item, x = item.width / 2, y = item.height / 2, button = Qt.LeftButton, modifiers = Qt.NoModifier, delay = -1)

        Simulates clicking a mouse \a button with optional \a modifiers
        on an \a item.  The position of the click is defined by \a x and \a y.
        If \a x and \a y are not defined the position will be the center of \a item.
        If \a delay is specified, the test will wait for the specified amount of
        milliseconds before pressing and before releasing the button.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        \sa mousePress(), mouseRelease(), mouseDoubleClickSequence(), mouseMove(), mouseDrag(), mouseWheel()
    */
    function mouseClick(item, x, y, button, modifiers, delay) {
        if (!qtest_verifyItem(item, "mouseClick"))
            return

        if (button === undefined)
            button = Qt.LeftButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (x === undefined)
            x = item.width / 2
        if (y === undefined)
            y = item.height / 2
        if (!qtest_events.mouseClick(item, x, y, button, modifiers, delay))
            qtest_fail("window not shown", 2)
    }

    /*!
        \qmlmethod TestCase::mouseDoubleClickSequence(item, x = item.width / 2, y = item.height / 2, button = Qt.LeftButton, modifiers = Qt.NoModifier, delay = -1)

        Simulates the full sequence of events generated by double-clicking a mouse
        \a button with optional \a modifiers on an \a item.

        This method reproduces the sequence of mouse events generated when a user makes
        a double click: Press-Release-Press-DoubleClick-Release.

        The position of the click is defined by \a x and \a y.
        If \a x and \a y are not defined the position will be the center of \a item.
        If \a delay is specified, the test will wait for the specified amount of
        milliseconds before pressing and before releasing the button.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        This QML method was introduced in Qt 5.5.

        \sa mousePress(), mouseRelease(), mouseClick(), mouseMove(), mouseDrag(), mouseWheel()
    */
    function mouseDoubleClickSequence(item, x, y, button, modifiers, delay) {
        if (!qtest_verifyItem(item, "mouseDoubleClickSequence"))
            return

        if (button === undefined)
            button = Qt.LeftButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (delay === undefined)
            delay = -1
        if (x === undefined)
            x = item.width / 2
        if (y === undefined)
            y = item.height / 2
        if (!qtest_events.mouseDoubleClickSequence(item, x, y, button, modifiers, delay))
            qtest_fail("window not shown", 2)
    }

    /*!
        \qmlmethod TestCase::mouseMove(item, x = item.width / 2, y = item.height / 2, delay = -1, buttons = Qt.NoButton)

        Moves the mouse pointer to the position given by \a x and \a y within
        \a item, while holding \a buttons if given. Since Qt 6.0, if \a x and
        \a y are not defined, the position will be the center of \a item.

        If a \a delay (in milliseconds) is given, the test will wait before
        moving the mouse pointer.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        \sa mousePress(), mouseRelease(), mouseClick(), mouseDoubleClickSequence(), mouseDrag(), mouseWheel()
    */
    function mouseMove(item, x, y, delay, buttons, modifiers) {
        if (!qtest_verifyItem(item, "mouseMove"))
            return

        if (delay === undefined)
            delay = -1
        if (buttons === undefined)
            buttons = Qt.NoButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifiers
        if (x === undefined)
            x = item.width / 2
        if (y === undefined)
            y = item.height / 2
        if (!qtest_events.mouseMove(item, x, y, delay, buttons, modifiers))
            qtest_fail("window not shown", 2)
    }

    /*!
        \qmlmethod TestCase::mouseWheel(item, x, y, xDelta, yDelta, button = Qt.LeftButton, modifiers = Qt.NoModifier, delay = -1)

        Simulates rotating the mouse wheel on an \a item with \a button pressed and optional \a modifiers.
        The position of the wheel event is defined by \a x and \a y.
        If \a delay is specified, the test will wait for the specified amount of milliseconds before releasing the button.

        The position given by \a x and \a y is transformed from the co-ordinate
        system of \a item into window co-ordinates and then delivered.
        If \a item is obscured by another item, or a child of \a item occupies
        that position, then the event will be delivered to the other item instead.

        The \a xDelta and \a yDelta contain the wheel rotation distance in eighths of a degree. see \l QWheelEvent::angleDelta() for more details.

        \sa mousePress(), mouseClick(), mouseDoubleClickSequence(), mouseMove(), mouseRelease(), mouseDrag(), QWheelEvent::angleDelta()
    */
    function mouseWheel(item, x, y, xDelta, yDelta, buttons, modifiers, delay) {
        if (!qtest_verifyItem(item, "mouseWheel"))
            return

        if (delay === undefined)
            delay = -1
        if (buttons === undefined)
            buttons = Qt.NoButton
        if (modifiers === undefined)
            modifiers = Qt.NoModifier
        if (xDelta === undefined)
            xDelta = 0
        if (yDelta === undefined)
            yDelta = 0
        if (!qtest_events.mouseWheel(item, x, y, buttons, modifiers, xDelta, yDelta, delay))
            qtest_fail("window not shown", 2)
   }

    /*!
        \qmlmethod TouchEventSequence TestCase::touchEvent(object item)

        \since 5.9

        Begins a sequence of touch events through a simulated touchscreen (QPointingDevice).
        Events are delivered to the window containing \a item.

        The returned object is used to enumerate events to be delivered through a single
        QTouchEvent. Touches are delivered to the window containing the TestCase unless
        otherwise specified.

        \code
        Rectangle {
            width: 640; height: 480

            MultiPointTouchArea {
                id: area
                anchors.fill: parent

                property bool touched: false

                onPressed: touched = true
            }

            TestCase {
                name: "ItemTests"
                when: windowShown
                id: test1

                function test_touch() {
                    let touch = touchEvent(area);
                    touch.press(0, area, 10, 10);
                    touch.commit();
                    verify(area.touched);
                }
            }
        }
        \endcode

        \sa TouchEventSequence::press(), TouchEventSequence::move(), TouchEventSequence::release(), TouchEventSequence::stationary(), TouchEventSequence::commit(), QInputDevice::DeviceType
    */

    function touchEvent(item) {
        if (!qtest_verifyItem(item, "touchEvent"))
            return

        return {
            _defaultItem: item,
            _sequence: qtest_events.touchEvent(item),

            press: function (id, target, x, y) {
                if (!target)
                    target = this._defaultItem;
                if (id === undefined)
                    qtest_fail("No id given to TouchEventSequence::press", 1);
                if (x === undefined)
                    x = target.width / 2;
                if (y === undefined)
                    y = target.height / 2;
                this._sequence.press(id, target, x, y);
                return this;
            },

            move: function (id, target, x, y) {
                if (!target)
                    target = this._defaultItem;
                if (id === undefined)
                    qtest_fail("No id given to TouchEventSequence::move", 1);
                if (x === undefined)
                    x = target.width / 2;
                if (y === undefined)
                    y = target.height / 2;
                this._sequence.move(id, target, x, y);
                return this;
            },

            stationary: function (id) {
                if (id === undefined)
                    qtest_fail("No id given to TouchEventSequence::stationary", 1);
                this._sequence.stationary(id);
                return this;
            },

            release: function (id, target, x, y) {
                if (!target)
                    target = this._defaultItem;
                if (id === undefined)
                    qtest_fail("No id given to TouchEventSequence::release", 1);
                if (x === undefined)
                    x = target.width / 2;
                if (y === undefined)
                    y = target.height / 2;
                this._sequence.release(id, target, x, y);
                return this;
            },

            commit: function () {
                 this._sequence.commit();
                 return this;
            }
        };
    }

    // Functions that can be overridden in subclasses for init/cleanup duties.
    /*!
        \qmlmethod TestCase::initTestCase()

        This function is called before any other test functions in the
        \l TestCase type.  The default implementation does nothing.
        The application can provide its own implementation to perform
        test case initialization.

        \sa cleanupTestCase(), init()
    */
    function initTestCase() {}

    /*!
        \qmlmethod TestCase::cleanupTestCase()

        This function is called after all other test functions in the
        \l TestCase type have completed.  The default implementation
        does nothing.  The application can provide its own implementation
        to perform test case cleanup.

        \sa initTestCase(), cleanup()
    */
    function cleanupTestCase() {}

    /*!
        \qmlmethod TestCase::init()

        This function is called before each test function that is
        executed in the \l TestCase type.  The default implementation
        does nothing.  The application can provide its own implementation
        to perform initialization before each test function.

        \sa cleanup(), initTestCase()
    */
    function init() {}

    /*!
        \qmlmethod TestCase::cleanup()

        This function is called after each test function that is
        executed in the \l TestCase type.  The default implementation
        does nothing.  The application can provide its own implementation
        to perform cleanup after each test function.

        \sa init(), cleanupTestCase()
    */
    function cleanup() {}

    /*! \internal */
    function qtest_verifyItem(item, method) {
        try {
            if (!(item instanceof Item) &&
                !(item instanceof Window)) {
                // it's a QObject, but not a type
                qtest_fail("TypeError: %1 requires an Item or Window type".arg(method), 2);
                return false;
            }
        } catch (e) { // it's not a QObject
            qtest_fail("TypeError: %1 requires an Item or Window type".arg(method), 3);
            return false;
        }

        return true;
    }

    /*! \internal */
    function qtest_runInternal(prop, arg) {
        try {
            qtest_testCaseResult = testCase[prop](arg)
        } catch (e) {
            qtest_testCaseResult = []
            if (e.message.indexOf("QtQuickTest::") !== 0) {
                // Test threw an unrecognized exception - fail.
                qtest_results.fail("Uncaught exception: " + e.message,
                             e.fileName, e.lineNumber)
            }
        }
        return !qtest_results.failed
    }

    /*! \internal */
    function qtest_runFunction(prop, arg) {
        qtest_runInternal("init")
        if (!qtest_results.skipped) {
            qtest_runInternal(prop, arg)
            qtest_results.finishTestData()
            qtest_runInternal("cleanup")
            qtest_destroyTemporaryObjects()

            // wait(0) will call processEvents() so objects marked for deletion
            // in the test function will be deleted.
            wait(0)

            qtest_results.finishTestDataCleanup()
        }
    }

    /*! \internal */
    function qtest_runBenchmarkFunction(prop, arg) {
        qtest_results.startMeasurement()
        do {
            qtest_results.beginDataRun()
            do {
                // Run the initialization function.
                qtest_runInternal("init")
                if (qtest_results.skipped)
                    break

                // Execute the benchmark function.
                if (prop.indexOf("benchmark_once_") !== 0)
                    qtest_results.startBenchmark(TestResult.RepeatUntilValidMeasurement, qtest_results.dataTag)
                else
                    qtest_results.startBenchmark(TestResult.RunOnce, qtest_results.dataTag)
                while (!qtest_results.isBenchmarkDone()) {
                    let success = qtest_runInternal(prop, arg)
                    qtest_results.finishTestData()
                    if (!success)
                        break
                    qtest_results.nextBenchmark()
                }
                qtest_results.stopBenchmark()

                // Run the cleanup function.
                qtest_runInternal("cleanup")
                qtest_results.finishTestDataCleanup()
                // wait(0) will call processEvents() so objects marked for deletion
                // in the test function will be deleted.
                wait(0)
            } while (!qtest_results.measurementAccepted())
            qtest_results.endDataRun()
        } while (qtest_results.needsMoreMeasurements())
    }

    /*! \internal */
    function qtest_run() {
        if (!when || completed || running || !qtest_componentCompleted)
            return;

        if (!TestLogger.log_can_start_test(qtest_testId)) {
            console.error("Interleaved test execution detected. This shouldn't happen")
            return;
        }

        if (TestLogger.log_start_test(qtest_testId)) {
            qtest_results.reset()
            qtest_results.testCaseName = name
            qtest_results.startLogging()
        } else {
            qtest_results.testCaseName = name
        }
        running = true

        // Check the run list to see if this class is mentioned.
        let checkNames = false
        let testsToRun = {} // explicitly provided function names to run and their tags for data-driven tests

        if (qtest_results.functionsToRun.length > 0) {
            checkNames = true
            let found = false

            if (name.length > 0) {
                for (let index in qtest_results.functionsToRun) {
                    let caseFuncName = qtest_results.functionsToRun[index]
                    if (caseFuncName.indexOf(name + "::") !== 0)
                        continue

                    found = true
                    let funcName = caseFuncName.substring(name.length + 2)

                    if (!(funcName in testsToRun))
                        testsToRun[funcName] = []

                    let tagName = qtest_results.tagsToRun[index]
                    if (tagName.length > 0) // empty tags mean run all rows
                        testsToRun[funcName].push(tagName)
                }
            }
            if (!found) {
                completed = true
                if (!TestLogger.log_complete_test(qtest_testId)) {
                    qtest_results.stopLogging()
                    Qt.quit()
                }
                qtest_results.testCaseName = ""
                return
            }
        }

        // Run the initTestCase function.
        qtest_results.functionName = "initTestCase"
        let runTests = true
        if (!qtest_runInternal("initTestCase"))
            runTests = false
        qtest_results.finishTestData()
        qtest_results.finishTestDataCleanup()
        qtest_results.finishTestFunction()

        // Run the test methods.
        let testList = []
        if (runTests) {
            for (let prop in testCase) {
                if (prop.indexOf("test_") !== 0 && prop.indexOf("benchmark_") !== 0)
                    continue
                let tail = prop.lastIndexOf("_data");
                if (tail !== -1 && tail === (prop.length - 5))
                    continue
                testList.push(prop)
            }
            testList.sort()
        }

        for (let index in testList) {
            let prop = testList[index]

            if (checkNames && !(prop in testsToRun))
                continue

            let datafunc = prop + "_data"
            let isBenchmark = (prop.indexOf("benchmark_") === 0)
            qtest_results.functionName = prop

            if (!(datafunc in testCase))
                datafunc = "init_data";

            if (datafunc in testCase) {
                if (qtest_runInternal(datafunc)) {
                    let table = qtest_testCaseResult
                    let haveData = false

                    let checkTags = (checkNames && testsToRun[prop].length > 0)

                    qtest_results.initTestTable()
                    for (let index in table) {
                        haveData = true
                        let row = table[index]
                        if (!row.tag)
                            row.tag = "row " + index    // Must have something
                        if (checkTags) {
                            let tags = testsToRun[prop]
                            let tagIdx = tags.indexOf(row.tag)
                            if (tagIdx < 0)
                                continue
                            tags.splice(tagIdx, 1)
                        }
                        qtest_results.dataTag = row.tag
                        if (isBenchmark)
                            qtest_runBenchmarkFunction(prop, row)
                        else
                            qtest_runFunction(prop, row)
                        qtest_results.dataTag = ""
                        qtest_results.skipped = false
                    }
                    if (!haveData) {
                        if (datafunc === "init_data")
                           qtest_runFunction(prop, null, isBenchmark)
                        else
                           qtest_results.warn("no data supplied for " + prop + "() by " + datafunc + "()"
                                            , util.callerFile(), util.callerLine());
                    }
                    qtest_results.clearTestTable()
                }
            } else if (isBenchmark) {
                qtest_runBenchmarkFunction(prop, null, isBenchmark)
            } else {
                qtest_runFunction(prop, null, isBenchmark)
            }
            qtest_results.finishTestFunction()
            qtest_results.skipped = false

            if (checkNames && testsToRun[prop].length <= 0)
                delete testsToRun[prop]
        }

        // Run the cleanupTestCase function.
        qtest_results.skipped = false
        qtest_results.functionName = "cleanupTestCase"
        qtest_runInternal("cleanupTestCase")

        // Complain about missing functions that we were supposed to run.
        if (checkNames) {
            let missingTests = []
            for (let func in testsToRun) {
                let caseFuncName = name + '::' + func
                let tags = testsToRun[func]
                if (tags.length <= 0)
                    missingTests.push(caseFuncName)
                else
                    for (let i in tags)
                        missingTests.push(caseFuncName + ':' + tags[i])
            }
            missingTests.sort()
            if (missingTests.length > 0)
                qtest_results.fail("Could not find test functions: " + missingTests, "", 0)
        }

        // Clean up and exit.
        running = false
        completed = true
        qtest_results.finishTestData()
        qtest_results.finishTestDataCleanup()
        qtest_results.finishTestFunction()
        qtest_results.functionName = ""

        // Stop if there are no more tests to be run.
        if (!TestLogger.log_complete_test(qtest_testId)) {
            qtest_results.stopLogging()
            Qt.quit()
        }
        qtest_results.testCaseName = ""
    }

    onWhenChanged: {
        if (when !== qtest_prevWhen) {
            qtest_prevWhen = when
            if (when)
                TestSchedule.testCases.push(testCase)
        }
    }

    onOptionalChanged: {
        if (!completed) {
            if (optional)
                TestLogger.log_optional_test(qtest_testId)
            else
                TestLogger.log_mandatory_test(qtest_testId)
        }
    }

    Component.onCompleted: {
        QTestRootObject.hasTestCase = true;
        qtest_componentCompleted = true;
        qtest_testId = TestLogger.log_register_test(name)
        if (optional)
            TestLogger.log_optional_test(qtest_testId)
        qtest_prevWhen = when
        if (when)
            TestSchedule.testCases.push(testCase)
    }
}
