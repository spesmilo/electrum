import QtQuick

import org.electrum 1.0

// Material 3 theme: color roles (light and dark), type scale, shapes and spacing.
// One instance lives on the application window as `m3` (see components_m3/main.qml);
// Material 3 files reach it through the context chain, as the classic files reach `constants`.
QtObject {
    id: theme

    // 'system', 'light' or 'dark'; changes apply immediately
    readonly property string mode: Config.m3Theme

    readonly property bool dark: mode === 'dark'
        || (mode !== 'light' && Application.styleHints.colorScheme === Qt.ColorScheme.Dark)

    // A manual choice is also written to the platform: on Android this switches the light/dark
    // status bar and navigation bar icons. In 'system' mode the override is cleared, so that
    // colorScheme follows the system again.
    // Android without edge-to-edge (below Android 15): the system draws the bars itself, dark, not the
    // page under them, so the light theme does not ask for dark icons (they would be dark on dark): it
    // writes Dark, the icons stay light. `dark` is not affected: in 'light' mode it is false whatever
    // colorScheme says.
    function applyColorScheme() {
        if (mode === 'light' && _systemDrawsBars())
            Application.styleHints.colorScheme = Qt.ColorScheme.Dark
        else if (mode === 'light')
            Application.styleHints.colorScheme = Qt.ColorScheme.Light
        else if (mode === 'dark')
            Application.styleHints.colorScheme = Qt.ColorScheme.Dark
        else
            Application.styleHints.colorScheme = Qt.ColorScheme.Unknown
    }
    function _systemDrawsBars() {
        return typeof AppController !== 'undefined' && AppController !== null
            && AppController.isAndroid() && !AppController.enforcesEdgeToEdge()
    }
    onModeChanged: applyColorScheme()
    Component.onCompleted: applyColorScheme()

    // Naming: the M3 role "on<Role>" (content color on <Role>) is called "<role>On" here, because a
    // QML property name of the form on<Uppercase> is read as a signal handler (m3.onPrimary would be
    // undefined). So onPrimary -> primaryOn, onSurfaceVariant -> surfaceVariantOn,
    // inverseOnSurface -> inverseSurfaceOn.
    // --- color roles: scheme for source color #36618E (light from the mockup, dark from the same
    // tonal palettes); tertiary replaced by the amber 'Lightning' role, plus a 'success' role ---
    readonly property color primary: dark ? '#A0CAFD' : '#36618E'
    readonly property color primaryOn: dark ? '#003258' : '#FFFFFF'
    readonly property color primaryContainer: dark ? '#194975' : '#D1E4FF'
    readonly property color primaryContainerOn: dark ? '#D1E4FF' : '#001D36'
    readonly property color inversePrimary: dark ? '#36618E' : '#A0CAFD'

    readonly property color secondary: dark ? '#BBC7DB' : '#535F70'
    readonly property color secondaryOn: dark ? '#253140' : '#FFFFFF'
    readonly property color secondaryContainer: dark ? '#3B4858' : '#D7E3F7'
    readonly property color secondaryContainerOn: dark ? '#D7E3F7' : '#101C2B'

    readonly property color tertiary: dark ? '#F0BF6C' : '#7C5800'
    readonly property color tertiaryOn: dark ? '#412D00' : '#FFFFFF'
    readonly property color tertiaryContainer: dark ? '#5C4200' : '#FFDEA6'
    readonly property color tertiaryContainerOn: dark ? '#FFDEA6' : '#271900'

    readonly property color success: dark ? '#87D992' : '#146C2E'
    readonly property color successOn: dark ? '#003912' : '#FFFFFF'
    readonly property color successContainer: dark ? '#01531E' : '#A3F5AC'
    readonly property color successContainerOn: dark ? '#A3F5AC' : '#002202'

    readonly property color error: dark ? '#FFB4AB' : '#BA1A1A'
    readonly property color errorOn: dark ? '#690005' : '#FFFFFF'
    readonly property color errorContainer: dark ? '#93000A' : '#FFDAD6'
    readonly property color errorContainerOn: dark ? '#FFDAD6' : '#410002'

    readonly property color surface: dark ? '#111418' : '#F8F9FF'
    readonly property color surfaceOn: dark ? '#E1E2E8' : '#191C20'
    readonly property color surfaceVariant: dark ? '#43474E' : '#DFE2EB'
    readonly property color surfaceVariantOn: dark ? '#C3C7CF' : '#43474E'
    readonly property color surfaceContainerLowest: dark ? '#0C0E13' : '#FFFFFF'
    readonly property color surfaceContainerLow: dark ? '#191C20' : '#F2F3FA'
    readonly property color surfaceContainer: dark ? '#1D2024' : '#ECEEF4'
    readonly property color surfaceContainerHigh: dark ? '#282A2F' : '#E7E8EE'
    readonly property color surfaceContainerHighest: dark ? '#33353A' : '#E1E2E8'
    readonly property color surfaceDim: dark ? '#111418' : '#D8DAE0'
    readonly property color surfaceBright: dark ? '#37393E' : '#F8F9FF'

    readonly property color outline: dark ? '#8D9199' : '#73777F'
    readonly property color outlineVariant: dark ? '#43474E' : '#C3C7CF'
    readonly property color inverseSurface: dark ? '#E1E2E8' : '#2E3135'
    readonly property color inverseSurfaceOn: dark ? '#2E3135' : '#EFF0F7'
    readonly property color scrim: '#000000'
    readonly property color shadow: '#000000'
    readonly property color scrimColor: Qt.rgba(0, 0, 0, 0.32)

    // --- state layers ---
    readonly property real stateHover: 0.08
    readonly property real stateFocus: 0.10
    readonly property real statePressed: 0.10
    readonly property real stateDragged: 0.16
    readonly property real disabledContentOpacity: 0.38
    readonly property real disabledContainerOpacity: 0.12

    // color `on` laid over `base` with the given opacity
    function stateLayer(base, on, opacity) {
        return Qt.tint(base, Qt.rgba(on.r, on.g, on.b, opacity))
    }

    // --- type scale: size / line height in px, weight, letter spacing in px ---
    readonly property var typeScale: ({
        'displayMedium':  { size: 45, line: 52, weight: Font.Normal, tracking: 0 },
        'amountHero':     { size: 40, line: 48, weight: Font.Medium, tracking: -0.5 },
        'displaySmall':   { size: 36, line: 44, weight: Font.Normal, tracking: 0 },
        'headlineSmall':  { size: 24, line: 32, weight: Font.Normal, tracking: 0 },
        'titleLarge':     { size: 22, line: 28, weight: Font.Normal, tracking: 0 },
        'titleMedium':    { size: 16, line: 24, weight: Font.Medium, tracking: 0.15 },
        'titleSmall':     { size: 14, line: 20, weight: Font.Medium, tracking: 0.1 },
        'bodyLarge':      { size: 16, line: 24, weight: Font.Normal, tracking: 0.5 },
        'bodyMedium':     { size: 14, line: 20, weight: Font.Normal, tracking: 0.25 },
        'bodySmall':      { size: 12, line: 16, weight: Font.Normal, tracking: 0.4 },
        'labelLarge':     { size: 14, line: 20, weight: Font.Medium, tracking: 0.1 },
        'labelMedium':    { size: 12, line: 16, weight: Font.Medium, tracking: 0.5 },
        'labelSmall':     { size: 11, line: 16, weight: Font.Medium, tracking: 0.5 }
    })

    function textStyle(role) {
        return role in typeScale ? typeScale[role] : typeScale['bodyMedium']
    }

    // --- shapes ---
    readonly property int radiusXS: 4
    readonly property int radiusS: 8
    readonly property int radiusM: 12
    readonly property int radiusL: 16
    readonly property int radiusLI: 20
    readonly property int radiusXL: 28

    // --- spacing (4 dp grid) and sizes ---
    readonly property int space4: 4
    readonly property int space8: 8
    readonly property int space12: 12
    readonly property int space16: 16
    readonly property int space24: 24
    readonly property int space32: 32

    readonly property int topAppBarHeight: 64
    readonly property int navigationBarHeight: 80
    readonly property int maxContentWidth: 640

    // screen margin: 16 on compact screens, 24 from 600 dp up
    function screenMargin(width) {
        return width >= 600 ? space24 : space16
    }
}
