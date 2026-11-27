import QtQuick

// Header of a group of settings or list items: titleSmall in primary, padding 16 / 8
M3Text {
    role: 'titleSmall'
    color: m3.primary
    leftPadding: m3.space16
    rightPadding: m3.space16
    topPadding: m3.space16
    bottomPadding: m3.space8
    elide: Text.ElideRight
}
