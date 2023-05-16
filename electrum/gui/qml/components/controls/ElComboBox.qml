import QtQuick.Controls 2.0

ComboBox {
    id: cb
    // make combobox implicit width a multiple of 32, so it aligns with others
    implicitWidth: Math.ceil(contentItem.implicitWidth/32)*32 + constants.paddingXXLarge
    // redefine contentItem, as the default crops the text easily
    contentItem: Label {
        text: cb.currentText
        padding: constants.paddingLarge
        rightPadding: constants.paddingXXLarge
        font.pixelSize: constants.fontSizeMedium
    }
}
