import QtQuick 2.15
import QtQuick.Controls 2.15

ComboBox {
    id: cb

    property int implicitChildrenWidth: 64

    // make combobox implicit width a multiple of 32, so it aligns with others
    implicitWidth: Math.ceil(implicitChildrenWidth/32)*32 + 2 * constants.paddingXLarge

    // redefine contentItem, as the default crops the text easily
    contentItem: Label {
        id: contentLabel
        text: cb.currentText
        padding: constants.paddingLarge
        rightPadding: constants.paddingXXLarge
        font.pixelSize: constants.fontSizeMedium
    }

    // determine widest element and store in implicitChildrenWidth
    function updateImplicitWidth() {
        console.log('updating implicit width')
        console.log(cb.count)
        for (let i = 0; i < cb.count; i++) {
            var txt = cb.textAt(i)
            var txtwidth = fontMetrics.advanceWidth(txt)
            console.log(txt + ' is ' + txtwidth + ' wide')
            if (txtwidth > cb.implicitChildrenWidth) {
                cb.implicitChildrenWidth = txtwidth
            }
        }
    }

    FontMetrics {
        id: fontMetrics
        font: contentLabel.font
    }

    Component.onCompleted: updateImplicitWidth()
    onModelChanged: updateImplicitWidth()
}
