# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'personalization-seedbackup-03.ui'
#
# Created: Thu Aug 28 22:26:22 2014
#      by: PyQt4 UI code generator 4.9.1
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.resize(400, 513)
        self.TitleLabel = QtGui.QLabel(Dialog)
        self.TitleLabel.setGeometry(QtCore.QRect(20, 10, 351, 31))
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setItalic(True)
        font.setWeight(75)
        self.TitleLabel.setFont(font)
        self.TitleLabel.setObjectName(_fromUtf8("TitleLabel"))
        self.IntroLabel = QtGui.QLabel(Dialog)
        self.IntroLabel.setGeometry(QtCore.QRect(20, 50, 351, 61))
        self.IntroLabel.setWordWrap(True)
        self.IntroLabel.setObjectName(_fromUtf8("IntroLabel"))
        self.IntroLabel_2 = QtGui.QLabel(Dialog)
        self.IntroLabel_2.setGeometry(QtCore.QRect(20, 120, 351, 31))
        self.IntroLabel_2.setWordWrap(True)
        self.IntroLabel_2.setObjectName(_fromUtf8("IntroLabel_2"))
        self.IntroLabel_3 = QtGui.QLabel(Dialog)
        self.IntroLabel_3.setGeometry(QtCore.QRect(20, 160, 351, 51))
        self.IntroLabel_3.setWordWrap(True)
        self.IntroLabel_3.setObjectName(_fromUtf8("IntroLabel_3"))
        self.IntroLabel_4 = QtGui.QLabel(Dialog)
        self.IntroLabel_4.setGeometry(QtCore.QRect(20, 220, 351, 51))
        self.IntroLabel_4.setWordWrap(True)
        self.IntroLabel_4.setObjectName(_fromUtf8("IntroLabel_4"))
        self.IntroLabel_5 = QtGui.QLabel(Dialog)
        self.IntroLabel_5.setGeometry(QtCore.QRect(20, 280, 351, 71))
        self.IntroLabel_5.setWordWrap(True)
        self.IntroLabel_5.setObjectName(_fromUtf8("IntroLabel_5"))
        self.IntroLabel_6 = QtGui.QLabel(Dialog)
        self.IntroLabel_6.setGeometry(QtCore.QRect(20, 350, 351, 51))
        self.IntroLabel_6.setWordWrap(True)
        self.IntroLabel_6.setObjectName(_fromUtf8("IntroLabel_6"))
        self.IntroLabel_7 = QtGui.QLabel(Dialog)
        self.IntroLabel_7.setGeometry(QtCore.QRect(20, 410, 351, 51))
        self.IntroLabel_7.setWordWrap(True)
        self.IntroLabel_7.setObjectName(_fromUtf8("IntroLabel_7"))
        self.NextButton = QtGui.QPushButton(Dialog)
        self.NextButton.setGeometry(QtCore.QRect(310, 480, 75, 25))
        self.NextButton.setObjectName(_fromUtf8("NextButton"))

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "BTChip setup", None, QtGui.QApplication.UnicodeUTF8))
        self.TitleLabel.setText(QtGui.QApplication.translate("Dialog", "BTChip setup  - seed backup", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel.setText(QtGui.QApplication.translate("Dialog", "If you do not trust this computer, perform the following steps on a trusted one or a different device. Anything supporting keyboard input will work (smartphone, TV box ...)", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_2.setText(QtGui.QApplication.translate("Dialog", "Open a text editor, set the focus on the text editor, then insert the dongle", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_3.setText(QtGui.QApplication.translate("Dialog", "After a very short time, the dongle will type the seed as hexadecimal (0..9 A..F) characters, starting with \"seed\" and ending with \"X\"", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_4.setText(QtGui.QApplication.translate("Dialog", "If you perform those steps on Windows, a new device driver will be loaded the first time and the seed will not be typed. This is normal.", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_5.setText(QtGui.QApplication.translate("Dialog", "If you perform those steps on Mac, you\'ll get a popup asking you to select a keyboard type the first time and the seed will not be typed. This is normal, just close the popup.", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_6.setText(QtGui.QApplication.translate("Dialog", "If you did not see the seed for any reason, keep the focus on the text editor, unplug and plug the dongle again twice.", None, QtGui.QApplication.UnicodeUTF8))
        self.IntroLabel_7.setText(QtGui.QApplication.translate("Dialog", "Then press Next once you wrote the seed to a safe medium (i.e. paper) and unplugged the dongle", None, QtGui.QApplication.UnicodeUTF8))
        self.NextButton.setText(QtGui.QApplication.translate("Dialog", "Next", None, QtGui.QApplication.UnicodeUTF8))

