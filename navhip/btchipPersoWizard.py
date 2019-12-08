"""
*******************************************************************************
*   BTChip Bitcoin Hardware Wallet Python API
*   (c) 2014 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************
"""

import sys

from PyQt4 import QtCore, QtGui
from PyQt4.QtGui import QDialog, QMessageBox

try:
	from mnemonic import Mnemonic
	MNEMONIC = True
except:
	MNEMONIC = False

from .btchipComm import getDongle, DongleWait
from .btchip import btchip
from .btchipUtils import compress_public_key,format_transaction, get_regular_input_script
from .bitcoinTransaction import bitcoinTransaction
from .btchipException import BTChipException

import ui.personalization00start
import ui.personalization01seed
import ui.personalization02security
import ui.personalization03config
import ui.personalization04finalize
import ui.personalizationseedbackup01
import ui.personalizationseedbackup02
import ui.personalizationseedbackup03
import ui.personalizationseedbackup04

BTCHIP_DEBUG = False

def waitDongle(currentDialog, persoData):
	try:
		if persoData['client'] != None:
			try:
				persoData['client'].dongle.close()
			except:
				pass
		dongle = getDongle(BTCHIP_DEBUG)
		persoData['client'] = btchip(dongle)
		persoData['client'].getFirmwareVersion()['version'].split(".")
		return True
	except BTChipException as e:
		if e.sw == 0x6faa:
			QMessageBox.information(currentDialog, "BTChip Setup", "Please unplug the dongle and plug it again", "OK")
			return False
		if QMessageBox.question(currentDialog, "BTChip setup", "BTChip dongle not found.  It might be in the wrong mode. Try unplugging und plugging it back in again, then press 'OK'", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) == QMessageBox.Yes:
			return False
		else:
			raise Exception("Aborted by user")
	except Exception as e:
		if QMessageBox.question(currentDialog, "BTChip setup", "BTChip dongle not found.  It might be in the wrong mode. Try unplugging und plugging it back in again, then press 'OK'", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes) == QMessageBox.Yes:
			return False
		else:
			raise Exception("Aborted by user")


class StartBTChipPersoDialog(QtGui.QDialog):

	def __init__(self):
		QDialog.__init__(self, None)
		self.ui = ui.personalization00start.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.NextButton.clicked.connect(self.processNext)
		self.ui.CancelButton.clicked.connect(self.processCancel)

	def processNext(self):
		persoData = {}
		persoData['currencyCode'] = 0x00
		persoData['currencyCodeP2SH'] = 0x05
		persoData['client'] = None
		dialog = SeedDialog(persoData, self)
		persoData['main'] = self
		dialog.exec_()
		pass

	def processCancel(self):
		self.reject()

class SeedDialog(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalization01seed.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.seed.setEnabled(False)
		self.ui.RestoreWalletButton.toggled.connect(self.restoreWalletToggled)
		self.ui.NextButton.clicked.connect(self.processNext)
		self.ui.CancelButton.clicked.connect(self.processCancel)
		if MNEMONIC:
			self.mnemonic = Mnemonic('english')
			self.ui.mnemonicNotAvailableLabel.hide()

	def restoreWalletToggled(self, toggled):
		self.ui.seed.setEnabled(toggled)

	def processNext(self):
		self.persoData['seed'] = None
		if self.ui.RestoreWalletButton.isChecked():
			# Check if it's an hexa string
			seedText = str(self.ui.seed.text())
			if len(seedText) == 0:
				QMessageBox.warning(self, "Error", "Please enter a seed", "OK")
				return
			if seedText[-1] == 'X':
				seedText = seedText[0:-1]
			try:
				self.persoData['seed'] = seedText.decode('hex')
			except:
				pass
			if self.persoData['seed'] == None:
				if not MNEMONIC:
					QMessageBox.warning(self, "Error", "Mnemonic API not available. Please install https://github.com/trezor/python-mnemonic", "OK")
					return
				if not self.mnemonic.check(seedText):
					QMessageBox.warning(self, "Error", "Invalid mnemonic", "OK")
					return
				self.persoData['seed'] = Mnemonic.to_seed(seedText)
			else:
				if (len(self.persoData['seed']) < 32) or (len(self.persoData['seed']) > 64):
					QMessageBox.warning(self, "Error", "Invalid seed length", "OK")
					return
		dialog = SecurityDialog(self.persoData, self)
		self.hide()
		dialog.exec_()

	def processCancel(self):
		self.reject()
		self.persoData['main'].reject()

class SecurityDialog(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalization02security.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.NextButton.clicked.connect(self.processNext)
		self.ui.CancelButton.clicked.connect(self.processCancel)


	def processNext(self):
		if (self.ui.pin1.text() != self.ui.pin2.text()):
			self.ui.pin1.setText("")
			self.ui.pin2.setText("")
			QMessageBox.warning(self, "Error", "PINs are not matching", "OK")
			return
		if (len(self.ui.pin1.text()) < 4):
			QMessageBox.warning(self, "Error", "PIN must be at least 4 characteres long", "OK")
			return
		if (len(self.ui.pin1.text()) > 32):
			QMessageBox.warning(self, "Error", "PIN is too long", "OK")
			return
		self.persoData['pin'] = str(self.ui.pin1.text())
		self.persoData['hardened'] = self.ui.HardenedButton.isChecked()
		dialog = ConfigDialog(self.persoData, self)
		self.hide()
		dialog.exec_()

	def processCancel(self):
		self.reject()
		self.persoData['main'].reject()

class ConfigDialog(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalization03config.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.NextButton.clicked.connect(self.processNext)
		self.ui.CancelButton.clicked.connect(self.processCancel)

	def processNext(self):
		if (self.ui.qwertyButton.isChecked()):
			self.persoData['keyboard'] = btchip.QWERTY_KEYMAP
		elif (self.ui.qwertzButton.isChecked()):
			self.persoData['keyboard'] = btchip.QWERTZ_KEYMAP
		elif (self.ui.azertyButton.isChecked()):
			self.persoData['keyboard'] = btchip.AZERTY_KEYMAP
		try:
			while not waitDongle(self, self.persoData):
				pass
		except Exception as e:
			self.reject()
			self.persoData['main'].reject()
		mode = btchip.OPERATION_MODE_WALLET
		if not self.persoData['hardened']:
			mode = mode | btchip.OPERATION_MODE_SERVER
		try:
			self.persoData['client'].setup(mode, btchip.FEATURE_RFC6979, self.persoData['currencyCode'],
				self.persoData['currencyCodeP2SH'], self.persoData['pin'], None,
				self.persoData['keyboard'], self.persoData['seed'])
		except BTChipException as e:
			if e.sw == 0x6985:
				QMessageBox.warning(self, "Error", "Dongle is already set up. Please insert a different one", "OK")
				return
		except Exception as e:
				QMessageBox.warning(self, "Error", "Error performing setup", "OK")
				return
		if self.persoData['seed'] is None:
			dialog = SeedBackupStart(self.persoData, self)
			self.hide()
			dialog.exec_()
		else:
			dialog = FinalizeDialog(self.persoData, self)
			self.hide()
			dialog.exec_()

	def processCancel(self):
		self.reject()
		self.persoData['main'].reject()

class FinalizeDialog(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalization04finalize.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.FinishButton.clicked.connect(self.finish)
		try:
			while not waitDongle(self, self.persoData):
				pass
		except Exception as e:
			self.reject()
			self.persoData['main'].reject()
		attempts = self.persoData['client'].getVerifyPinRemainingAttempts()
		self.ui.remainingAttemptsLabel.setText("Remaining attempts " + str(attempts))

	def finish(self):
		if (len(self.ui.pin1.text()) < 4):
			QMessageBox.warning(self, "Error", "PIN must be at least 4 characteres long", "OK")
			return
		if (len(self.ui.pin1.text()) > 32):
			QMessageBox.warning(self, "Error", "PIN is too long", "OK")
			return
		try:
			self.persoData['client'].verifyPin(str(self.ui.pin1.text()))
		except BTChipException as e:
			if ((e.sw == 0x63c0) or (e.sw == 0x6985)):
				QMessageBox.warning(self, "Error", "Invalid PIN - dongle has been reset. Please personalize again", "OK")
				self.reject()
				self.persoData['main'].reject()
			if ((e.sw & 0xfff0) == 0x63c0):
				attempts = e.sw - 0x63c0
				self.ui.remainingAttemptsLabel.setText("Remaining attempts " + str(attempts))
			QMessageBox.warning(self, "Error", "Invalid PIN - please unplug the dongle and plug it again before retrying", "OK")
			try:
				while not waitDongle(self, self.persoData):
					pass
			except Exception as e:
				self.reject()
				self.persoData['main'].reject()
			return
		except Exception as e:
			QMessageBox.warning(self, "Error", "Unexpected error verifying PIN  - aborting", "OK")
			self.reject()
			self.persoData['main'].reject()
			return
		if not self.persoData['hardened']:
			try:
				self.persoData['client'].setOperationMode(btchip.OPERATION_MODE_SERVER)
			except:
				QMessageBox.warning(self, "Error", "Error switching to non hardened mode", "OK")
				self.reject()
				self.persoData['main'].reject()
				return
		QMessageBox.information(self, "BTChip Setup", "Setup completed. Please unplug the dongle and plug it again before use", "OK")
		self.accept()
		self.persoData['main'].accept()

class SeedBackupStart(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalizationseedbackup01.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.NextButton.clicked.connect(self.processNext)

	def processNext(self):
		dialog = SeedBackupUnplug(self.persoData, self)
		self.hide()
		dialog.exec_()

class SeedBackupUnplug(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalizationseedbackup02.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.NextButton.clicked.connect(self.processNext)

	def processNext(self):
		dialog = SeedBackupInstructions(self.persoData, self)
		self.hide()
		dialog.exec_()

class SeedBackupInstructions(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalizationseedbackup03.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.NextButton.clicked.connect(self.processNext)

	def processNext(self):
		dialog = SeedBackupVerify(self.persoData, self)
		self.hide()
		dialog.exec_()

class SeedBackupVerify(QtGui.QDialog):

	def __init__(self, persoData, parent = None):
		QDialog.__init__(self, parent)
		self.persoData = persoData
		self.ui = ui.personalizationseedbackup04.Ui_Dialog()
		self.ui.setupUi(self)
		self.ui.seedOkButton.clicked.connect(self.seedOK)
		self.ui.seedKoButton.clicked.connect(self.seedKO)

	def seedOK(self):
		dialog = FinalizeDialog(self.persoData, self)
		self.hide()
		dialog.exec_()

	def seedKO(self):
		finished = False
		while not finished:
			try:
				while not waitDongle(self, self.persoData):
					pass
			except Exception as e:
				pass
			try:
				self.persoData['client'].verifyPin("0")
			except BTChipException as e:
				if e.sw == 0x63c0:
					QMessageBox.information(self, "BTChip Setup", "Dongle is reset and can be repersonalized", "OK")
					finished = True
					pass
				if e.sw == 0x6faa:
					QMessageBox.information(self, "BTChip Setup", "Please unplug the dongle and plug it again", "OK")
					pass
			except Exception as e:
				pass
		self.reject()
		self.persoData['main'].reject()

if __name__ == "__main__":

	app = QtGui.QApplication(sys.argv)
	dialog = StartBTChipPersoDialog()
	dialog.show()
	app.exec_()
