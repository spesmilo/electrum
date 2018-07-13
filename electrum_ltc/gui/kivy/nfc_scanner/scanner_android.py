'''This is the Android implementation of NFC Scanning using the
built in NFC adapter of some android phones.
'''

from kivy.app import App
from kivy.clock import Clock
#Detect which platform we are on
from kivy.utils import platform
if platform != 'android':
    raise ImportError
import threading

from . import NFCBase
from jnius import autoclass, cast
from android.runnable import run_on_ui_thread
from android import activity

BUILDVERSION = autoclass('android.os.Build$VERSION').SDK_INT
NfcAdapter = autoclass('android.nfc.NfcAdapter')
PythonActivity = autoclass('org.kivy.android.PythonActivity')
JString = autoclass('java.lang.String')
Charset = autoclass('java.nio.charset.Charset')
locale = autoclass('java.util.Locale')
Intent = autoclass('android.content.Intent')
IntentFilter = autoclass('android.content.IntentFilter')
PendingIntent = autoclass('android.app.PendingIntent')
Ndef = autoclass('android.nfc.tech.Ndef')
NdefRecord = autoclass('android.nfc.NdefRecord')
NdefMessage = autoclass('android.nfc.NdefMessage')

app = None



class ScannerAndroid(NFCBase):
    ''' This is the class responsible for handling the interface with the
    Android NFC adapter. See Module Documentation for details.
    '''

    name = 'NFCAndroid'

    def nfc_init(self):
        ''' This is where we initialize NFC adapter.
        '''
        # Initialize NFC
        global app
        app = App.get_running_app()

        # Make sure we are listening to new intent 
        activity.bind(on_new_intent=self.on_new_intent)

        # Configure nfc
        self.j_context = context = PythonActivity.mActivity
        self.nfc_adapter = NfcAdapter.getDefaultAdapter(context)
        # Check if adapter exists
        if not self.nfc_adapter:
            return False
        
        # specify that we want our activity to remain on top when a new intent
        # is fired
        self.nfc_pending_intent = PendingIntent.getActivity(context, 0,
            Intent(context, context.getClass()).addFlags(
                Intent.FLAG_ACTIVITY_SINGLE_TOP), 0)

        # Filter for different types of action, by default we enable all.
        # These are only for handling different NFC technologies when app is in foreground
        self.ndef_detected = IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED)
        #self.tech_detected = IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)
        #self.tag_detected = IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED)

        # setup tag discovery for ourt tag type
        try:
            self.ndef_detected.addCategory(Intent.CATEGORY_DEFAULT)
            # setup the foreground dispatch to detect all mime types
            self.ndef_detected.addDataType('*/*')

            self.ndef_exchange_filters = [self.ndef_detected]
        except Exception as err:
            raise Exception(repr(err))
        return True

    def get_ndef_details(self, tag):
        ''' Get all the details from the tag.
        '''
        details = {}

        try:
            #print 'id'
            details['uid'] = ':'.join(['{:02x}'.format(bt & 0xff) for bt in tag.getId()])
            #print 'technologies'
            details['Technologies'] = tech_list = [tech.split('.')[-1] for tech in tag.getTechList()]
            #print 'get NDEF tag details'
            ndefTag = cast('android.nfc.tech.Ndef', Ndef.get(tag))
            #print 'tag size'
            details['MaxSize'] = ndefTag.getMaxSize()
            #details['usedSize'] = '0'
            #print 'is tag writable?'
            details['writable'] = ndefTag.isWritable()
            #print 'Data format'
            # Can be made readonly
            # get NDEF message details
            ndefMesg = ndefTag.getCachedNdefMessage()
            # get size of current records
            details['consumed'] = len(ndefMesg.toByteArray())
            #print 'tag type'
            details['Type'] = ndefTag.getType()

            # check if tag is empty
            if not ndefMesg:
                details['Message'] = None
                return details

            ndefrecords =  ndefMesg.getRecords()
            length = len(ndefrecords)
            #print 'length', length
            # will contain the NDEF record types
            recTypes = []
            for record in ndefrecords:
                recTypes.append({
                    'type': ''.join(map(unichr, record.getType())),
                    'payload': ''.join(map(unichr, record.getPayload()))
                    })

            details['recTypes'] = recTypes
        except Exception as err:
            print(str(err))

        return details

    def on_new_intent(self, intent):
        ''' This function is called when the application receives a
        new intent, for the ones the application has registered previously,
        either in the manifest or in the foreground dispatch setup in the
        nfc_init function above. 
        '''

        action_list = (NfcAdapter.ACTION_NDEF_DISCOVERED,)
        # get TAG
        #tag = cast('android.nfc.Tag', intent.getParcelableExtra(NfcAdapter.EXTRA_TAG))

        #details = self.get_ndef_details(tag)

        if intent.getAction() not in action_list:
            print('unknow action, avoid.')
            return

        rawmsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)
        if not rawmsgs:
            return
        for message in rawmsgs:
            message = cast(NdefMessage, message)
            payload = message.getRecords()[0].getPayload()
            print('payload: {}'.format(''.join(map(chr, payload))))

    def nfc_disable(self):
        '''Disable app from handling tags.
        '''
        self.disable_foreground_dispatch()

    def nfc_enable(self):
        '''Enable app to handle tags when app in foreground.
        '''
        self.enable_foreground_dispatch()

    def create_AAR(self):
        '''Create the record responsible for linking our application to the tag.
        '''
        return NdefRecord.createApplicationRecord(JString("org.electrum_ltc.kivy"))

    def create_TNF_EXTERNAL(self, data):
        '''Create our actual payload record.
        '''
        if BUILDVERSION >= 14:
            domain = "org.electrum_ltc"
            stype = "externalType"
            extRecord = NdefRecord.createExternal(domain, stype, data)
        else:
            # Creating the NdefRecord manually:
            extRecord = NdefRecord(
                NdefRecord.TNF_EXTERNAL_TYPE,
                "org.electrum_ltc:externalType",
                '',
                data)
        return extRecord

    def create_ndef_message(self, *recs):
        ''' Create the Ndef message that will be written to tag
        '''
        records = []
        for record in recs:
            if record:
                records.append(record)

        return NdefMessage(records)


    @run_on_ui_thread
    def disable_foreground_dispatch(self):
        '''Disable foreground dispatch when app is paused.
        '''
        self.nfc_adapter.disableForegroundDispatch(self.j_context)

    @run_on_ui_thread
    def enable_foreground_dispatch(self):
        '''Start listening for new tags
        '''
        self.nfc_adapter.enableForegroundDispatch(self.j_context,
                self.nfc_pending_intent, self.ndef_exchange_filters, self.ndef_tech_list)

    @run_on_ui_thread
    def _nfc_enable_ndef_exchange(self, data):
        # Enable p2p exchange
        # Create record
        ndef_record = NdefRecord(
                NdefRecord.TNF_MIME_MEDIA,
                'org.electrum_ltc.kivy', '', data)
        
        # Create message
        ndef_message = NdefMessage([ndef_record])

        # Enable ndef push
        self.nfc_adapter.enableForegroundNdefPush(self.j_context, ndef_message)

        # Enable dispatch
        self.nfc_adapter.enableForegroundDispatch(self.j_context,
                self.nfc_pending_intent, self.ndef_exchange_filters, [])

    @run_on_ui_thread
    def _nfc_disable_ndef_exchange(self):
        # Disable p2p exchange
        self.nfc_adapter.disableForegroundNdefPush(self.j_context)
        self.nfc_adapter.disableForegroundDispatch(self.j_context)

    def nfc_enable_exchange(self, data):
        '''Enable Ndef exchange for p2p
        '''
        self._nfc_enable_ndef_exchange()

    def nfc_disable_exchange(self):
        ''' Disable Ndef exchange for p2p
        '''
        self._nfc_disable_ndef_exchange()
