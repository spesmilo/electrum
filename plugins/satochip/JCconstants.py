"""
 * Python API for the SatoChip Bitcoin Hardware Wallet
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https:#github.com/Toporin
 * 
 * Copyright 2015 by Toporin (https:#github.com/Toporin)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http:#www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
"""

class JCconstants:
    
    #Maximum number of keys handled by the Cardlet
    MAX_NUM_KEYS = 0x10;
    # Maximum number of PIN codes
    MAX_NUM_PINS = 0x8;
    # Maximum number of keys allowed for ExtAuth
    MAX_NUM_AUTH_KEYS = 0x6;

    # Maximum size for the extended APDU buffer for a 2048 bit key:
    # CLA [1 byte] + INS [1 byte] + P1 [1 byte] + P2 [1 byte] +
    # LC [3 bytes] + cipher_mode[1 byte] + cipher_direction [1 byte] +
    # data_location [1 byte] + data_size [2 bytes] + data [256 bytes]
    # = 268 bytes
    EXT_APDU_BUFFER_SIZE = 268;

    # Minimum PIN size
    PIN_MIN_SIZE = 4;
    # Maximum PIN size
    PIN_MAX_SIZE =  16;
    # PIN[0] initial value...
    PIN_INIT_VALUE=[0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30] #default pin
    
    # Maximum external authentication tries per key
    MAX_KEY_TRIES =  5;

    # Import/Export Object ID
    IN_OBJECT_CLA =  0xFFFF;
    IN_OBJECT_ID =  0xFFFE;
    OUT_OBJECT_CLA =  0xFFFF;
    OUT_OBJECT_ID =  0xFFFF;

    KEY_ACL_SIZE =  6;
    ACL_READ =  0;
    ACL_WRITE =  2;
    ACL_USE =  4;
    DEFAULT_ACL= [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    
    # code of CLA byte in the command APDU header
    CardEdge_CLA =  0xB0

    '''****************************************
       *         Instruction codes            *
       ****************************************'''

    # Applet initialization
    INS_SETUP =  0x2A;

    # Keys' use and management
    INS_GEN_KEYPAIR =  0x30;
    INS_GEN_KEYSYM =  0x31;
    INS_IMPORT_KEY =  0x32;
    INS_EXPORT_KEY =  0x34;
    INS_GET_PUBLIC_FROM_PRIVATE= 0x35;
    INS_COMPUTE_CRYPT =  0x36;
    INS_COMPUTE_SIGN =  0x37; # added
    
    # External authentication
    INS_CREATE_PIN =  0x40;
    INS_VERIFY_PIN =  0x42;
    INS_CHANGE_PIN =  0x44;
    INS_UNBLOCK_PIN =  0x46;
    INS_LOGOUT_ALL =  0x60;
    INS_GET_CHALLENGE =  0x62;
    INS_EXT_AUTH =  0x38;

    # Objects' use and management
    INS_CREATE_OBJ =  0x5A;
    INS_DELETE_OBJ =  0x52;
    INS_READ_OBJ =  0x56;
    INS_WRITE_OBJ =  0x54;
    INS_SIZE_OBJ =  0x57;

    # Status information
    INS_LIST_OBJECTS =  0x58;
    INS_LIST_PINS =  0x48;
    INS_LIST_KEYS =  0x3A;
    INS_GET_STATUS =  0x3C;
    
    # HD wallet
    INS_COMPUTE_SHA512 =  0x6A;
    INS_COMPUTE_HMACSHA512=  0x6B;
    INS_BIP32_IMPORT_SEED=  0x6C;
    INS_BIP32_GET_AUTHENTIKEY=  0x73;
    INS_BIP32_GET_EXTENDED_KEY=  0x6D;
    INS_SIGN_MESSAGE=  0x6E;
    INS_SIGN_SHORT_MESSAGE=  0x72;
    INS_SIGN_TRANSACTION=  0x6F;
    INS_BIP32_SET_EXTENDED_KEY=  0x70;
    INS_PARSE_TRANSACTION =  0x71;
    
    '''****************************************
       *             Error codes              *
       ****************************************'''	   
    #o error!
    SW_OK = 0x9000;
    # There have been memory problems on the card 
    SW_NO_MEMORY_LEFT = 0x9c01;
    # Entered PIN is not correct */
    SW_AUTH_FAILED =  0x9C02;
    # Required operation is not allowed in actual circumstances 
    SW_OPERATION_NOT_ALLOWED =  0x9C03;
    # Required setup is not not done */
    SW_SETUP_NOT_DONE =  0x9C04;
    # Required feature is not (yet) supported */
    SW_UNSUPPORTED_FEATURE =  0x9C05;
    # Required operation was not authorized because of a lack of privileges */
    SW_UNAUTHORIZED =  0x9C06;
    # Required object is missing */
    SW_OBJECT_NOT_FOUND =  0x9C07;
    # New object ID already in use */
    SW_OBJECT_EXISTS =  0x9C08;
    # Algorithm specified is not correct */
    SW_INCORRECT_ALG =  0x9C09;

    # Incorrect P1 parameter */
    SW_INCORRECT_P1 =  0x9C10;
    # Incorrect P2 parameter */
    SW_INCORRECT_P2 =  0x9C11;
    # No more data available */
    SW_SEQUENCE_END =  0x9C12;
    # Invalid input parameter to command */
    SW_INVALID_PARAMETER =  0x9C0F;

    # Verify operation detected an invalid signature */
    SW_SIGNATURE_INVALID =  0x9C0B;
    # Operation has been blocked for security reason */
    SW_IDENTITY_BLOCKED =  0x9C0C;
    # Unspecified error */
    SW_UNSPECIFIED_ERROR =  0x9C0D;
    # For debugging purposes */
    SW_INTERNAL_ERROR =  0x9CFF;
    # For debugging purposes 2*/
    SW_DEBUG_FLAG =  0x9FFF;
    # Very low probability error */
    SW_BIP32_DERIVATION_ERROR =  0x9C0E;
    # Support only hardened key currently */
    SW_BIP32_HARDENED_KEY_ERROR =  0x9C16;
    # Incorrect initialization of method */
    SW_INCORRECT_INITIALIZATION =  0x9C13;
    # Bip32 seed is not initialized*/
    SW_BIP32_UNINITIALIZED_SEED =  0x9C14;
    # Incorrect transaction hash */
    SW_INCORRECT_TXHASH =  0x9C15;
    
    '''****************************************
       *          Algorithm codes             *
       ****************************************'''
    
    # Algorithm Type in APDUs
    ALG_RSA = 0x01; #KeyPair.ALG_RSA;
    ALG_RSA_CRT = 0x02; #KeyPair.ALG_RSA_CRT;
    ALG_EC_FP = 0x05; #KeyPair.ALG_EC_FP;

    # Key Type in Key Blobs
    TYPE_RSA_PUBLIC = 4; #KeyBuilder.TYPE_RSA_PUBLIC; 
    TYPE_RSA_PRIVATE = 5; #KeyBuilder.TYPE_RSA_PRIVATE; 
    TYPE_RSA_CRT_PRIVATE = 6; #KeyBuilder.TYPE_RSA_CRT_PRIVATE; 
    TYPE_EC_FP_PUBLIC = 11; #KeyBuilder.TYPE_EC_FP_PUBLIC;
    TYPE_EC_FP_PRIVATE = 12; #KeyBuilder.TYPE_EC_FP_PRIVATE;
    TYPE_DES = 3; #KeyBuilder.TYPE_DES; 
    TYPE_AES=15; #KeyBuilder.TYPE_AES;
        
    # KeyBlob Encoding in Key Blobs
    BLOB_ENC_PLAIN =  0x00;

    # Cipher Operations admitted in ComputeCrypt()
    OP_INIT =  0x01;
    OP_PROCESS =  0x02;
    OP_FINALIZE =  0x03;

    # Cipher Directions admitted in ComputeCrypt()
    MODE_SIGN = 0x01; #Signature.MODE_SIGN;
    MODE_VERIFY = 0x02; #Signature.MODE_VERIFY;
    MODE_ENCRYPT = 0x02; #Cipher.MODE_ENCRYPT; 
    MODE_DECRYPT = 0x01; #Cipher.MODE_DECRYPT; 

    # Cipher Modes admitted in ComputeCrypt()
    ALG_RSA_NOPAD = 12; #Cipher.ALG_RSA_NOPAD; # 0x00;
    ALG_RSA_PKCS1 = 10; #Cipher.ALG_RSA_PKCS1; # 0x01;
    ALG_DES_CBC_NOPAD = 1; #Cipher.ALG_DES_CBC_NOPAD; # 0x20;
    ALG_DES_ECB_NOPAD = 5; #Cipher.ALG_DES_ECB_NOPAD; # 0x21;
    ALG_AES_BLOCK_128_CBC_NOPAD = 13; #Cipher.ALG_AES_BLOCK_128_CBC_NOPAD; 
    ALG_AES_BLOCK_128_ECB_NOPAD = 14; #Cipher.ALG_AES_BLOCK_128_ECB_NOPAD; 
    ALG_ECDSA_SHA = 17; #Signature.ALG_ECDSA_SHA;# 0x30;
    ALG_ECDSA_SHA_256 = 33; #Bitcoin (Signature.ALG_ECDSA_SHA256==33) https:#javacard.kenai.com/javadocs/classic/javacard/security/Signature.html#ALG_ECDSA_SHA_256 
    
    DL_APDU =  0x01;
    DL_OBJECT =  0x02;
    LIST_OPT_RESET =  0x00;
    LIST_OPT_NEXT =  0x01;

    OPT_DEFAULT =  0x00; # Use JC defaults
    OPT_RSA_PUB_EXP =  0x01; # RSA: provide public exponent
    OPT_EC_SECP256k1 =  0x03; # EC: provide P, a, b, G, R, K public key parameters 
        
    # Offsets in buffer[] for key generation
    OFFSET_GENKEY_ALG =  0;
    OFFSET_GENKEY_SIZE =  (OFFSET_GENKEY_ALG + 1);
    OFFSET_GENKEY_PRV_ACL =  (OFFSET_GENKEY_SIZE + 2);
    OFFSET_GENKEY_PUB_ACL =  (OFFSET_GENKEY_PRV_ACL + KEY_ACL_SIZE);
    OFFSET_GENKEY_OPTIONS =  (OFFSET_GENKEY_PUB_ACL + KEY_ACL_SIZE);
    OFFSET_GENKEY_RSA_PUB_EXP_LENGTH =  (OFFSET_GENKEY_OPTIONS + 1);
    OFFSET_GENKEY_RSA_PUB_EXP_VALUE =  (OFFSET_GENKEY_RSA_PUB_EXP_LENGTH + 2);
    
    # JC API 2.2.2 does not define this constant:
    ALG_EC_SVDP_DH_PLAIN=  3; #https:#javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
    LENGTH_EC_FP_256=  256;
    
    #Satochip: default parameters for EC curve secp256k1
    SECP256K1_P =[ 
                    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 
                    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 
                    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
                    0xFF,0xFF,0xFF,0xFE, 0xFF,0xFF,0xFC,0x2F]; 
    SECP256K1_a = [
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00];
    SECP256K1_b = [
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07];
    SECP256K1_G = [0x04, #base point, uncompressed form 
                    0x79,0xBE,0x66,0x7E, 0xF9,0xDC,0xBB,0xAC,
                    0x55,0xA0,0x62,0x95, 0xCE,0x87,0x0B,0x07,
                    0x02,0x9B,0xFC,0xDB, 0x2D,0xCE,0x28,0xD9,
                    0x59,0xF2,0x81,0x5B, 0x16,0xF8,0x17,0x98,
                    0x48,0x3A,0xDA,0x77, 0x26,0xA3,0xC4,0x65,
                    0x5D,0xA4,0xFB,0xFC, 0x0E,0x11,0x08,0xA8,
                    0xFD,0x17,0xB4,0x48, 0xA6,0x85,0x54,0x19,
                    0x9C,0x47,0xD0,0x8F, 0xFB,0x10,0xD4,0xB8];
    SECP256K1_R = [
                    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, # order of G
                    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFE,
                    0xBA,0xAE,0xDC,0xE6, 0xAF,0x48,0xA0,0x3B,
                    0xBF,0xD2,0x5E,0x8C, 0xD0,0x36,0x41,0x41];
    SECP256K1_K = 0x01; # cofactor     

