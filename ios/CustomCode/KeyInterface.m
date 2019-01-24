//
//  KeyInterface.m
//  TestKeys
//
//  Created by calin on 6/15/18.
//  Copyright © 2018 c3-soft.com. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import "KeyInterface.h"

#define newCFDict CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks)
#define CFClean(x) do { if (x) CFRelease(x); x = NULL; } while (0)

@interface KeyInterface()
- (SecKeyRef) lookupPublicKeyRef;
- (SecKeyRef) lookupPrivateKeyRef;
@property (nonatomic, strong) LAContext *laContext;
@end

@implementation KeyInterface {
    SecKeyRef _publicKeyRef;
    SecKeyRef _privateKeyRef;
    NSData    *_publicKeyBits;
    NSString *_publicKeyName, *_privateKeyName;
}

- (void) dealloc {
    CFClean(_publicKeyRef);
    CFClean(_privateKeyRef);
}

- (instancetype) init {
    if ((self = [super init])) {
        self.prompt = @"Authenticate, please";
        self.laContext = [LAContext new];
        //self.laContext.localizedReason = self.prompt;
    }
    return self;
}

+ (instancetype) keyInterfaceWithPublicKeyName:(NSString *)publicKeyName privateKeyName:(NSString *)privateKeyName {
    KeyInterface *ret = [KeyInterface new];
    if (ret) {
        ret->_publicKeyName = [publicKeyName copy];
        ret->_privateKeyName = [privateKeyName copy];
    }
    return ret;
}

- (BOOL) biometricsAreAvailableWithError:(NSError **)errPtr {
    __autoreleasing NSError *dummy = nil;
    if (errPtr) *errPtr = nil;
    else errPtr = &dummy;
    return [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                       error:errPtr];
}

- (BOOL) biometricsAreAvailable { return [self biometricsAreAvailableWithError:nil]; }

- (void) biometricAuthWithCompletion:(void (^)(BOOL,NSError *))completion {
    [self.laContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:self.prompt reply: ^(BOOL b, NSError *e){
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(b, e); });
    }];
}

- (BOOL) publicKeyExists
{
    if (_publicKeyRef) return _publicKeyRef != nil;
    CFMutableDictionaryRef publicKeyExistsQuery = newCFDict;
    CFDictionarySetValue(publicKeyExistsQuery, kSecClass,               kSecClassKey);
    CFDictionarySetValue(publicKeyExistsQuery, kSecAttrKeyType,         kSecAttrKeyTypeEC);
    CFDictionarySetValue(publicKeyExistsQuery, kSecAttrApplicationTag,  (CFStringRef)_publicKeyName);
    CFDictionarySetValue(publicKeyExistsQuery, kSecAttrKeyClass,        kSecAttrKeyClassPublic);
    CFDictionarySetValue(publicKeyExistsQuery, kSecReturnRef,          kCFBooleanTrue);

    OSStatus status = SecItemCopyMatching(publicKeyExistsQuery, (CFTypeRef *)&_publicKeyRef);
    CFClean(publicKeyExistsQuery);

    if (status == errSecItemNotFound) {
        return NO;
    }
    else if (status == errSecSuccess) {
        return YES;
    }
    else {
        [NSException raise:@"Unexpected OSStatus" format:@"Status: %d", (int)status];
        return NO;
    }
}

- (SecKeyRef) lookupPublicKeyRef
{
    if (_publicKeyRef) return _publicKeyRef;
    [self publicKeyExists];
    return _publicKeyRef;
}

- (NSData *) publicKeyBits
{
    if (!self.publicKeyExists)
        return nil;
    if (_publicKeyBits) return _publicKeyBits;
    if (_publicKeyRef)
        _publicKeyBits = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(_publicKeyRef, NULL));
    return _publicKeyBits;
}

- (void) setPrompt:(NSString *)prompt {
    if (!_prompt || ![prompt isEqualToString:_prompt]) {
        _prompt = prompt ? [prompt copy] : [@"" copy];
        if (_privateKeyRef)
            /* by clearing the ref, we force re-setting of the kSecUseOperationPrompt
               dictionary entry for this item... (see lookupPrivateKeyRef below) */
            CFClean(_privateKeyRef);
    }
}

// NB: DO NOT release returned value!!
- (SecKeyRef) lookupPrivateKeyRef
{
    if (_privateKeyRef) return _privateKeyRef;
    CFMutableDictionaryRef getPrivateKeyRef = newCFDict;
    CFDictionarySetValue(getPrivateKeyRef, kSecClass, kSecClassKey);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrLabel, (CFStringRef)_privateKeyName);
    CFDictionarySetValue(getPrivateKeyRef, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(getPrivateKeyRef, kSecUseOperationPrompt, (CFStringRef)_prompt);
    OSStatus status = SecItemCopyMatching(getPrivateKeyRef, (CFTypeRef *)&_privateKeyRef);
    CFClean(getPrivateKeyRef);
    if (status == errSecItemNotFound)
        return nil;

    return _privateKeyRef;
}

- (void) generateTouchIDKeyPairWithCompletion:(void (^)(BOOL, NSError *))completion
{
    __weak KeyInterface *weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{
        CFErrorRef error = NULL;
        // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
        SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(
                                                                        kCFAllocatorDefault,
                                                                        kSecAttrAccessibleWhenUnlocked,/*kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,*/
#if __IPHONE_OS_VERSION_MIN_REQUIRED >= 113000
                                                                        kSecAccessControlBiometryAny
#else
                                                                        kSecAccessControlTouchIDAny
#endif
                                                                        | kSecAccessControlPrivateKeyUsage,
                                                                        &error
                                                                        );

        BOOL ret = NO;
        NSError *err = nil;
        if (error != errSecSuccess) {
            NSLog(@"Generate key error: %@\n", error);
            err = CFBridgingRelease(error);
        } else
            ret = [weakSelf generateKeyPairWithAccessControlObject:sacObject];
        CFClean(sacObject);
        if (completion) {
            if (!err && !ret) err = [NSError errorWithDomain:@"Unspecified Error" code:-50 userInfo:nil];
            dispatch_async(dispatch_get_main_queue(), ^{ completion(ret, err); });
        }
    });
}

- (BOOL) generatePasscodeKeyPair
{
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(
                                                                    kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenUnlocked,
                                                                    /*kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,*/
                                                                    kSecAccessControlUserPresence,
                                                                    &error
                                                                    );

    if (error != errSecSuccess) {
        NSLog(@"Generate key error: %@\n", error);
    }

    BOOL ret = [self generateKeyPairWithAccessControlObject:sacObject];
    CFClean(sacObject);
    return ret;
}

- (BOOL) generateKeyPairWithAccessControlObject:(SecAccessControlRef)accessControlRef
{
    // create dict of private key info
    CFMutableDictionaryRef accessControlDict = newCFDict;;
    CFDictionaryAddValue(accessControlDict, kSecAttrAccessControl, accessControlRef);
    CFDictionaryAddValue(accessControlDict, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(accessControlDict, kSecAttrLabel, (CFStringRef)_privateKeyName);

    static NSNumber *num256;
    if (!num256) num256 = @(256);
    // create dict which actually saves key into keychain
    CFMutableDictionaryRef generatePairRef = newCFDict;
    CFDictionaryAddValue(generatePairRef, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionaryAddValue(generatePairRef, kSecAttrKeyType, kSecAttrKeyTypeEC);
    CFDictionaryAddValue(generatePairRef, kSecAttrKeySizeInBits, (CFNumberRef)num256);
    CFDictionaryAddValue(generatePairRef, kSecPrivateKeyAttrs, accessControlDict);

    OSStatus status = SecKeyGeneratePair(generatePairRef, &_publicKeyRef, &_privateKeyRef);

    CFClean(generatePairRef);
    CFClean(accessControlDict);

    if (status != errSecSuccess)
        return NO;

    BOOL ret = [KeyInterface savePublicKeyFromRef:_publicKeyRef withName:_publicKeyName];
    // now clear them so user has to auth each the next time to use them
    CFClean(_publicKeyRef);
    CFClean(_privateKeyRef);
    return ret;
}

+ (BOOL) savePublicKeyFromRef:(SecKeyRef)publicKeyRef withName:(NSString *)name
{
    CFTypeRef keyBits = NULL;
    CFMutableDictionaryRef savePublicKeyDict = newCFDict;
    CFDictionaryAddValue(savePublicKeyDict, kSecClass,        kSecClassKey);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyType,  kSecAttrKeyTypeEC);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrApplicationTag, (CFStringRef)name);
    CFDictionaryAddValue(savePublicKeyDict, kSecValueRef, publicKeyRef);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrIsPermanent, kCFBooleanTrue);
    //CFDictionaryAddValue(savePublicKeyDict, kSecReturnData, kCFBooleanTrue);

    OSStatus err = SecItemAdd(savePublicKeyDict, &keyBits);
    CFClean(keyBits);
    if (err == errSecDuplicateItem) {
        while (err == errSecDuplicateItem)
        {
            err = SecItemDelete(savePublicKeyDict);
        }
        keyBits = NULL;
        err = SecItemAdd(savePublicKeyDict, &keyBits);
        CFClean(keyBits);
    }
    CFClean(savePublicKeyDict);
    return err == errSecSuccess;
}

- (BOOL) deleteKeyPair {
    if (_publicKeyRef) CFClean(_publicKeyRef);
    _publicKeyBits = nil;
    CFMutableDictionaryRef savePublicKeyDict = newCFDict;
    CFDictionaryAddValue(savePublicKeyDict, kSecClass,        kSecClassKey);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyType,  kSecAttrKeyTypeEC);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFDictionaryAddValue(savePublicKeyDict, kSecAttrApplicationTag, (CFStringRef)_publicKeyName);

    OSStatus err = SecItemDelete(savePublicKeyDict);
    while (err == errSecDuplicateItem)
    {
        err = SecItemDelete(savePublicKeyDict);
    }
    CFClean(savePublicKeyDict);
    if (_privateKeyRef) CFClean(_privateKeyRef);
    CFMutableDictionaryRef getPrivateKeyRef = newCFDict;
    CFDictionarySetValue(getPrivateKeyRef, kSecClass, kSecClassKey);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(getPrivateKeyRef, kSecAttrLabel, (CFStringRef)_privateKeyName);
    CFDictionarySetValue(getPrivateKeyRef, kSecReturnRef, kCFBooleanTrue);

    err = SecItemDelete(getPrivateKeyRef);
    while (err == errSecDuplicateItem)
    {
        err = SecItemDelete(getPrivateKeyRef);
    }
    CFClean(getPrivateKeyRef);
    return YES;
}

- (void) generateSignatureForData:(NSData *)inputData completion:(void(^)(NSData*, NSError*))completion {
    __weak KeyInterface *weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{
        const uint8_t * const digestData = [inputData bytes];
        size_t digestLength = [inputData length];

        uint8_t signature[256] = { 0 };
        size_t signatureLength = sizeof(signature);

        OSStatus status = errSecBadReq;
        SecKeyRef pk = [weakSelf lookupPrivateKeyRef];
        if (pk)
            status = SecKeyRawSign(pk, kSecPaddingPKCS1, digestData, digestLength, signature, &signatureLength);

        if (status == errSecSuccess && completion) {
            NSData *sig = [NSData dataWithBytes:signature length:signatureLength];
            dispatch_async(dispatch_get_main_queue(), ^{ completion(sig, nil); });
        } else if (completion) {
            NSError *error = [NSError errorWithDomain:@"SecKeyError" code:status userInfo:nil];
            dispatch_async(dispatch_get_main_queue(), ^{ completion(nil, error); });
        }
    });
}

- (BOOL) verifySignature:(NSData *)signature forData:(NSData *)inputData error:(NSError **)errPtr {
    const uint8_t * const data = [inputData bytes];
    size_t dataLength = [inputData length];
    const uint8_t * const sig = [signature bytes];
    size_t sigLength = [signature length];
    SecKeyRef pk = [self lookupPublicKeyRef];
    OSStatus status = errSecBadReq;
    if (pk)
        status = SecKeyRawVerify(pk, kSecPaddingPKCS1,
                                 data, dataLength,
                                 sig, sigLength);

    if (status == errSecSuccess) {
        if (errPtr) *errPtr = nil;
        return YES;
    }
    // else...
    if (errPtr) *errPtr = [NSError errorWithDomain:@"SecKeyError" code:status userInfo:nil];
    return NO;
}

- (NSData *) encryptData:(NSData *)plainText error:(NSError **)errPtr {
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM;
    SecKeyRef publicKey = [self lookupPublicKeyRef];
    BOOL canEncrypt = publicKey && SecKeyIsAlgorithmSupported(publicKey,
                                                              kSecKeyOperationTypeEncrypt,
                                                              algorithm);
    if (!canEncrypt) {
        if (errPtr)
            *errPtr = [NSError errorWithDomain:@"SecKeyDomain Unsupported or Key Not Found" code:-50 userInfo:nil];
        return nil;
    }
    CFErrorRef error = NULL;
    NSData *cipherText = (NSData*)CFBridgingRelease(      // ARC takes ownership
                                                    SecKeyCreateEncryptedData(publicKey,
                                                                              algorithm,
                                                                              (__bridge CFDataRef)plainText,
                                                                              &error));
    if (!cipherText) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        if (errPtr) *errPtr = err;
        return nil;
    }
    if (errPtr) *errPtr = nil;
    return cipherText;
}

- (void) decryptData:(NSData *)cypherText completion:(void (^)(NSData *,NSError *))completion {
    __weak KeyInterface *weakSelf = self;
    dispatch_async(dispatch_get_main_queue(), ^{
        SecKeyAlgorithm algorithm = kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM;
        SecKeyRef privateKey = [weakSelf lookupPrivateKeyRef];
        BOOL canDec = privateKey && SecKeyIsAlgorithmSupported(privateKey,
                                                               kSecKeyOperationTypeDecrypt,
                                                               algorithm);
        if (!canDec) {
            if (completion)
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(nil, [NSError errorWithDomain:@"SecKeyDomain Unsupported or Key Not Found" code:-50 userInfo:nil]);
                });
            return;
        }
        CFErrorRef error = NULL;
        NSData *plainText = (NSData*)CFBridgingRelease(      // ARC takes ownership
                                                        SecKeyCreateDecryptedData(privateKey,
                                                                                  algorithm,
                                                                                  (__bridge CFDataRef)cypherText,
                                                                                  &error));
        if (!plainText) {
            NSError *err = CFBridgingRelease(error);  // ARC takes ownership
            if (completion)
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion(nil, err);
                });
            return;
        }
        if (completion)
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(plainText, nil);
            });
    });
}

@end

