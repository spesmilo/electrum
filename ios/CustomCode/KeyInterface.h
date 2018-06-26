//
//  KeyInterface.h
//  TestKeys
//
//  Created by calin on 6/15/18.
//  Copyright © 2018 c3-soft.com. All rights reserved.
//

#ifndef KeyInterface_h
#define KeyInterface_h

#import <Foundation/Foundation.h>

@interface KeyInterface : NSObject

+ (instancetype) keyInterfaceWithPublicKeyName:(NSString *)publicKeyName privateKeyName:(NSString *)privateKeyName;

@property (nonatomic, readonly) NSString *publicKeyName, *privateKeyName;
@property (nonatomic, copy) NSString *prompt;

@property (nonatomic, readonly) BOOL publicKeyExists;
@property (nonatomic, readonly) NSData *publicKeyBits;
@property (nonatomic, readonly) BOOL biometricsAreAvailable;

- (BOOL) biometricsAreAvailableWithError:(NSError **)errPtr_null_ok;
- (void) biometricAuthWithCompletion:(void (^)(BOOL,NSError *))completion;
- (void) generateTouchIDKeyPairWithCompletion:(void (^)(BOOL, NSError *))completion;
- (BOOL) deleteKeyPair;

// asynchronously signs some data on main thread, calls completion when done or on error. Has to be asynch because it involves asking the user to auth with biometrics
- (void) generateSignatureForData:(NSData *)inputData completion:(void(^)(NSData *data, NSError *err))completion;

- (BOOL) verifySignature:(NSData *)signature forData:(NSData *)inputData error:(NSError **)errPtr_null_ok;

- (NSData *) encryptData:(NSData *)plainText error:(NSError **)errPtr_null_ok;

// this is also asynch because it asks user for auth with biometrics
- (void) decryptData:(NSData *)cypherText completion:(void (^)(NSData *,NSError *))completion;

@end

#endif /* KeyInterface_h */
