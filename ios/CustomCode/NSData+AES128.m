//
//  NSData+AES128.m
//  Electron-Cash
//
//  Created by calin on 9/20/18.
//  Copyright © 2018 Calin Culianu. All rights reserved.
//
//  MIT License
#import "NSData+AES128.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (AES128)

- (NSData *)AES128EncryptWithKey:(NSData * __nonnull)key initializationVector:(NSData * __nullable)iv {
    const size_t keyLength = key.length;
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        // 'key' should be 16 bytes for AES128
        NSLog(@"AES128EncryptWithKey: key must be exactly 16,24, or 32 bytes! (got: %d)",(int)keyLength);
        return nil;
    }
    if (iv && iv.length != 16) {
        // 'iv' should be 16 bytes for AES128
        NSLog(@"AES128EncryptWithKey: initializationVector must be exactly 16 bytes!");
        return nil;
    }
    const size_t dataLength = self.length;
    if (!dataLength) {
        return self;
    }
    NSData *data = self;

    const void *keyPtr = key.bytes;

    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, keyLength,
                                          iv.bytes /* initialization vector (optional) */,
                                          data.bytes, dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    NSLog(@"AES128EncryptWithKey: unspecified error (%d)",(int)cryptStatus);
    free(buffer); //free the buffer;
    return nil;
}

- (NSData *)AES128DecryptWithKey:(NSData * __nonnull)key initializationVector:(NSData * __nullable)iv keepPadding:(BOOL)keepPadding {
    const size_t keyLength = key.length;
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        // 'key' should be 16 bytes for AES128
        NSLog(@"AES128DecryptWithKey: key must be exactly 16, 24, or 32 bytes! (got: %d)",(int)key.length);
        return nil;
    }
    if (iv && iv.length != 16) {
        // 'iv' should be 16 bytes for AES128
        NSLog(@"AES128DecryptWithKey: initializationVector must be exactly 16 bytes!");
        return nil;
    }
    const size_t cypherLength = self.length;
    if (!cypherLength) {
        return self;
    }
    NSData *cypherText = self;

    const void *keyPtr = key.bytes;

    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize = cypherLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);

    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, keepPadding ? 0 : kCCOptionPKCS7Padding,
                                          keyPtr, keyLength,
                                          iv.bytes /* initialization vector (optional) */,
                                          cypherText.bytes, cypherLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);

    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    NSLog(@"AES128DecryptWithKey: unspecified error (%d)",(int)cryptStatus);
    free(buffer); //free the buffer;
    return nil;
}

- (NSData *)AES128DecryptWithKey:(NSData * __nonnull)key initializationVector:(NSData * __nullable)iv {
    return [self AES128DecryptWithKey:key initializationVector:iv keepPadding:NO];
}

@end
