/*
 * QRCodeReader
 *
 * Copyright 2014-present Yannick Loriot.
 * http://yannickloriot.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#import <Foundation/Foundation.h>
#import <AVFoundation/AVFoundation.h>
#import <UIKit/UIKit.h>

/**
 * Reader object base on the `AVCaptureDevice` to read / scan 1D and 2D codes.
 */
@interface QRCodeReader : NSObject

#pragma mark - Creating and Inializing QRCode Readers
/** @name Creating and Inializing QRCode Readers */

/**
 * @abstract Initializes a reader with the `QRCode` metadata object type.
 * @since 4.1.0
 */
- (nonnull id)init;

/**
 * @abstract Initializes a reader with a list of metadata object types.
 * @param metadataObjectTypes An array of strings identifying the types of
 * metadata objects to process.
 * @since 3.0.0
 */
- (nonnull id)initWithMetadataObjectTypes:(nonnull NSArray *)metadataObjectTypes;

/**
 * @abstract Creates a reader with a list of metadata object types.
 * @param metadataObjectTypes An array of strings identifying the types of
 * metadata objects to process.
 * @see initWithMetadataObjectTypes:
 * @since 3.0.0
 */
+ (nonnull instancetype)readerWithMetadataObjectTypes:(nonnull NSArray *)metadataObjectTypes;

#pragma mark - Checking the Reader Availabilities
/** @name Checking the Reader Availabilities */

/**
 * @abstract Returns whether the reader is available with the current device.
 * @return a Boolean value indicating whether the reader is available.
 * @since 3.0.0
 */
+ (BOOL)isAvailable;

/**
 * @abstract Checks and return whether the given metadata object types are
 * supported by the current device.
 * @return a Boolean value indicating whether the given metadata object types
 * are supported by the current device.
 * @since 3.2.0
 */
+ (BOOL)supportsMetadataObjectTypes:(nonnull NSArray *)metadataObjectTypes;

#pragma mark - Checking the Metadata Items Types
/** @name Checking the Metadata Items Types */

/**
 * @abstract An array of strings identifying the types of metadata objects to
 * process.
 * @since 3.0.0
 */
@property (strong, nonatomic, readonly) NSArray * _Nonnull metadataObjectTypes;

#pragma mark - Viewing the Camera
/** @name Viewing the Camera */

/**
 * @abstract CALayer that you use to display video as it is being captured
 * by an input device.
 * @since 3.0.0
 */
@property (strong, nonatomic, readonly) AVCaptureVideoPreviewLayer * _Nonnull previewLayer;

#pragma mark - Controlling the Reader
/** @name Controlling the Reader */

/**
 * @abstract Starts scanning the codes.
 * @since 3.0.0
 */
- (void)startScanning;

/**
 * @abstract Stops scanning the codes.
 * @since 3.0.0
 */
- (void)stopScanning;

/**
 * @abstract Indicates whether the session is currently running.
 * @discussion The value of this property is a Bool indicating whether the
 * receiver is running.
 * Clients can key value observe the value of this property to be notified
 * when the session automatically starts or stops running.
 * @since 3.3.0
 */
- (BOOL)running;

/**
 * @abstract Switch between the back and the front camera.
 * @since 3.0.0
 */
- (void)switchDeviceInput;

/**
 * @abstract Returns true whether a front device is available.
 * @return true whether a front device is available.
 * @since 3.0.0
 */
- (BOOL)hasFrontDevice;

/**
 * @abstract Returns true whether a torch is available.
 * @return true if a torch is available.
 * @since 4.0.0
 */
- (BOOL)isTorchAvailable;

/**
 * @abstract Toggles torch on the default device.
 * @since 4.0.0
 */
- (void)toggleTorch;

#pragma mark - Getting Inputs and Outputs
/** @name Getting Inputs and Outputs */

/**
 * @abstract Accessing to the `AVCaptureDeviceInput` object representing 
 * the default device input (generally the back camera).
 * @since 3.5.0
 */
@property (readonly) AVCaptureDeviceInput * _Nonnull defaultDeviceInput;

/**
 * @abstract Accessing to the `AVCaptureDeviceInput` object representing
 * the front device input.
 * @since 3.5.0
 */
@property (readonly) AVCaptureDeviceInput * _Nullable frontDeviceInput;

/**
 * @abstract Accessing to the `AVCaptureMetadataOutput` object.
 * @discussion It allows you to configure the scanner to restrict the area of
 * the scan to the overlay one for example.
 * @since 3.5.0
 */
@property (readonly) AVCaptureMetadataOutput * _Nonnull metadataOutput;

#pragma mark - Managing the Orientation
/** @name Managing the Orientation */

/**
 * @abstract Returns the video orientation correspongind to the given interface
 * orientation.
 * @param interfaceOrientation An interface orientation.
 * @return the video orientation correspongind to the given device orientation.
 * @since 3.1.0
 */
+ (AVCaptureVideoOrientation)videoOrientationFromInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation;

#pragma mark - Managing the Block
/** @name Managing the Block */

/**
 * @abstract Sets the completion with a block that executes when a QRCode
 * or when the user did stopped the scan.
 * @param completionBlock The block to be executed. This block has no
 * return value and takes one argument: the `resultAsString`. If the user
 * stop the scan and that there is no response the `resultAsString` argument
 * is nil.
 * @since 3.0.0
 */
- (void)setCompletionWithBlock:(nullable void (^) (NSString * _Nullable resultAsString))completionBlock;

@end
