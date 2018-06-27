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

#import "QRCodeReader.h"

@interface QRCodeReader () <AVCaptureMetadataOutputObjectsDelegate>
@property (strong, nonatomic) AVCaptureDevice            *defaultDevice;
@property (strong, nonatomic) AVCaptureDeviceInput       *defaultDeviceInput;
@property (strong, nonatomic) AVCaptureDevice            *frontDevice;
@property (strong, nonatomic) AVCaptureDeviceInput       *frontDeviceInput;
@property (strong, nonatomic) AVCaptureMetadataOutput    *metadataOutput;
@property (strong, nonatomic) AVCaptureSession           *session;
@property (strong, nonatomic) AVCaptureVideoPreviewLayer *previewLayer;

@property (copy, nonatomic) void (^completionBlock) (NSString *);

@end

@implementation QRCodeReader

- (id)init
{
  if ((self = [super init])) {
    _metadataObjectTypes = @[AVMetadataObjectTypeQRCode];

    [self setupAVComponents];
    [self configureDefaultComponents];
  }
  return self;
}

- (id)initWithMetadataObjectTypes:(NSArray *)metadataObjectTypes
{
  if ((self = [super init])) {
    _metadataObjectTypes = metadataObjectTypes;

    [self setupAVComponents];
    [self configureDefaultComponents];
  }
  return self;
}

+ (instancetype)readerWithMetadataObjectTypes:(NSArray *)metadataObjectTypes
{
  return [[self alloc] initWithMetadataObjectTypes:metadataObjectTypes];
}

#pragma mark - Initializing the AV Components

- (void)setupAVComponents
{
  self.defaultDevice = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];

  if (_defaultDevice) {
    self.defaultDeviceInput = [AVCaptureDeviceInput deviceInputWithDevice:_defaultDevice error:nil];
    self.metadataOutput     = [[AVCaptureMetadataOutput alloc] init];
    self.session            = [[AVCaptureSession alloc] init];
    self.previewLayer       = [AVCaptureVideoPreviewLayer layerWithSession:self.session];

#if !defined(__IPHONE_OS_VERSION_MIN_REQUIRED) || __IPHONE_OS_VERSION_MIN_REQUIRED < 100000
      // before iOS 10.0, this was the way
    for (AVCaptureDevice *device in [AVCaptureDevice devicesWithMediaType:AVMediaTypeVideo]) {
      if (device.position == AVCaptureDevicePositionFront) {
        self.frontDevice = device;
      }
    }
#else
   // iOS 10+ method..
    NSArray<AVCaptureDeviceType> *types = @[
                                              AVCaptureDeviceTypeBuiltInWideAngleCamera,
                                              AVCaptureDeviceTypeBuiltInTelephotoCamera,
                                              AVCaptureDeviceTypeBuiltInDualCamera
                                              ];
    AVCaptureDeviceDiscoverySession *session = [AVCaptureDeviceDiscoverySession discoverySessionWithDeviceTypes:types mediaType:AVMediaTypeVideo position:AVCaptureDevicePositionFront];
    NSArray<AVCaptureDevice *> *devices = session.devices;
    for (AVCaptureDevice *device in devices) {
        if (device.position == AVCaptureDevicePositionFront) {
            self.frontDevice = device;
        }
    }
#endif

    if (_frontDevice) {
      self.frontDeviceInput = [AVCaptureDeviceInput deviceInputWithDevice:_frontDevice error:nil];
    }
  }
}

- (void)configureDefaultComponents
{
  [_session addOutput:_metadataOutput];

  if (_defaultDeviceInput) {
    [_session addInput:_defaultDeviceInput];
  }

  [_metadataOutput setMetadataObjectsDelegate:self queue:dispatch_get_main_queue()];
  NSMutableSet *available = [NSMutableSet setWithArray:[_metadataOutput availableMetadataObjectTypes]];
  NSSet *desired = [NSSet setWithArray:_metadataObjectTypes];
  [available intersectSet:desired];
  [_metadataOutput setMetadataObjectTypes:available.allObjects];
  [_previewLayer setVideoGravity:AVLayerVideoGravityResizeAspectFill];
}

- (void)switchDeviceInput
{
  if (_frontDeviceInput) {
    [_session beginConfiguration];

    AVCaptureDeviceInput *currentInput = [_session.inputs firstObject];
    [_session removeInput:currentInput];

    AVCaptureDeviceInput *newDeviceInput = (currentInput.device.position == AVCaptureDevicePositionFront) ? _defaultDeviceInput : _frontDeviceInput;
    [_session addInput:newDeviceInput];

    [_session commitConfiguration];
  }
}

- (BOOL)hasFrontDevice
{
  return _frontDevice != nil;
}

- (BOOL)isTorchAvailable
{
  return _defaultDevice.hasTorch;
}

- (void)toggleTorch
{
  NSError *error = nil;

  [_defaultDevice lockForConfiguration:&error];

  if (error == nil) {
    AVCaptureTorchMode mode = _defaultDevice.torchMode;

    _defaultDevice.torchMode = mode == AVCaptureTorchModeOn ? AVCaptureTorchModeOff : AVCaptureTorchModeOn;
  }
  
  [_defaultDevice unlockForConfiguration];
}

#pragma mark - Controlling Reader

- (void)startScanning
{
  if (![self.session isRunning]) {
    [self.session startRunning];
  }
}

- (void)stopScanning
{
  if ([self.session isRunning]) {
    [self.session stopRunning];
  }
}

- (BOOL)running {
  return self.session.running;
}

#pragma mark - Managing the Orientation

+ (AVCaptureVideoOrientation)videoOrientationFromInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
  switch (interfaceOrientation) {
    case UIInterfaceOrientationLandscapeLeft:
      return AVCaptureVideoOrientationLandscapeLeft;
    case UIInterfaceOrientationLandscapeRight:
      return AVCaptureVideoOrientationLandscapeRight;
    case UIInterfaceOrientationPortrait:
      return AVCaptureVideoOrientationPortrait;
    default:
      return AVCaptureVideoOrientationPortraitUpsideDown;
  }
}

#pragma mark - Checking the Reader Availabilities

+ (BOOL)isAvailable
{
  @autoreleasepool {
    AVCaptureDevice *captureDevice = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];

    if (!captureDevice) {
      return NO;
    }

    NSError *error;
    AVCaptureDeviceInput *deviceInput = [AVCaptureDeviceInput deviceInputWithDevice:captureDevice error:&error];

    if (!deviceInput || error) {
      return NO;
    }

    return YES;
  }
}

+ (BOOL)supportsMetadataObjectTypes:(NSArray *)metadataObjectTypes
{
  if (![self isAvailable]) {
    return NO;
  }

  @autoreleasepool {
    // Setup components
    AVCaptureDevice *captureDevice    = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
    AVCaptureDeviceInput *deviceInput = [AVCaptureDeviceInput deviceInputWithDevice:captureDevice error:nil];
    AVCaptureMetadataOutput *output   = [[AVCaptureMetadataOutput alloc] init];
    AVCaptureSession *session         = [[AVCaptureSession alloc] init];

    [session addInput:deviceInput];
    [session addOutput:output];

    if (metadataObjectTypes == nil || metadataObjectTypes.count == 0) {
      // Check the QRCode metadata object type by default
      metadataObjectTypes = @[AVMetadataObjectTypeQRCode];
    }

    for (NSString *metadataObjectType in metadataObjectTypes) {
      if (![output.availableMetadataObjectTypes containsObject:metadataObjectType]) {
        return NO;
      }
    }

    return YES;
  }
}

#pragma mark - Managing the Block

- (void)setCompletionWithBlock:(void (^) (NSString *resultAsString))completionBlock
{
  self.completionBlock = completionBlock;
}

#pragma mark - AVCaptureMetadataOutputObjects Delegate Methods

- (void)captureOutput:(AVCaptureOutput *)captureOutput didOutputMetadataObjects:(NSArray *)metadataObjects fromConnection:(AVCaptureConnection *)connection
{
  for (AVMetadataObject *current in metadataObjects) {
    if ([current isKindOfClass:[AVMetadataMachineReadableCodeObject class]]
        && [_metadataObjectTypes containsObject:current.type]) {
      NSString *scannedResult = [(AVMetadataMachineReadableCodeObject *)current stringValue];

      if (_completionBlock) {
        _completionBlock(scannedResult);
      }

      break;
    }
  }
}

@end
