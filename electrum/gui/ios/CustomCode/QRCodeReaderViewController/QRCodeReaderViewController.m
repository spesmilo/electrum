/*
 * QRCodeReaderViewController
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

#import "QRCodeReaderViewController.h"
#import "QRCameraSwitchButton.h"
#import "QRCodeReaderView.h"
#import "QRToggleTorchButton.h"

@interface QRCodeReaderViewController ()
@property (strong, nonatomic) QRCameraSwitchButton *switchCameraButton;
@property (strong, nonatomic) QRToggleTorchButton *toggleTorchButton;
@property (strong, nonatomic) QRCodeReaderView     *cameraView;
@property (strong, nonatomic) UIButton             *cancelButton;
@property (strong, nonatomic) QRCodeReader         *codeReader;
@property (assign, nonatomic) BOOL                 startScanningAtLoad;
@property (assign, nonatomic) BOOL                 showSwitchCameraButton;
@property (assign, nonatomic) BOOL                 showTorchButton;

@property (copy, nonatomic) void (^completionBlock) (NSString * __nullable);

@end

@implementation QRCodeReaderViewController

- (void)dealloc
{
  [self stopScanning];

  [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (id)init
{
  return [self initWithCancelButtonTitle:nil];
}

- (id)initWithCancelButtonTitle:(NSString *)cancelTitle
{
  return [self initWithCancelButtonTitle:cancelTitle metadataObjectTypes:@[AVMetadataObjectTypeQRCode]];
}

- (id)initWithMetadataObjectTypes:(NSArray *)metadataObjectTypes
{
  return [self initWithCancelButtonTitle:nil metadataObjectTypes:metadataObjectTypes];
}

- (id)initWithCancelButtonTitle:(NSString *)cancelTitle metadataObjectTypes:(NSArray *)metadataObjectTypes
{
  QRCodeReader *reader = [QRCodeReader readerWithMetadataObjectTypes:metadataObjectTypes];

  return [self initWithCancelButtonTitle:cancelTitle codeReader:reader];
}

- (id)initWithCancelButtonTitle:(NSString *)cancelTitle codeReader:(QRCodeReader *)codeReader
{
  return [self initWithCancelButtonTitle:cancelTitle codeReader:codeReader startScanningAtLoad:true];
}

- (id)initWithCancelButtonTitle:(NSString *)cancelTitle codeReader:(QRCodeReader *)codeReader startScanningAtLoad:(BOOL)startScanningAtLoad
{
  return [self initWithCancelButtonTitle:cancelTitle codeReader:codeReader startScanningAtLoad:startScanningAtLoad showSwitchCameraButton:YES showTorchButton:NO];
}

- (id)initWithCancelButtonTitle:(nullable NSString *)cancelTitle codeReader:(nonnull QRCodeReader *)codeReader startScanningAtLoad:(BOOL)startScanningAtLoad showSwitchCameraButton:(BOOL)showSwitchCameraButton showTorchButton:(BOOL)showTorchButton
{
  if ((self = [super init])) {
    self.view.backgroundColor   = [UIColor blackColor];
    self.codeReader             = codeReader;
    self.startScanningAtLoad    = startScanningAtLoad;
    self.showSwitchCameraButton = showSwitchCameraButton;
    self.showTorchButton        = showTorchButton;

    if (cancelTitle == nil) {
      cancelTitle = NSLocalizedString(@"Cancel", @"Cancel");
    }

    [self setupUIComponentsWithCancelButtonTitle:cancelTitle];
    [self setupAutoLayoutConstraints];

    [_cameraView.layer insertSublayer:_codeReader.previewLayer atIndex:0];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(orientationChanged:) name:UIApplicationDidChangeStatusBarOrientationNotification object:nil];

    __weak __typeof__(self) weakSelf = self;

    [codeReader setCompletionWithBlock:^(NSString *resultAsString) {
      if (weakSelf.completionBlock != nil) {
        weakSelf.completionBlock(resultAsString);
      }

      if (weakSelf.delegate && [weakSelf.delegate respondsToSelector:@selector(reader:didScanResult:)]) {
        [weakSelf.delegate reader:weakSelf didScanResult:resultAsString];
      }
    }];
  }
  return self;
}

+ (instancetype)readerWithCancelButtonTitle:(NSString *)cancelTitle
{
  return [[self alloc] initWithCancelButtonTitle:cancelTitle];
}

+ (instancetype)readerWithMetadataObjectTypes:(NSArray *)metadataObjectTypes
{
  return [[self alloc] initWithMetadataObjectTypes:metadataObjectTypes];
}

+ (instancetype)readerWithCancelButtonTitle:(NSString *)cancelTitle metadataObjectTypes:(NSArray *)metadataObjectTypes
{
  return [[self alloc] initWithCancelButtonTitle:cancelTitle metadataObjectTypes:metadataObjectTypes];
}

+ (instancetype)readerWithCancelButtonTitle:(NSString *)cancelTitle codeReader:(QRCodeReader *)codeReader
{
  return [[self alloc] initWithCancelButtonTitle:cancelTitle codeReader:codeReader];
}

+ (instancetype)readerWithCancelButtonTitle:(NSString *)cancelTitle codeReader:(QRCodeReader *)codeReader startScanningAtLoad:(BOOL)startScanningAtLoad
{
  return [[self alloc] initWithCancelButtonTitle:cancelTitle codeReader:codeReader startScanningAtLoad:startScanningAtLoad];
}

+ (instancetype)readerWithCancelButtonTitle:(NSString *)cancelTitle codeReader:(QRCodeReader *)codeReader startScanningAtLoad:(BOOL)startScanningAtLoad showSwitchCameraButton:(BOOL)showSwitchCameraButton showTorchButton:(BOOL)showTorchButton
{
  return [[self alloc] initWithCancelButtonTitle:cancelTitle codeReader:codeReader startScanningAtLoad:startScanningAtLoad showSwitchCameraButton:showSwitchCameraButton showTorchButton:showTorchButton];
}

- (void)viewWillAppear:(BOOL)animated
{
  [super viewWillAppear:animated];

  if (_startScanningAtLoad) {
    [self startScanning];
  }
}

- (void)viewWillDisappear:(BOOL)animated
{
  [self stopScanning];

  [super viewWillDisappear:animated];
}

- (void)viewWillLayoutSubviews
{
  [super viewWillLayoutSubviews];

  _codeReader.previewLayer.frame = self.view.bounds;
}

- (BOOL)shouldAutorotate
{
  return YES;
}

#pragma mark - Controlling the Reader

- (void)startScanning {
  [_codeReader startScanning];
}

- (void)stopScanning {
  [_codeReader stopScanning];
}

#pragma mark - Managing the Orientation

- (void)orientationChanged:(NSNotification *)notification
{
  [_cameraView setNeedsDisplay];

  if (_codeReader.previewLayer.connection.isVideoOrientationSupported) {
    UIInterfaceOrientation orientation = [[UIApplication sharedApplication] statusBarOrientation];

    _codeReader.previewLayer.connection.videoOrientation = [QRCodeReader videoOrientationFromInterfaceOrientation:
                                                            orientation];
  }
}

#pragma mark - Managing the Block

- (void)setCompletionWithBlock:(void (^) (NSString *resultAsString))completionBlock
{
  self.completionBlock = completionBlock;
}

#pragma mark - Initializing the AV Components

- (void)setupUIComponentsWithCancelButtonTitle:(NSString *)cancelButtonTitle
{
  self.cameraView                                       = [[QRCodeReaderView alloc] init];
  _cameraView.translatesAutoresizingMaskIntoConstraints = NO;
  _cameraView.clipsToBounds                             = YES;
  [self.view addSubview:_cameraView];

  [_codeReader.previewLayer setFrame:CGRectMake(0, 0, self.view.frame.size.width, self.view.frame.size.height)];

  if ([_codeReader.previewLayer.connection isVideoOrientationSupported]) {
    UIInterfaceOrientation orientation = [[UIApplication sharedApplication] statusBarOrientation];

    _codeReader.previewLayer.connection.videoOrientation = [QRCodeReader videoOrientationFromInterfaceOrientation:orientation];
  }

  if (_showSwitchCameraButton && [_codeReader hasFrontDevice]) {
    _switchCameraButton = [[QRCameraSwitchButton alloc] init];
    
    [_switchCameraButton setTranslatesAutoresizingMaskIntoConstraints:false];
    [_switchCameraButton addTarget:self action:@selector(switchCameraAction:) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_switchCameraButton];
  }

  if (_showTorchButton && [_codeReader isTorchAvailable]) {
    _toggleTorchButton = [[QRToggleTorchButton alloc] init];

    [_toggleTorchButton setTranslatesAutoresizingMaskIntoConstraints:false];
    [_toggleTorchButton addTarget:self action:@selector(toggleTorchAction:) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_toggleTorchButton];
  }

  self.cancelButton                                       = [[UIButton alloc] init];
  _cancelButton.translatesAutoresizingMaskIntoConstraints = NO;
  [_cancelButton setTitle:cancelButtonTitle forState:UIControlStateNormal];
  [_cancelButton setTitleColor:[UIColor grayColor] forState:UIControlStateHighlighted];
  [_cancelButton addTarget:self action:@selector(cancelAction:) forControlEvents:UIControlEventTouchUpInside];
  [self.view addSubview:_cancelButton];
}

- (void)setupAutoLayoutConstraints
{
    NSLayoutYAxisAnchor * topLayoutAnchor;
    NSLayoutYAxisAnchor * bottomLayoutAnchor;
    NSLayoutXAxisAnchor * leftLayoutAnchor;
    NSLayoutXAxisAnchor * rightLayoutAnchor;
/*    if (@available(iOS 11.0, *)) {
      topLayoutAnchor = self.view.safeAreaLayoutGuide.topAnchor;
      bottomLayoutAnchor = self.view.safeAreaLayoutGuide.bottomAnchor;
      leftLayoutAnchor = self.view.safeAreaLayoutGuide.leftAnchor;
      rightLayoutAnchor = self.view.safeAreaLayoutGuide.rightAnchor;
    } else {
 */
      topLayoutAnchor = self.topLayoutGuide.topAnchor;
      bottomLayoutAnchor = self.bottomLayoutGuide.bottomAnchor;
      leftLayoutAnchor = self.view.leftAnchor;
      rightLayoutAnchor = self.view.rightAnchor;
//    }
    
  NSDictionary *views = NSDictionaryOfVariableBindings(_cameraView, _cancelButton);

  [self.view addConstraints:
   [NSLayoutConstraint constraintsWithVisualFormat:@"V:|[_cameraView][_cancelButton(40)]" options:0 metrics:nil views:views]];
  [[bottomLayoutAnchor constraintEqualToAnchor:_cancelButton.bottomAnchor] setActive:YES];
  [self.view addConstraints:
   [NSLayoutConstraint constraintsWithVisualFormat:@"H:|[_cameraView]|" options:0 metrics:nil views:views]];
  [self.view addConstraints:
   [NSLayoutConstraint constraintsWithVisualFormat:@"H:|-[_cancelButton]-|" options:0 metrics:nil views:views]];
  
  if (_switchCameraButton) {
      [NSLayoutConstraint activateConstraints:@[
          [topLayoutAnchor constraintEqualToAnchor:_switchCameraButton.topAnchor],
          [rightLayoutAnchor constraintEqualToAnchor:_switchCameraButton.rightAnchor],
          [_switchCameraButton.heightAnchor constraintEqualToConstant:50],
          [_switchCameraButton.widthAnchor constraintEqualToConstant:70]
          ]];
  }

  if (_toggleTorchButton) {
      [NSLayoutConstraint activateConstraints:@[
          [topLayoutAnchor constraintEqualToAnchor:_toggleTorchButton.topAnchor],
          [leftLayoutAnchor constraintEqualToAnchor:_toggleTorchButton.leftAnchor],
          [_toggleTorchButton.heightAnchor constraintEqualToConstant:50],
          [_toggleTorchButton.widthAnchor constraintEqualToConstant:70]
          ]];
  }
}

- (void)switchDeviceInput
{
  [_codeReader switchDeviceInput];
}

#pragma mark - Catching Button Events

- (void)cancelAction:(UIButton *)button
{
  [_codeReader stopScanning];

  if (_completionBlock) {
    _completionBlock(nil);
  }

  if (_delegate && [_delegate respondsToSelector:@selector(readerDidCancel:)]) {
    [_delegate readerDidCancel:self];
  }
}

- (void)switchCameraAction:(UIButton *)button
{
  [self switchDeviceInput];
}

- (void)toggleTorchAction:(UIButton *)button
{
  [_codeReader toggleTorch];
}

@end
