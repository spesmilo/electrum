//
//  AppDelegate.m
//  CalinsQRReader
//
//  Created by calin on 11/25/18.
//  Copyright © 2018 Calin Culianu <calin.culianu@gmail.com>. MIT License.
//

#import "AppDelegate.h"
#import <AVFoundation/AVFoundation.h>
#include <stdio.h>

@interface AppDelegate () <NSWindowDelegate, AVCaptureVideoDataOutputSampleBufferDelegate> {
    __strong dispatch_queue_t dispatchQueue;
}

@property (nonatomic, weak) IBOutlet NSWindow *window;
@property (nonatomic, weak) IBOutlet NSView *viewForCamera;

@property (nonatomic) BOOL isReading;
@property (nonatomic, strong) AVCaptureSession *captureSession;
@property (nonatomic, strong) AVCaptureVideoPreviewLayer *videoPreviewLayer;
@property (nonatomic, strong) CIDetector *detector;

-(BOOL)startReading;
-(void)stopReading;

-(void)windowWillClose:(NSNotification *)notification;
-(void)windowDidResize:(NSNotification *)notification;

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    self.window.level = NSFloatingWindowLevel; // make this window be rudely always on top of every other window on the desktop ;)
    [self.window makeKeyAndOrderFront:nil];
    dispatch_async(dispatch_get_main_queue(), ^{
        // this is executed later on main thread after the window finishes raising itself.
        [self startReading]; // start your engines!
    });
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    [self stopReading];
}

- (BOOL)startReading {
    NSError *error;
    self.button.hidden = YES;

#if defined(__MAC_10_14) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_10_14
    if (@available(macOS 10.14, *)) {
        // macOS 10.14 or later code path -- ask user for permission to access camera
        AVAuthorizationStatus st = [AVCaptureDevice authorizationStatusForMediaType:AVMediaTypeVideo];
        if (st == AVAuthorizationStatusRestricted) {
            self.label.stringValue = @"Camera access restricted";
            return NO;
        } else if (st != AVAuthorizationStatusAuthorized) {
            self.label.stringValue = @"Requesting camera authorization";
            [AVCaptureDevice requestAccessForMediaType:AVMediaTypeVideo completionHandler:^(BOOL granted){
                // below must be done on the main thread -- (this handler is not necessarily on the main thread)
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (!granted) {
                        self.label.stringValue = @"Camera access denied";
                    } else {
                        [self startReading];
                    }
                });
            }];
            return NO;
        }
    }
#endif

    AVCaptureDevice *captureDevice = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];

    if (captureDevice.position == AVCaptureDevicePositionBack) {
        //NSLog(@"back camera");
    } else if (captureDevice.position == AVCaptureDevicePositionFront) {
        //NSLog(@"Front Camera");
    } else {
        //NSLog(@"Unspecified, %@",captureDevice);
    }

    self.label.stringValue = @"";

    AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:captureDevice error:&error];

    if (!input) {
        NSString *errDesc = error.description;
        //NSLog(@"%@", errDesc);
        if (errDesc.length) self.label.stringValue = errDesc;
        else self.label.stringValue = @"Error initializing camera";
        return NO;
    }

    self.captureSession = [[AVCaptureSession alloc] init];
    [self.captureSession addInput:input];

    if (!dispatchQueue) {
        dispatchQueue = dispatch_queue_create("myQueue", NULL);
    }
    // add per-frame callback (see captureOutput:didOutputSampleBuffer:fromConnection method below)
    AVCaptureVideoDataOutput *vdo = [AVCaptureVideoDataOutput new];
    [vdo setSampleBufferDelegate:self queue:dispatchQueue];
    [self.captureSession addOutput:vdo];
    self.detector = [CIDetector detectorOfType:CIDetectorTypeQRCode context:nil options:nil];
    self.videoPreviewLayer = [[AVCaptureVideoPreviewLayer alloc] initWithSession:_captureSession];

    [self.videoPreviewLayer setVideoGravity:AVLayerVideoGravityResizeAspectFill];
    [self.videoPreviewLayer setFrame:self.viewForCamera.layer.bounds];
    [self.viewForCamera.layer addSublayer:self.videoPreviewLayer];

    [_captureSession startRunning];

    return YES;
}

- (void)stopReading {
    [self.captureSession stopRunning];
    self.captureSession = nil;
    [self.videoPreviewLayer removeFromSuperlayer];
    self.videoPreviewLayer = nil;
    self.detector = nil;
    dispatchQueue = nil;
    //self.button.hidden = NO; // <--- uncomment this if you want the app to read more than one QR code (if you make this a standalone app)
}

- (void)windowWillClose:(NSNotification *)notif {
    if (notif.object == self.window)
        [[NSApplication sharedApplication] terminate:self];
}
- (void)windowDidResize:(NSNotification *)notif {
    if (notif.object == self.window && self.videoPreviewLayer && self.viewForCamera) {
        [self.videoPreviewLayer setFrame:self.viewForCamera.layer.bounds];
    }
}
// This callback processes each video frame, sending it to CoreImage APIs for detecting QR Codes.
- (void)captureOutput:(AVCaptureOutput *)output didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer fromConnection:(AVCaptureConnection *)connection {
    //NSLog(@"sample buffer did output");
    CIImage *img = [CIImage imageWithCVImageBuffer:CMSampleBufferGetImageBuffer(sampleBuffer)];
    NSArray <CIFeature *> *features = [self.detector featuresInImage:img];
    for (CIFeature *f in features) {
        if ([f.type isEqualToString:CIFeatureTypeQRCode]) {
            //NSLog(@"Feature %@ at %f,%f,%f,%f",f.type, f.bounds.origin.x, f.bounds.origin.y, f.bounds.size.width, f.bounds.size.height);
            CIQRCodeFeature *qr = (CIQRCodeFeature *)f;
            //NSLog(@"Message: %@", qr.messageString);
            NSString *msg = qr.messageString;
            // the below must be done on the main thread because it touches the GUI!
            dispatch_sync(dispatch_get_main_queue(), ^{
                printf("%s\n",[msg UTF8String]); // tell calling process what the QR code is.
                self.label.stringValue = msg;
                [self stopReading];
                [self.window close]; // this will trigger an app exit in windowWillClose: above. Comment this out if you want this app to be a standalone app.
            });
            return;
        }
    }
}

- (IBAction) onButton:(id)sender {
    [self startReading];
}

- (IBAction) showAbout:(id)sender {
    // this method isn't normally reached becasue we run as a background app -- but if we were to
    // change Info.plist to make this a foreground app, then this could potentially be executed.
    NSApplication *app = NSApplication.sharedApplication;
    [app orderFrontStandardAboutPanel:sender];
    NSArray<NSWindow *> *windows = app.windows;
    for (NSWindow *w in windows) {
        if (w != self.window) {
            // about panel .. make sure it's on top.
            w.level = self.window.level + 1;
            [w orderFront:sender];
        }
    }
}
@end
