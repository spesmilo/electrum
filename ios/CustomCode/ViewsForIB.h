//
//  ViewsForIB.h
//  Electron-Cash
//
//  Created by calin on 4/7/18.
//  Copyright © 2018 Calin Culianu <calin.culianu@gmail.com>. MIT License.
//

#ifndef ViewsForIB_h
#define ViewsForIB_h

#import <UIKit/UIKit.h>
#import "DZNSegmentedControl/DZNSegmentedControl.h"
#import "UIKitExtras.h"
#import "CCActivityIndicator/CCActivityIndicator.h"
#import "KeyboardVC/KeyboardVC.h"
#import "ECTextViewDelegate/ECTextViewDelegate.h"

@interface CustomViewController : UIViewController
@end

@interface CustomNavController : UINavigationController
@end

@interface AddrConvBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *blurb, *cashTit, *cash, *legacyTit, *legacy, *addressTit;
@property (nonatomic, weak) IBOutlet UITextField *address;
@property (nonatomic, weak) IBOutlet UIButton *qrBut, *qrButShowLegacy, *qrButShowCash, *cpyCashBut, *cpyLegBut;
@property (nonatomic, weak) id qr, qrvc; /// used by python to keep a pointer to the qr code reader
@end

@interface AddrConv : AddrConvBase
// implemented in python addrconv.py
- (IBAction) onBut:(id)sender;
- (IBAction) onAddress:(id)sender;
@end

@interface NewContactBase : CustomViewController
@property (nonatomic, weak) IBOutlet UIBarButtonItem *okBut;
@property (nonatomic, weak) IBOutlet UILabel *nameTit;
@property (nonatomic, weak) IBOutlet UITextField *name;
@property (nonatomic, weak) IBOutlet UILabel *addressTit;
@property (nonatomic, weak) IBOutlet UITextField *address;
@property (nonatomic, weak) IBOutlet UIButton *qrBut;
@property (nonatomic, weak) IBOutlet UIButton *cpyAddressBut;
@property (nonatomic, weak) IBOutlet UIButton *cpyNameBut;
@end

// stub for Python -- implemented in contacts.py
@interface NewContactVC : NewContactBase
-(IBAction) onQR;
-(IBAction) onOk;
-(IBAction) onCancel;
-(IBAction) onCpy:(id)sender;
@end

// dummy stub for Interface Builder -- actual implementation is in python in amountedit.py
@interface BTCAmountEdit : UITextField
@end
// dummy stub for Interface Builder -- actual implementation is in python in amountedit.py
@interface FiatAmountEdit : BTCAmountEdit
@end
// dummy stub for Interface Builder -- actual implementation is in python in amountedit.py
@interface BTCkBEdit : BTCAmountEdit
@end

// dummy stub for Interface Builder -- actual implementation is in python in feeslider.py
@interface FeeSlider : UISlider
@end

@interface SendBase : CustomViewController
@property (nonatomic, weak) IBOutlet UIView *contentView;
@property (nonatomic, weak) IBOutlet UILabel *payToTit;
@property (nonatomic, weak) IBOutlet UITextField *payTo;
@property (nonatomic, weak) IBOutlet UIButton *qrBut;
@property (nonatomic, weak) IBOutlet UIButton *contactBut;
@property (nonatomic, weak) IBOutlet UILabel *descTit;
@property (nonatomic, weak) IBOutlet UITextView *desc;
@property (nonatomic, weak) IBOutlet UILabel *amtTit;
@property (nonatomic, weak) IBOutlet BTCAmountEdit *amt;
@property (nonatomic, weak) IBOutlet UIButton *maxBut;
@property (nonatomic, weak) IBOutlet FiatAmountEdit *fiat;
@property (nonatomic, weak) IBOutlet UILabel *feeTit;
@property (nonatomic, weak) IBOutlet UISlider *feeSlider;
@property (nonatomic, weak) IBOutlet UILabel *feeLbl;
@property (nonatomic, weak) IBOutlet BTCAmountEdit *feeTf;
@property (nonatomic, weak) IBOutlet UIBarButtonItem *clearBut;
@property (nonatomic, weak) IBOutlet UIBarButtonItem *previewBut;
@property (nonatomic, weak) IBOutlet UIButton *sendBut; // actually a subview of a UIBarButtonItem
@property (nonatomic, weak) IBOutlet UILabel *message;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *csFeeTop, *csTvHeight, *csPayToTop, *csContentHeight;
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, weak) IBOutlet UIView *bottomView, *messageView;
@property (nonatomic, strong) IBOutlet ECTextViewDelegate *descDel;
@end

@interface SendVC : SendBase
-(IBAction)onQRBut:(id)sender; // implemented in python send.py
-(IBAction)onContactBut:(id)sender; // implemented in python send.py
-(IBAction)clear; // implemented in python send.py
-(IBAction)onPreviewSendBut:(id)sender; // implemented in python send.py
-(IBAction)clearSpendFrom; // implemented in python send.py
-(IBAction)onMaxBut:(id)sender; // implemented in python send.py
@end


@interface TxDetailBase : CustomViewController
@property (nonatomic, weak) IBOutlet UIView *contentView;
@property (nonatomic, weak) IBOutlet UILabel *txTit;
@property (nonatomic, weak) IBOutlet UILabel *txHash;
@property (nonatomic, weak) IBOutlet UIView *noTxHashView;
@property (nonatomic, weak) IBOutlet UILabel *noTxHashLbl;
@property (nonatomic, weak) IBOutlet UIButton *cpyBut;
@property (nonatomic, weak) IBOutlet UIButton *qrBut;
//# Description:
@property (nonatomic, weak) IBOutlet UILabel *descTit;
@property (nonatomic, weak) IBOutlet UITextField *descTf;
//# Status:
@property (nonatomic, weak) IBOutlet UILabel *statusTit;
@property (nonatomic, weak) IBOutlet UIImageView *statusIV;
@property (nonatomic, weak) IBOutlet UILabel *statusLbl;
//# Date:
@property (nonatomic, weak) IBOutlet UILabel *dateTit;
@property (nonatomic, weak) IBOutlet UILabel *dateLbl;
//# Amount received/sent:
@property (nonatomic, weak) IBOutlet UILabel *amtTit;
@property (nonatomic, weak) IBOutlet UILabel *amtLbl;
//# Size:
@property (nonatomic, weak) IBOutlet UILabel *sizeTit;
@property (nonatomic, weak) IBOutlet UILabel *sizeLbl;
//# Fee:
@property (nonatomic, weak) IBOutlet UILabel *feeTit;
@property (nonatomic, weak) IBOutlet UILabel *feeLbl;
//# Locktime:
@property (nonatomic, weak) IBOutlet UILabel *lockTit;
@property (nonatomic, weak) IBOutlet UILabel *lockLbl;
@property (nonatomic, weak) IBOutlet UILabel *schnorrLbl;
//# Inputs
@property (nonatomic, weak) IBOutlet UITableView *inputsTV;
//# Outputs
@property (nonatomic, weak) IBOutlet UITableView *outputsTV;

@property (nonatomic, weak) IBOutlet NSLayoutConstraint *inputsTVHeightCS, *outputsTVHeightCS, *contentViewHeightCS;
@property (nonatomic, strong) IBOutlet NSLayoutConstraint *statusTopCSRelated, *statusTopCSUnrelated;
@property (nonatomic) CGFloat maxTVHeight;
@property (nonatomic, weak) IBOutlet UIView *bottomView;
@property (nonatomic, weak) IBOutlet UIButton *bottomBut;

@end

@interface TxDetail : TxDetailBase
- (IBAction) onCpyBut:(id)sender; // overridden in TxDetail (python)
- (IBAction) onQRBut:(id)sender; // overridden in TxDetail (python)
- (IBAction) onSign;
- (IBAction) onBroadcast;
@end

@interface TxInputsOutputsTVCBase : NSObject
@property (nonatomic, weak) TxDetailBase *txDetailVC; // the TxDetail that is holding us
@end

@interface WalletsNavBase : UINavigationController
@property (nonatomic, weak) IBOutlet UITabBarItem *tabBarItem; // contains the 'Wallets' title
@end

typedef NS_ENUM(NSInteger, WalletsStatusMode) {
    WalletsStatusOffline = 0,
    WalletsStatusOnline = 1,
    WalletsStatusDownloadingHeaders = 2,
    WalletsStatusSynchronizing = 3,
    WalletsStatusLagging = 4
};

@class WalletsDrawerVC;
@class TxHistoryHelper;
@class ReqTVD;

@interface WalletsVCBase : UIViewController
@property (nonatomic,assign) WalletsStatusMode status;
@property (nonatomic,copy) NSString *statusExtraInfo;
@property (nonatomic,weak) IBOutlet UILabel *statusLabel;
@property (nonatomic,weak) IBOutlet UILabel *statusBlurb;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *statusLabelWidthCS;

#pragma mark Top Nav Bar related
@property (nonatomic, weak) IBOutlet UINavigationBar *navBar;
@property (nonatomic, weak) IBOutlet UIView *blueBarTop;

#pragma mark Drawer Related
@property (nonatomic, weak) IBOutlet WalletsDrawerVC *modalDrawerVC;
@property (nonatomic, weak) IBOutlet UILabel *walletName, *walletAmount, *walletUnits;

#pragma mark Main View Area Related
@property (nonatomic, weak) IBOutlet DZNSegmentedControl *segControl;
@property (nonatomic, strong) IBOutlet TxHistoryHelper *txsHelper; ///< txsHelper.tv is the tableView
@property (nonatomic, strong) IBOutlet ReqTVD *reqTVD; ///< reqstv is the tableView
@property (nonatomic, weak) IBOutlet UITableView *reqstv;
@property (nonatomic, weak) IBOutlet UIView *noTXsView; ///< displays a message and shows an image when the txsHelper.tv table is empty
@property (nonatomic, weak) IBOutlet UIView *noReqsView; ///< displays a message and shows an image when the reqstv table is empty
@property (nonatomic, weak) IBOutlet UIButton *sendBut;
@property (nonatomic, weak) IBOutlet UIButton *receiveBut;
@property (nonatomic, weak) IBOutlet UILabel *noTXsLabel, *noReqsLabel; ///< here for i18n
@end

// stub to represent python -- implemented in python wallets.py
@interface WalletsVC : WalletsVCBase
-(IBAction)toggleDrawer; // declared here for IB, implemented in python wallets.py
-(IBAction)didChangeSegment:(DZNSegmentedControl *)control; // implemented in python wallets.py
-(IBAction)onSendBut;
-(IBAction)onReceiveBut;
-(IBAction)onTopNavTap;
@end
// stub to represent python -- implemented in python wallets.py
@interface WalletsNav : WalletsNavBase
@end
@interface WalletsDrawerVCBase : UIViewController
@property (nonatomic, weak) IBOutlet WalletsVC *vc; // parent viewcontroller that presented us
@property (nonatomic, weak) IBOutlet UIImageView *chevron;
@property (nonatomic, weak) IBOutlet UILabel *name, *amount, *units; // top labels
@property (nonatomic, weak) IBOutlet UIView *drawer; // the wallet 'drawer' dropdown
@property (nonatomic, weak) IBOutlet UIView *drawerBottom; // the wallet 'drawer' dropdown's bottom (sometimes hidden) area
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *drawerHeight;
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, strong) IBOutlet UIView *tableHeader, *tableFooter;
@property (nonatomic, weak) IBOutlet UILabel *addNewWalletLabel; // a pointer to the "Add new Wallet" label inside tableFooter. Here so we can translate it in the UI.
@property (nonatomic, assign) BOOL isOpen;
-(void)openAnimated:(BOOL)animated;
-(void)closeAnimated:(BOOL)animated;
@end
// stub to represent python -- implemented in python wallets.py
@interface WalletsDrawerVC : WalletsDrawerVCBase
-(IBAction)addWallet;
@end

@interface TxHistoryHelperBase : NSObject
@property (nonatomic, weak) IBOutlet UIViewController *vc;
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, assign) BOOL compactMode;
@end
// stub to represent python -- implemented in python wallets.py
@interface TxHistoryHelper : TxHistoryHelperBase
@end

@interface TxHistoryCell : UITableViewCell
@property (nonatomic, weak) IBOutlet UIImageView *icon;
@property (nonatomic, weak) IBOutlet UILabel *amountTit;
@property (nonatomic, weak) IBOutlet UILabel *amount;
@property (nonatomic, weak) IBOutlet UILabel *balanceTit;
@property (nonatomic, weak) IBOutlet UILabel *balance;
@property (nonatomic, weak) IBOutlet UILabel *date;
@property (nonatomic, weak) IBOutlet UILabel *desc;
@property (nonatomic, weak) IBOutlet UILabel *statusTit;
@property (nonatomic, weak) IBOutlet UIImageView *statusIcon;
@property (nonatomic, weak) IBOutlet UILabel *status;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *amtTitCS;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *amtCS;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *dateCS;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *descCS;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *dateWidthCS;
@end

@interface ReqTVDBase : NSObject
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, weak) IBOutlet UIViewController *vc;
@end

// stub to represent python -- implemented in python receive.py
@interface ReqTVD : ReqTVDBase
@end


@interface RequestListCell : UITableViewCell
@property (nonatomic, weak) IBOutlet UILabel *addressTit;
@property (nonatomic, weak) IBOutlet UILabel *address;
@property (nonatomic, weak) IBOutlet UILabel *amountTit;
@property (nonatomic, weak) IBOutlet UILabel *amount;
@property (nonatomic, weak) IBOutlet UILabel *statusTit;
@property (nonatomic, weak) IBOutlet UILabel *status;
@property (nonatomic, weak) IBOutlet UILabel *date;
@property (nonatomic, weak) IBOutlet UILabel *desc;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *addressTitCS;
@property (nonatomic, weak) IBOutlet UIImageView *chevron;
@end

@interface ContactsVCBase : CustomViewController
@property (nonatomic, weak) IBOutlet UIView *noContacts;
@property (nonatomic, weak) IBOutlet UILabel *noContactsLabel;
@property (nonatomic, weak) IBOutlet UIButton *butBottom;
@property (nonatomic, weak) IBOutlet UIRefreshControl *refreshControl; // bound in python
@property (nonatomic, weak) IBOutlet UITableView *tv;
@end

// stub to represent python -- implemented in python contacts.py
@interface ContactsVC : ContactsVCBase
-(IBAction) onAddBut;
@end

@interface ContactsCell : UITableViewCell
@property (nonatomic, weak) IBOutlet UIImageView *customAccessory;
@property (nonatomic, weak) IBOutlet UILabel *name;
@property (nonatomic, weak) IBOutlet LinkLabel *address;
@property (nonatomic, weak) IBOutlet UILabel *numTxs;
@end

@interface ContactDetailVCBase: CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *name;
@property (nonatomic, weak) IBOutlet UIImageView *qr;
@property (nonatomic, weak) IBOutlet UILabel *address;
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, weak) IBOutlet UIButton *payToBut;
@property (nonatomic, weak) TxHistoryHelper *helper;
@end

// stub for python -- implemented in contacts.py
@interface ContactDetailVC : ContactDetailVCBase
- (IBAction) onPayTo;
- (IBAction) cpyAddressToClipboard;
- (IBAction) cpyNameToClipboard;
- (IBAction) onQRImgTap;
@end

@interface AddressesVCBase : CustomViewController
@property (nonatomic, weak) IBOutlet UIView *topComboProxyL, *topComboProxyR;
@property (nonatomic, weak) IBOutlet UILabel *topLblL, *topLblR;
@property (nonatomic, weak) IBOutlet UITableView *tableView;
@end

// stub for python -- implemented in addresses.py
@interface AddressesVC : AddressesVCBase
- (IBAction) onTapComboProxyL;
- (IBAction) onTapComboProxyR;
- (IBAction) onTapAddress:(UIGestureRecognizer *)gr;
@end

@interface AddressesCell : UITableViewCell
@property (nonatomic, weak) IBOutlet LinkLabel *address;
@property (nonatomic, weak) IBOutlet UILabel *index, *balanceTit, *balance, *flags, *desc;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *topCS, *midCS;
@end

@interface AddressDetailBase : CustomViewController
@property (nonatomic, strong) IBOutlet ECTextViewDelegate *descDel;
@property (nonatomic, weak) UIBarButtonItem *optionsBarBut;
@property (nonatomic, weak) IBOutlet UIImageView *qr;
@property (nonatomic, weak) IBOutlet UILabel *address, *balanceTit, *balance, *fiatBalance, *statusTit, *status, *descTit, *numTxTit, *numTx;
@property (nonatomic, weak) IBOutlet UITextView *desc;
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, weak) IBOutlet UIButton *freezeBut, *spendFromBut; // set .selected=YES/NO for checked/unchecked
@property (nonatomic, weak) IBOutlet UIGestureRecognizer *utxoGr; // enabled when they have nonzero utxos
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *txHistoryTopCS, *statusTopCS, *contentHeightCS;
@property (nonatomic) CGFloat txHistoryTopSaved, statusTopSaved;
@end

// stub for python -- implemented in addresses.py
@interface AddressDetail : AddressDetailBase
- (IBAction) toggleFreezeAddress;
- (IBAction) cpyAddress;
- (void) onOptions;
- (IBAction) onSpendFrom;
- (IBAction) onUTXOs;
- (IBAction) onQRImgTap;
@end

@interface CoinsCellSelectedBackgroundView : UIView
@property (nonatomic, weak) IBOutlet UIView *blueView;
@property (nonatomic, weak) IBOutlet UIButton *selBut;
@end

@interface CoinsCell : UITableViewCell
@property (nonatomic, weak) IBOutlet LinkLabel *address;
@property (nonatomic, weak) IBOutlet UILabel *utxo, *amount, *height, *desc, *flags;
@property (nonatomic, weak) IBOutlet UILabel *amountTit, *utxoTit, *heightTit;
@property (nonatomic, weak) IBOutlet UIView *accessoryFlashView;
@property (nonatomic) BOOL chevronHidden; // defaults to NO. If YES cell will re-layout itself
@property (nonatomic) BOOL buttonSelected; // defaults to NO. If YES, button will have a checkmark and will be in the 'selected' state
@property (nonatomic) BOOL buttonEnabled; // defaults to YES. If YES, button will send events and select itself on tap. If NO, it will be grayed out
@property (nonatomic, copy) void(^onButton)(CoinsCell *cell); // set this block to define a callback for when the button is tapped due to user interaction. Not called if buttonSelected = YES is set programmatically!
@property (nonatomic, copy) void(^onAccessory)(CoinsCell *cell); // set this block to define a callback for when the accessory (chevron on right) is tapped.  If chevronHidden = true, no events will come.
@end


@interface CoinsDetailBase : CustomViewController
@property (nonatomic, strong) IBOutlet ECTextViewDelegate *descDel;
@property (nonatomic, weak) UIBarButtonItem *optionsBarBut;
@property (nonatomic, weak) IBOutlet UIImageView *qr;
@property (nonatomic, weak) IBOutlet UILabel *address, *addressTit, *amountTit, *amount, *fiatAmount, *utxoTit, *utxo, *descTit, *heightTit, *height, *status, *slpToken;
@property (nonatomic, weak) IBOutlet UITextView *desc;
@property (nonatomic, weak) IBOutlet UIButton *freezeBut; // set .selected=YES/NO for checked/unchecked
@property (nonatomic, weak) IBOutlet UIButton *spendFromBut;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *addressTopCS, *statusTopCS, *contentHeightCS;
@property (nonatomic) CGFloat addressTopSaved, statusTopSaved;
@property (nonatomic, weak) IBOutlet UIView *descBox;
@end

// stub for python -- implemented in coins.py
@interface CoinsDetail : CoinsDetailBase
- (IBAction) toggleFreezeAddress;
- (IBAction) cpyAddress;
- (IBAction) cpyUTXO;
- (void) onOptions;
- (IBAction) onSpendFrom;
- (IBAction) onQRImgTap;
@end

@interface PleaseWaitVC : UIViewController
@property (nonatomic, weak) IBOutlet UILabel *message, *pleaseWait;
@property (nonatomic, weak) IBOutlet CCActivityIndicator *activityIndicator;
@end

@interface NewWalletNavBase : CustomNavController
@property (nonatomic) BOOL onBoardingWizard;
@end
@interface NewWalletNav : NewWalletNavBase
// implemented in python newwallet.py
@end
@interface NewWalletVCBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *walletNameTit, *walletPw1Tit, *walletPw2Tit, *errMsg, *touchIdTit;
@property (nonatomic, weak) IBOutlet UISwitch *touchId;
@property (nonatomic, weak) IBOutlet UITextField *walletName, *walletPw1, *walletPw2;
@property (nonatomic, weak) IBOutlet UIView *errMsgView, *touchIdView;
@property (nonatomic, weak) IBOutlet UIButton *nextBut, *showHidePWBut;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *nextButBotCS, *errHeightCS, *errTopCS;
@property (nonatomic) BOOL noPWCheck; ///< set by ImportSaveWallet child class to skip the password check for wallets that lack a password (watching-only wallets)
@end
@interface NewWalletVC : NewWalletVCBase
// implemented in python newwallet.py..
- (IBAction) toggleShowHidePW;
@end
@interface NewWalletVCAtEnd : NewWalletVC
// implemented in python newwallet.py..
@end
@interface RestoreWallet2 : NewWalletVCAtEnd
// implemented in python newwallet.py
- (IBAction) onRestoreModeSave;
@end
@interface ImportSaveWallet : NewWalletVCAtEnd
// implemented in python newwallet.py
- (IBAction) onSave;
@end

@interface NewWalletSeedBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *seedTit, *info;
@property (nonatomic, weak) IBOutlet UITextView *seedtv;
@property (nonatomic, weak) IBOutlet UIView *infoView;
@property (nonatomic, weak) IBOutlet UIButton *nextBut;

// below only used in NewWalletSeed2 and RestoreWallet1 child classes
@property (nonatomic, weak) IBOutlet KeyboardVC *kvc;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *kvcHeightCS;
@property (nonatomic, weak) IBOutlet UIView *kvcContainerView;
@property (nonatomic, weak) IBOutlet UIView *errMsgView;
@property (nonatomic, weak) IBOutlet UILabel *errMsg;
// below only used by RestoreWallet1 child class
@property (nonatomic, weak) IBOutlet UILabel *seedExtTit, *bip39Tit;
@property (nonatomic, weak) IBOutlet UITextField *seedExt;
@property (nonatomic, weak) IBOutlet UISwitch *bip39;
@end
@interface NewWalletSeed1 : NewWalletSeedBase
// implemented in python newwallet.py
@end
@interface NewWalletSeed2 : NewWalletSeedBase
// implemented in python newwallet.py
- (IBAction) onNext;
@end
@interface RestoreWallet1 : NewWalletSeed2
// implemented in python newwallet.py
@end
@interface SuggestionButton : UIButton
+ (instancetype) suggestionButtonWithText:(NSString *)text handler:(void(^)(UIControl *))handler;
@end


@interface NewWalletMenuBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *tit, *blurb;
@property (nonatomic, weak) IBOutlet UIButton *std, *restore, *imp, *master;
- (IBAction) dismiss;
@end
@interface NewWalletMenu : NewWalletMenuBase
// implemented in python newwallet.py
@end

@interface Import1Base : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *tit;
@property (nonatomic, weak) IBOutlet UITextView *tv;
@property (nonatomic, weak) IBOutlet UIView *errMsgView, *infoView;
@property (nonatomic, weak) IBOutlet UILabel *errMsg, *info;
@property (nonatomic, weak) IBOutlet UIButton *nextBut;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *nextButBotCS;
@property (nonatomic, strong) IBOutlet ECTextViewDelegate *tvDel;

@property (nonatomic, weak) id qr, qrvc; ///< used in python by subclass. Declared here to take advantage of ARC and weak refs
@property (nonatomic) BOOL masterKeyMode; ///< defaults to NO, but the Master key screens set this to YES and the python subclass uses this to change the behavior/display of the Import1 screen
@end

@interface Import1 : Import1Base
// implemented in python newwallet.py
- (IBAction) onQRBut;
@end

@interface Import2Base : CustomViewController
@property (nonatomic, weak) IBOutlet UITableView *tv;
@property (nonatomic, weak) IBOutlet UIView *errMsgView, *infoView;
@property (nonatomic, weak) IBOutlet UILabel *errMsg, *info;
@property (nonatomic, weak) IBOutlet UIButton *nextBut;

@property (nonatomic, strong) NSArray<NSString *> *items; ///< used in python as a property but declared here to take advantage of ARC
@property (nonatomic) NSInteger forceType; ///< set this to only accept private keys (=2) or only watching-only public keys (=1) -- to be used in future code that re-uses this class for importing
@property (nonatomic) BOOL masterKeyMode; ///< similar to Import1Base's flag.  This is for the "Import Master Key" set of screens and is set to true there.
@end

@interface Import2 : Import2Base
// implemented in python newwallet.py
- (IBAction) onNext;
- (IBAction) toggleAddressFormat;
@end

@interface ImportCell : UITableViewCell
@property (nonatomic, weak) IBOutlet UILabel *num, *item, *desc, *status;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *centerYCS;
@end

@interface OnBoardingWizardBase : CustomViewController
@property (nonatomic) NSInteger currentPageIndex;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *bottomMarginCS; // on iPhone 5 we set the .constant to 0
@end

@interface OnBoardingWizard : OnBoardingWizardBase
// implemented in python in newwallet.py
@end
@interface OnBoardingPageBase : CustomViewController
@property (nonatomic, weak) IBOutlet UIButton *nextBut;
@property (nonatomic, weak) IBOutlet UILabel *tit, *blurb;
@property (nonatomic, weak) OnBoardingWizard *parent;
@property (nonatomic) NSInteger pageIndex;
@end
@interface OnBoardingPage : OnBoardingPageBase
// implemented in python newwallet.py
- (IBAction) onNext;
@end

@interface OnBoardingMenuBase : NewWalletMenuBase
@property (nonatomic, weak) OnBoardingWizard *parent;
@property (nonatomic) NSInteger pageIndex;
@end

@interface OnBoardingMenu : OnBoardingMenuBase
// implemented in python newwallet.py
- (IBAction) onNewStandardWallet;
- (IBAction) onRestoreSeed;
- (IBAction) onImportAddysPks;
- (IBAction) onMasterKey;
@end

@interface TxDetailInOutCell : UITableViewCell
@property (nonatomic, weak) IBOutlet UILabel *addressType, *address, *detail;
@end

@interface SpendFromCell : UITableViewCell
@property (nonatomic, weak) IBOutlet UILabel *num, *address, *input, *amount;
@end

@interface PrivateKeyDialogBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *addressTit, *address, *scriptTypeTit, *scriptType, *privKeyTit, *redeemScriptTit;
@property (nonatomic, weak) IBOutlet UITextView *privKey, *redeemScript;
@property (nonatomic, weak) IBOutlet UIButton *cpyAddress, *cpyPrivKey, *cpyRedeemScript, *qrAddress, *qrPrivKey, *qrRedeemScript;
@end
@interface PrivateKeyDialog : PrivateKeyDialogBase
// implemented in python private_key_dialog.py
- (IBAction) onCpyBut:(id)sender;
- (IBAction) onQRBut:(id)sender;
@end

@interface SignDecryptBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *topTit, *midTit, *botTit;
@property (nonatomic, weak) IBOutlet UITextView *topTv, *botTv;
@property (nonatomic, weak) IBOutlet UITextField *tf;
@property (nonatomic, weak) IBOutlet UIButton *cpyTop, *cpyBot, *addressBut, *butLeft, *butRight;
@property (nonatomic, strong) IBOutlet ECTextViewDelegate *topTvDel, *botTvDel;
@end

@interface SignDecryptVC : SignDecryptBase
// implemented in python sign_decrypt_dialog.py
- (IBAction) onCpyBut:(id)sender;
- (IBAction) onPickAddress:(id)sender;
- (IBAction) onExecuteBut:(id)sender;
@end

@interface ReceiveBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *addrTit, *descTit, *amtTit, *amtFiatTit, *expiresTit, *expires, *message;
@property (nonatomic, weak) IBOutlet LinkLabel *addr, *expiresLink;
@property (nonatomic, weak) IBOutlet UIImageView *qr;
@property (nonatomic, weak) IBOutlet UITextField *desc, *amt, *amtFiat;
@property (nonatomic, weak) IBOutlet UIButton *cpyBut, *shareRequestBut;
@property (nonatomic, weak) IBOutlet UIBarButtonItem *saveBarBut;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *csFiatLine;
@property (nonatomic, weak) IBOutlet UIScrollView *sv;
@property (nonatomic, weak) IBOutlet UIView *bottomView;
@end

@interface ReceiveVC : ReceiveBase
// implemented in python receive.py
- (IBAction) onShareRequestBut:(id)sender;
- (IBAction) onQRImgTap;
@end

@interface SeedDisplayBase : CustomViewController
@property (nonatomic, strong) NSString *seed, *passphrase;
@property (nonatomic, weak) IBOutlet UIView *contentView, *warnView;
@property (nonatomic, weak) IBOutlet UILabel *seedTit, *extTit, *seedLbl, *extLbl, *blurb, *warnTit, *warn1, *warn2, *warn3;
@property (nonatomic, weak) IBOutlet UIButton *okBut;
@property (nonatomic, weak) IBOutlet UIGestureRecognizer *grSeed, *grExt;
@property (nonatomic, weak) IBOutlet NSLayoutConstraint *csBlurbTop, *csBlurbBot, *csBlurbHeight, *csOkButHeight, *csTitTop;
@end

@interface SeedDisplayVC : SeedDisplayBase
// implemented in python seed_dialog.py
- (IBAction) onSeedLblTap:(id)sender;
- (IBAction) onOk:(id)sender;
@end

@interface CrashReporterNav : CustomNavController
@end

@interface CrashReporterBase : CustomViewController
@property (nonatomic, weak) IBOutlet UILabel *errMsg, *reportTit, *descTit;
@property (nonatomic, weak) IBOutlet UITextView *report, *desc;
@property (nonatomic, strong) IBOutlet ECTextViewDelegate *descDel;
@property (nonatomic) NSInteger kbas;
@property (nonatomic, weak) IBOutlet UIScrollView *sv;
@property (nonatomic, weak) IBOutlet UIView *bottomView, *contentView;
@property (nonatomic, weak) IBOutlet UIButton *sendBut;
@end
@interface CrashReporterVC : CrashReporterBase
// implemented in python crashreporter.py
- (IBAction) onSendBut:(id)sender;
@end
#endif /* ViewsForIB_h */
