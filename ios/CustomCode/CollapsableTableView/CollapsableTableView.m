//
//  CollapsableTableView.m
//
//  Created by calin on 3/25/18.
//  Copyright © 2018 Calin Culianu. MIT License.
//

#import <Foundation/Foundation.h>
#import "CollapsableTableView.h"

@interface CollapsableTableView()<UITableViewDelegate,UITableViewDataSource>
@property (nonatomic, weak, nullable) id<UITableViewDelegate> realDelegate;
@property (nonatomic, weak, nullable) id<UITableViewDataSource> realDataSource;

// required
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section;

// Row display. Implementers should *always* try to reuse cells by setting each cell's reuseIdentifier and querying for available reusable cells with dequeueReusableCellWithIdentifier:
// Cell gets various attributes set automatically based on table (separators) and data source (accessory views, editing controls)

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath;

//@optional

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView;              // Default is 1 if not implemented

// UITableViewDelegate
// optional
- (void)tableView:(UITableView *)tableView willDisplayHeaderView:(UIView *)view forSection:(NSInteger)section;
- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section;
- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath;
- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section;

// UIGestureRecognizer
- (void) onGestureRecognizer:(UIGestureRecognizer *)gr;
- (void)userTapped:(UIView <CollapsableHeaderProtocol> *)view;
- (NSArray *)indexPathsForSection:(NSInteger)section;
@end

@implementation CollapsableTableView {
    NSString *hvi;
    NSMutableSet *visibleSections;
}
@synthesize realDelegate, realDataSource, headerViewIdentifier = hvi, singleOpen;


- (void) commonInit {
    self.headerViewIdentifier = @"CollapsabeSectionHeaderViewID";
    visibleSections = [NSMutableSet setWithCapacity:1];
    [visibleSections addObject:[NSNumber numberWithInteger:0]];
    self.singleOpen = NO;
    UINib *nib = [UINib nibWithNibName:@"CollapsableSectionHeaderView" bundle:nil];
    if (nib) [self registerNib:nib forHeaderFooterViewReuseIdentifier:self.headerViewIdentifier];
}

- (instancetype) init {
    if ( (self = [super init]) ) {
        [self commonInit];
    }
    return self;
}


- (instancetype) initWithFrame:(CGRect)frame {
    if ( (self = [super initWithFrame:frame]) ) {
        [self commonInit];
    }
    return self;
}


- (instancetype) initWithFrame:(CGRect)frame style:(UITableViewStyle)style {
    if ( (self = [super initWithFrame:frame style:style]) ) {
        [self commonInit];
    }
    return self;
}


- (instancetype) initWithCoder:(NSCoder *)aDecoder {
    self = [super initWithCoder:aDecoder];
    if (self) {
        self.delegate = super.delegate;
        self.dataSource = super.dataSource;
        [self commonInit];
    }
    return self;
}
//UITableViewDataSource
//@required

- (void) setDataSource:(id<UITableViewDataSource>)ds {
    //NSLog(@"setDataSource called ok!");
    self.realDataSource = ds;
    super.dataSource = ds ? self : nil;
}

- (void) setDelegate:(id<UITableViewDelegate>)d {
    //NSLog(@"setDelegate called ok!");
    self.realDelegate = d;
    super.delegate = d ? self : nil;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    //NSLog(@"proxy method 1 called ok ok!");
    return [self isSectionVisible:section] && self.realDataSource ? [self.realDataSource tableView:tableView numberOfRowsInSection:section] : 0;
}

// Row display. Implementers should *always* try to reuse cells by setting each cell's reuseIdentifier and querying for available reusable cells with dequeueReusableCellWithIdentifier:
// Cell gets various attributes set automatically based on table (separators) and data source (accessory views, editing controls)

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    //NSLog(@"proxy method 2 called ok ok!");
    return [self.realDataSource tableView:tableView cellForRowAtIndexPath:indexPath];

}

//@optional

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    //NSLog(@"proxy method 3 called ok ok!");
    NSInteger n = 1;
    if (self.realDataSource && [self.realDataSource respondsToSelector:@selector(numberOfSectionsInTableView:)])
        n = [self.realDataSource numberOfSectionsInTableView:tableView];
    return n;
}

// UITableViewDelegate
- (void)tableView:(UITableView *)tableView willDisplayHeaderView:(UIView *)view forSection:(NSInteger)section {
    //NSLog(@"proxy method 4 called ok ok!");
    if (self.realDelegate && [self.realDelegate respondsToSelector:@selector(tableView:willDisplayHeaderView:forSection:)]) {
        [self.realDelegate tableView:tableView willDisplayHeaderView:view forSection:section];
    }

    id <CollapsableHeaderProtocol> sectionView = (id <CollapsableHeaderProtocol>)view;

    if ([self isSectionVisible:section]) {
        [sectionView openAnimated:NO];
    } else {
        [sectionView closeAnimated:NO];
    }
}

-(UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section {
    //NSLog(@"proxy method 5 called ok ok!");
    if (self.realDelegate && [self.realDelegate respondsToSelector:@selector(tableView:viewForHeaderInSection:)]) {
        UIView *ret = [self.realDelegate tableView:tableView viewForHeaderInSection:section];
        ret.tag = section;
        return ret;
    }
    // else...
    UIView <CollapsableHeaderProtocol> *view = (UIView <CollapsableHeaderProtocol> *)[tableView dequeueReusableHeaderFooterViewWithIdentifier:hvi];
    //view.interactionDelegate = self;
    view.tag = section;
    if (self.realDataSource && [self.realDataSource respondsToSelector:@selector(tableView:titleForHeaderInSection:)]) {
        view.titleLabel.text = [self.realDataSource tableView:tableView titleForHeaderInSection:section];
    }
    UITapGestureRecognizer *tr = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onGestureRecognizer:)];
    [view addGestureRecognizer:tr];
    view.userInteractionEnabled = YES;
    return view;
}
- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    //NSLog(@"proxy method 6 called ok ok!");
    if (self.realDelegate && [self.realDelegate respondsToSelector:@selector(tableView:heightForRowAtIndexPath:)]) {
        return [self.realDelegate tableView:tableView heightForRowAtIndexPath:indexPath];
    }
    return 44.0f;
}
- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section {
    //NSLog(@"proxy method 7 called ok ok!");
    if (self.realDelegate && [self.realDelegate respondsToSelector:@selector(tableView:heightForHeaderInSection:)]) {
        return [self.realDelegate tableView:tableView heightForHeaderInSection:section];
    }
    return 22.0f;
}

- (void)onGestureRecognizer:(UIGestureRecognizer *)gr {
    [self userTapped:(UIView<CollapsableHeaderProtocol> *)gr.view];
}

- (void) setSection:(NSInteger)section visible:(BOOL)visible {
    NSNumber *n = [NSNumber numberWithInteger:section];
    if (visible) {
        [visibleSections addObject:n];
    } else {
        [visibleSections removeObject:n];
    }
}

- (BOOL) isSectionVisible:(NSInteger)section {
    NSNumber *n = [NSNumber numberWithInteger:section];
    return [visibleSections containsObject:n];
}

- (void) setAllSectionsVisible:(BOOL)visible {
    NSInteger n = self.numberOfSections;
    [visibleSections removeAllObjects];
    for (NSInteger i = 0; i < n; ++i)
        [self setSection:i visible:visible];
}

-(void)userTapped:(UIView <CollapsableHeaderProtocol> *)view {

    UITableView *tableView = self;

    [tableView beginUpdates];

    BOOL foundOpenUnchosenMenuSection = NO;

    const int nSects = (int)[self numberOfSectionsInTableView:self];
    const int tappedSection = (int)view.tag;
    NSMutableSet *setSelections = [NSMutableSet setWithCapacity:1], *setDeselections = [NSMutableSet setWithCapacity:1];

    for (int i = 0; i < nSects; ++i) {

        BOOL chosenMenuSection = (i == tappedSection);

        BOOL isVisible = [self isSectionVisible:(NSInteger)i];

        if (isVisible && chosenMenuSection) {

            [self setSection:i visible:NO];
            [setDeselections addObject:[NSNumber numberWithInt:i]];

            if ([view conformsToProtocol:@protocol(CollapsableHeaderProtocol)]
                || [view respondsToSelector:@selector(closeAnimated:)])
                [view closeAnimated:YES];

            NSInteger section = view.tag;

            NSArray *indexPaths = [self indexPathsForSection:section];

            [tableView deleteRowsAtIndexPaths:indexPaths
                             withRowAnimation:(foundOpenUnchosenMenuSection) ? UITableViewRowAnimationBottom : UITableViewRowAnimationTop];

        } else if (!isVisible && chosenMenuSection) {

            [self setSection:i visible:YES];
            [setSelections addObject:[NSNumber numberWithInt:i]];

            if ([view conformsToProtocol:@protocol(CollapsableHeaderProtocol)]
                || [view respondsToSelector:@selector(openAnimated:)])
                [view openAnimated:YES];

            NSInteger section = view.tag;

            NSArray *indexPaths = [self indexPathsForSection:section];

            [tableView insertRowsAtIndexPaths:indexPaths
                             withRowAnimation:(foundOpenUnchosenMenuSection) ? UITableViewRowAnimationBottom : UITableViewRowAnimationTop];

        } else if (isVisible && !chosenMenuSection && self.singleOpen) {

            foundOpenUnchosenMenuSection = YES;

            [self setSection:i visible:NO];
            [setDeselections addObject:[NSNumber numberWithInt:i]];

            NSInteger section = i;

            UIView <CollapsableHeaderProtocol> *headerView = (UIView <CollapsableHeaderProtocol> *)[tableView headerViewForSection:section];

            if ([headerView conformsToProtocol:@protocol(CollapsableHeaderProtocol)]
                || [headerView respondsToSelector:@selector(closeAnimated:)])
                [headerView closeAnimated:YES];

            NSArray *indexPaths = [self indexPathsForSection:section];

            [tableView deleteRowsAtIndexPaths:indexPaths
                             withRowAnimation:(view.tag > section) ? UITableViewRowAnimationTop : UITableViewRowAnimationBottom];

        }

    }

    [tableView endUpdates];

    for (NSNumber *num in setDeselections) {
        NSInteger section = num.integerValue;
        if ([self.realDelegate respondsToSelector:@selector(tableView:didDeselectHeaderInSection:)]
            || [self.realDelegate conformsToProtocol:@protocol(CollapsableTableViewDelegate)]) {
            id<CollapsableTableViewDelegate> del = (id<CollapsableTableViewDelegate>)self.realDelegate;
            [del tableView:tableView didDeselectHeaderInSection:section];
        }
    }
    for (NSNumber *num in setSelections) {
        NSInteger section = num.integerValue;
        if ([self.realDelegate respondsToSelector:@selector(tableView:didSelectHeaderInSection:)]
            || [self.realDelegate conformsToProtocol:@protocol(CollapsableTableViewDelegate)]) {
            id<CollapsableTableViewDelegate> del = (id<CollapsableTableViewDelegate>)self.realDelegate;
            [del tableView:tableView didSelectHeaderInSection:section];
        }
    }
}

-(NSArray *)indexPathsForSection:(NSInteger)section {
    NSInteger count = self.realDataSource && [self.realDataSource respondsToSelector:@selector(tableView:numberOfRowsInSection:)] ? [self.realDataSource tableView:self numberOfRowsInSection:section] : 0;
    NSIndexPath *indexPath;
    NSMutableArray *collector = [NSMutableArray arrayWithCapacity:(NSUInteger)count];
    for (NSInteger i = 0; i < count; i++) {
        indexPath = [NSIndexPath indexPathForRow:i inSection:section];
        [collector addObject:indexPath];
    }
    return collector;
}

// optional stuff.. forward calls to delegates and dataSource...
- (void)tableView:(UITableView *)tableView willDisplayCell:(UITableViewCell *)cell forRowAtIndexPath:(NSIndexPath *)indexPath {
    @try {
        if ([self.realDelegate respondsToSelector:@selector(tableView:willDisplayCell:forRowAtIndexPath:)])
            [self.realDelegate tableView:tableView willDisplayCell:cell forRowAtIndexPath:indexPath];
    } @catch (NSException * e) {
        if ([e.name isEqualToString:NSInvalidArgumentException]) {
            // safely ignore.. optional method
            //NSLog(@"Caught exception: %@ - %@",[e name],[e description]);
        } else
            @throw e;
    }
}
- (void)tableView:(UITableView *)tableView didEndDisplayingCell:(UITableViewCell *)cell forRowAtIndexPath:(NSIndexPath*)indexPath {
    @try {
        if ([self.realDelegate respondsToSelector:@selector(tableView:didEndDisplayingCell:forRowAtIndexPath:)])
            [self.realDelegate tableView:tableView didEndDisplayingCell:cell forRowAtIndexPath:indexPath];
    } @catch (NSException * e) {
        if ([e.name isEqualToString:NSInvalidArgumentException]) {
            // safely ignore.. optional method
            //NSLog(@"Caught exception: %@ - %@",[e name],[e description]);
        } else
            @throw e;
    }
}
- (void)tableView:(UITableView *)tableView didEndDisplayingHeaderView:(UIView *)view forSection:(NSInteger)section {
    @try {
        if ([self.realDelegate respondsToSelector:@selector(tableView:didEndDisplayingHeaderView:forSection:)])
            [self.realDelegate tableView:tableView didEndDisplayingHeaderView:view forSection:section];
    } @catch (NSException * e) {
        if ([e.name isEqualToString:NSInvalidArgumentException]) {
            // safely ignore.. optional method
            //NSLog(@"Caught exception: %@ - %@",[e name],[e description]);
        } else
            @throw e;
    }
}
- (void)tableView:(UITableView *)tableView accessoryButtonTappedForRowWithIndexPath:(NSIndexPath *)indexPath {
    @try {
        if ([self.realDelegate respondsToSelector:@selector(tableView:accessoryButtonTappedForRowWithIndexPath:)])
            [self.realDelegate tableView:tableView accessoryButtonTappedForRowWithIndexPath:indexPath];
    } @catch (NSException * e) {
        if ([e.name isEqualToString:NSInvalidArgumentException]) {
            // safely ignore.. optional method
            //NSLog(@"Caught exception: %@ - %@",[e name],[e description]);
        } else
            @throw e;
    }
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    @try {
        if ([self.realDelegate respondsToSelector:@selector(tableView:didSelectRowAtIndexPath:)])
            [self.realDelegate tableView:tableView didSelectRowAtIndexPath:indexPath];
    } @catch (NSException * e) {
        if ([e.name isEqualToString:NSInvalidArgumentException]) {
            // safely ignore.. optional method
            //NSLog(@"Caught exception: %@ - %@",[e name],[e description]);
        } else
            @throw e;
    }
}
- (void)tableView:(UITableView *)tableView didDeselectRowAtIndexPath:(NSIndexPath *)indexPath {
    @try {
        if ([self.realDelegate respondsToSelector:@selector(tableView:didDeselectRowAtIndexPath:)])
            [self.realDelegate tableView:tableView didDeselectRowAtIndexPath:indexPath];
    } @catch (NSException * e) {
        if ([e.name isEqualToString:NSInvalidArgumentException]) {
            // safely ignore.. optional method
            //NSLog(@"Caught exception: %@ - %@",[e name],[e description]);
        } else
            @throw e;
    }
}

@end
