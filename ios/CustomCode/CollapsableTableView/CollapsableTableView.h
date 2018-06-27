//
//  CollapsableTableView.h
//
//  Created by calin on 3/25/18.
//  Copyright © 2018 Calin Culianu. MIT License.
//

#ifndef CollapsableTableView_h
#define CollapsableTableView_h
#import <UIKit/UIKit.h>

@protocol CollapsableTableViewDelegate;

@protocol CollapsableTableViewDelegate <UITableViewDelegate>
@optional
// your custom .delegate can optionally implement this method to be notified about when a section was tapped and expanded as a result
- (void) tableView:(nonnull UITableView *)tableView didSelectHeaderInSection:(NSInteger)section;
// your custom .delegate can optionally implement this method to be notified about when a section was tapped and collapsed as a result
- (void) tableView:(nonnull UITableView *)tableView didDeselectHeaderInSection:(NSInteger)section;
@end

@interface CollapsableTableView : UITableView
@property (nonatomic, copy, nonnull) NSString *headerViewIdentifier;
@property (nonatomic) BOOL singleOpen;
- (void) setSection:(NSInteger)section visible:(BOOL)visible;
- (BOOL) isSectionVisible:(NSInteger)section;
- (void) setAllSectionsVisible:(BOOL)visible;
@end

// your custom headerview that you may optionally create with the delegate callback should conform to this protocol
@protocol CollapsableHeaderProtocol <NSObject>
@property (nullable, weak, nonatomic) IBOutlet UILabel *titleLabel;
-(void)openAnimated:(BOOL)animated;
-(void)closeAnimated:(BOOL)animated;
@end


#endif /* CollapsableTableView_h */
