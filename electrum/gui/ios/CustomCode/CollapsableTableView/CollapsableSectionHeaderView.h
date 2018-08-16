//
//  CollapsableSectionHeaderView.h
//
//  Created by calin on 3/25/18.
//  Copyright © 2018 Calin Culianu. MIT License.
//

#import "CollapsableTableView.h"

@interface CollapsableSectionHeaderView : UITableViewHeaderFooterView <CollapsableHeaderProtocol>
@property (weak, nonatomic) IBOutlet UILabel *titleLabel;
@end
