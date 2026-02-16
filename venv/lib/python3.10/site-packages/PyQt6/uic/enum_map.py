# Copyright (c) 2026 Riverbank Computing Limited <info@riverbankcomputing.com>
# 
# This file is part of PyQt6.
# 
# This file may be used under the terms of the GNU General Public License
# version 3.0 as published by the Free Software Foundation and appearing in
# the file LICENSE included in the packaging of this file.  Please review the
# following information to ensure the GNU General Public License version 3.0
# requirements will be met: http://www.gnu.org/copyleft/gpl.html.
# 
# If you do not wish to use this file under the terms of the GPL version 3.0
# then you may purchase a commercial license.  For more information contact
# info@riverbankcomputing.com.
# 
# This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
# WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.


# Map enum member names to fully scoped names.  Note that Designer v6.7.0 and
# later use fully scoped enum names so this is only needed for .ui files
# created with older versions.
EnumMap = {
    'Qt::AlignHCenter':         'Qt::AlignmentFlag::AlignHCenter',
    'Qt::AlignJustify':         'Qt::AlignmentFlag::AlignJustify',
    'Qt::AlignLeft':            'Qt::AlignmentFlag::AlignLeft',
    'Qt::AlignRight':           'Qt::AlignmentFlag::AlignRight',

    'Qt::AlignBaseline':        'Qt::AlignmentFlag::AlignBaseline',
    'Qt::AlignBottom':          'Qt::AlignmentFlag::AlignBottom',
    'Qt::AlignTop':             'Qt::AlignmentFlag::AlignTop',
    'Qt::AlignVCenter':         'Qt::AlignmentFlag::AlignVCenter',

    'Qt::AlignAbsolute':        'Qt::AlignmentFlag::AlignAbsolute',
    'Qt::AlignLeading':         'Qt::AlignmentFlag::AlignLeading',
    'Qt::AlignTrailing':        'Qt::AlignmentFlag::AlignTrailing',

    'Qt::AlignCenter':          'Qt::AlignmentFlag::AlignCenter',

    'Qt::AlignHorizontal_Mask': 'Qt::AlignmentFlag::AlignHorizontal_Mask',
    'Qt::AlignVertical_Mask':   'Qt::AlignmentFlag::AlignVertical_Mask',

    'Qt::DownArrow':    'Qt::ArrowType::DownArrow',
    'Qt::LeftArrow':    'Qt::ArrowType::LeftArrow',
    'Qt::NoArrow':      'Qt::ArrowType::NoArrow',
    'Qt::RightArrow':   'Qt::ArrowType::RightArrow',
    'Qt::UpArrow':      'Qt::ArrowType::UpArrow',

    'Qt::Checked':          'Qt::CheckState::Checked',
    'Qt::PartiallyChecked': 'Qt::CheckState::PartiallyChecked',
    'Qt::Unchecked':        'Qt::CheckState::Unchecked',

    'Qt::ActionsContextMenu':   'Qt::ContextMenuPolicy::ActionsContextMenu',
    'Qt::CustomContextMenu':    'Qt::ContextMenuPolicy::CustomContextMenu',
    'Qt::DefaultContextMenu':   'Qt::ContextMenuPolicy::DefaultContextMenu',
    'Qt::NoContextMenu':        'Qt::ContextMenuPolicy::NoContextMenu',
    'Qt::PreventContextMenu':   'Qt::ContextMenuPolicy::PreventContextMenu',

    'Qt::LogicalMoveStyle': 'Qt::CursorMoveStyle::LogicalMoveStyle',
    'Qt::VisualMoveStyle':  'Qt::CursorMoveStyle::VisualMoveStyle',

    'Qt::Monday':       'Qt::DayOfWeek::Monday',
    'Qt::Tuesday':      'Qt::DayOfWeek::Tuesday',
    'Qt::Wednesday':    'Qt::DayOfWeek::Wednesday',
    'Qt::Thursday':     'Qt::DayOfWeek::Thursday',
    'Qt::Friday':       'Qt::DayOfWeek::Friday',
    'Qt::Saturday':     'Qt::DayOfWeek::Saturday',
    'Qt::Sunday':       'Qt::DayOfWeek::Sunday',

    'Qt::AllDockWidgetAreas':   'Qt::DockWidgetArea::AllDockWidgetAreas',
    'Qt::LeftDockWidgetArea':   'Qt::DockWidgetArea::LeftDockWidgetArea',
    'Qt::RightDockWidgetArea':  'Qt::DockWidgetArea::RightDockWidgetArea',
    'Qt::TopDockWidgetArea':    'Qt::DockWidgetArea::TopDockWidgetArea',
    'Qt::BottomDockWidgetArea': 'Qt::DockWidgetArea::BottomDockWidgetArea',
    'Qt::NoDockWidgetArea':     'Qt::DockWidgetArea::NoDockWidgetArea',

    'Qt::ActionMask':       'Qt::DropAction::ActionMask',
    'Qt::CopyAction':       'Qt::DropAction::CopyAction',
    'Qt::IgnoreAction':     'Qt::DropAction::IgnoreAction',
    'Qt::LinkAction':       'Qt::DropAction::LinkAction',
    'Qt::MoveAction':       'Qt::DropAction::MoveAction',
    'Qt::TargetMoveAction': 'Qt::DropAction::TargetMoveAction',

    'Qt::ClickFocus':   'Qt::FocusPolicy::ClickFocus',
    'Qt::NoFocus':      'Qt::FocusPolicy::NoFocus',
    'Qt::TabFocus':     'Qt::FocusPolicy::TabFocus',
    'Qt::StrongFocus':  'Qt::FocusPolicy::StrongFocus',
    'Qt::WheelFocus':   'Qt::FocusPolicy::WheelFocus',

    'Qt::ImhDate':                  'Qt::InputMethodHint::ImhDate',
    'Qt::ImhDialableCharactersOnly':    'Qt::InputMethodHint::ImhDialableCharactersOnly',
    'Qt::ImhDigitsOnly':            'Qt::InputMethodHint::ImhDigitsOnly',
    'Qt::ImhEmailCharactersOnly':   'Qt::InputMethodHint::ImhEmailCharactersOnly',
    'Qt::ImhExclusiveInputMask':    'Qt::InputMethodHint::ImhExclusiveInputMask',
    'Qt::ImhFormattedNumbersOnly':  'Qt::InputMethodHint::ImhFormattedNumbersOnly',
    'Qt::ImhHiddenText':            'Qt::InputMethodHint::ImhHiddenText',
    'Qt::ImhLatinOnly':             'Qt::InputMethodHint::ImhLatinOnly',
    'Qt::ImhLowercaseOnly':         'Qt::InputMethodHint::ImhLowercaseOnly',
    'Qt::ImhMultiLine':             'Qt::InputMethodHint::ImhMultiLine',
    'Qt::ImhNoAutoUppercase':       'Qt::InputMethodHint::ImhNoAutoUppercase',
    'Qt::ImhNoEditMenu':            'Qt::InputMethodHint::ImhNoEditMenu',
    'Qt::ImhNoPredictiveText':      'Qt::InputMethodHint::ImhNoPredictiveText',
    'Qt::ImhNoTextHandles':         'Qt::InputMethodHint::ImhNoTextHandles',
    'Qt::ImhNone':                  'Qt::InputMethodHint::ImhNone',
    'Qt::ImhPreferLatin':           'Qt::InputMethodHint::ImhPreferLatin',
    'Qt::ImhPreferLowercase':       'Qt::InputMethodHint::ImhPreferLowercase',
    'Qt::ImhPreferNumbers':         'Qt::InputMethodHint::ImhPreferNumbers',
    'Qt::ImhPreferUppercase':       'Qt::InputMethodHint::ImhPreferUppercase',
    'Qt::ImhSensitiveData':         'Qt::InputMethodHint::ImhSensitiveData',
    'Qt::ImhTime':                  'Qt::InputMethodHint::ImhTime',
    'Qt::ImhUppercaseOnly':         'Qt::InputMethodHint::ImhUppercaseOnly',
    'Qt::ImhUrlCharactersOnly':     'Qt::InputMethodHint::ImhUrlCharactersOnly',

    'Qt::ItemIsAutoTristate':   'Qt::ItemFlag::ItemIsAutoTristate',
    'Qt::ItemIsDragEnabled':    'Qt::ItemFlag::ItemIsDragEnabled',
    'Qt::ItemIsDropEnabled':    'Qt::ItemFlag::ItemIsDropEnabled',
    'Qt::ItemIsEditable':       'Qt::ItemFlag::ItemIsEditable',
    'Qt::ItemIsEnabled':        'Qt::ItemFlag::ItemIsEnabled',
    'Qt::ItemIsSelectable':     'Qt::ItemFlag::ItemIsSelectable',
    'Qt::ItemIsUserCheckable':  'Qt::ItemFlag::ItemIsUserCheckable',
    'Qt::ItemIsUserTristate':   'Qt::ItemFlag::ItemIsUserTristate',
    'Qt::ItemNeverHasChildren': 'Qt::ItemFlag::ItemNeverHasChildren',
    'Qt::NoItemFlags':          'Qt::ItemFlag::NoItemFlags',

    'Qt::ContainsItemBoundingRect':     'Qt::ItemSelectionMode::ContainsItemBoundingRect',
    'Qt::ContainsItemShape':            'Qt::ItemSelectionMode::ContainsItemShape',
    'Qt::IntersectsItemBoundingRect':   'Qt::ItemSelectionMode::IntersectsItemBoundingRect',
    'Qt::IntersectsItemShape':          'Qt::ItemSelectionMode::IntersectsItemShape',

    'Qt::LayoutDirectionAuto':  'Qt::LayoutDirection::LayoutDirectionAuto',
    'Qt::LeftToRight':          'Qt::LayoutDirection::LeftToRight',
    'Qt::RightToLeft':          'Qt::LayoutDirection::RightToLeft',

    'Qt::Horizontal':   'Qt::Orientation::Horizontal',
    'Qt::Vertical':     'Qt::Orientation::Vertical',

    'Qt::CustomDashLine':   'Qt::PenStyle::CustomDashLine',
    'Qt::DashDotDotLine':   'Qt::PenStyle::DashDotDotLine',
    'Qt::DashDotLine':      'Qt::PenStyle::DashDotLine',
    'Qt::DashLine':         'Qt::PenStyle::DashLine',
    'Qt::DotLine':          'Qt::PenStyle::DotLine',
    'Qt::NoPen':            'Qt::PenStyle::NoPen',
    'Qt::SolidLine':        'Qt::PenStyle::SolidLine',

    'Qt::ScrollBarAlwaysOff':   'Qt::ScrollBarPolicy::ScrollBarAlwaysOff',
    'Qt::ScrollBarAlwaysOn':    'Qt::ScrollBarPolicy::ScrollBarAlwaysOn',
    'Qt::ScrollBarAsNeeded':    'Qt::ScrollBarPolicy::ScrollBarAsNeeded',

    'Qt::ApplicationShortcut':          'Qt::ShortcutContext::ApplicationShortcut',
    'Qt::WidgetShortcut':               'Qt::ShortcutContext::WidgetShortcut',
    'Qt::WidgetWithChildrenShortcut':   'Qt::ShortcutContext::WidgetWithChildrenShortcut',
    'Qt::WindowShortcut':               'Qt::ShortcutContext::WindowShortcut',

    'Qt::ElideLeft':    'Qt::TextElideMode::ElideLeft',
    'Qt::ElideRight':   'Qt::TextElideMode::ElideRight',
    'Qt::ElideMiddle':  'Qt::TextElideMode::ElideMiddle',
    'Qt::ElideNone':    'Qt::TextElideMode::ElideNone',

    'Qt::NoTextInteraction':            'Qt::TextInteractionFlag::NoTextInteraction',
    'Qt::TextSelectableByMouse':        'Qt::TextInteractionFlag::TextSelectableByMouse',
    'Qt::TextSelectableByKeyboard':     'Qt::TextInteractionFlag::TextSelectableByKeyboard',
    'Qt::LinksAccessibleByMouse':       'Qt::TextInteractionFlag::LinksAccessibleByMouse',
    'Qt::LinksAccessibleByKeyboard':    'Qt::TextInteractionFlag::LinksAccessibleByKeyboard',
    'Qt::TextEditable':                 'Qt::TextInteractionFlag::TextEditable',
    'Qt::TextEditorInteraction':        'Qt::TextInteractionFlag::TextEditorInteraction',
    'Qt::TextBrowserInteraction':       'Qt::TextInteractionFlag::TextBrowserInteraction',

    'Qt::AutoText':     'Qt::TextFormat::AutoText',
    'Qt::MarkdownText': 'Qt::TextFormat::MarkdownText',
    'Qt::PlainText':    'Qt::TextFormat::PlainText',
    'Qt::RichText':     'Qt::TextFormat::RichText',

    'Qt::LocalTime':        'Qt::TimeSpec::LocalTime',
    'Qt::OffsetFromUTC':    'Qt::TimeSpec::OffsetFromUTC',
    'Qt::TimeZone':         'Qt::TimeSpec::TimeZone',
    'Qt::UTC':              'Qt::TimeSpec::UTC',

    'Qt::LeftToolBarArea':      'Qt::ToolBarArea::LeftToolBarArea',
    'Qt::RightToolBarArea':     'Qt::ToolBarArea::RightToolBarArea',
    'Qt::TopToolBarArea':       'Qt::ToolBarArea::TopToolBarArea',
    'Qt::BottomToolBarArea':    'Qt::ToolBarArea::BottomToolBarArea',
    'Qt::AllToolBarAreas':      'Qt::ToolBarArea::AllToolBarAreas',
    'Qt::NoToolBarArea':        'Qt::ToolBarArea::NoToolBarArea',

    'Qt::ToolButtonFollowStyle':    'Qt::ToolButtonStyle::ToolButtonFollowStyle',
    'Qt::ToolButtonIconOnly':       'Qt::ToolButtonStyle::ToolButtonIconOnly',
    'Qt::ToolButtonTextBesideIcon': 'Qt::ToolButtonStyle::ToolButtonTextBesideIcon',
    'Qt::ToolButtonTextOnly':       'Qt::ToolButtonStyle::ToolButtonTextOnly',
    'Qt::ToolButtonTextUnderIcon':  'Qt::ToolButtonStyle::ToolButtonTextUnderIcon',

    'Qt::ApplicationModal': 'Qt::WindowModality::ApplicationModal',
    'Qt::NonModal':         'Qt::WindowModality::NonModal',
    'Qt::WindowModal':      'Qt::WindowModality::WindowModal',

    'QAbstractItemView::NoDragDrop':    'QAbstractItemView::DragDropMode::NoDragDrop',
    'QAbstractItemView::DragOnly':      'QAbstractItemView::DragDropMode::DragOnly',
    'QAbstractItemView::DropOnly':      'QAbstractItemView::DragDropMode::DropOnly',
    'QAbstractItemView::DragDrop':      'QAbstractItemView::DragDropMode::DragDrop',
    'QAbstractItemView::InternalMove':  'QAbstractItemView::DragDropMode::InternalMove',

    'QAbstractItemView::NoEditTriggers':    'QAbstractItemView::EditTrigger::NoEditTriggers',
    'QAbstractItemView::CurrentChanged':    'QAbstractItemView::EditTrigger::CurrentChanged',
    'QAbstractItemView::DoubleClicked':     'QAbstractItemView::EditTrigger::DoubleClicked',
    'QAbstractItemView::SelectedClicked':   'QAbstractItemView::EditTrigger::SelectedClicked',
    'QAbstractItemView::EditKeyPressed':    'QAbstractItemView::EditTrigger::EditKeyPressed',
    'QAbstractItemView::AnyKeyPressed':     'QAbstractItemView::EditTrigger::AnyKeyPressed',
    'QAbstractItemView::AllEditTriggers':   'QAbstractItemView::EditTrigger::AllEditTriggers',

    'QAbstractItemView::ScrollPerItem':     'QAbstractItemView::ScrollMode::ScrollPerItem',
    'QAbstractItemView::ScrollPerPixel':    'QAbstractItemView::ScrollMode::ScrollPerPixel',

    'QAbstractItemView::SelectColumns': 'QAbstractItemView::SelectionBehavior::SelectColumns',
    'QAbstractItemView::SelectItems':   'QAbstractItemView::SelectionBehavior::SelectItems',
    'QAbstractItemView::SelectRows':    'QAbstractItemView::SelectionBehavior::SelectRows',

    'QAbstractItemView::NoSelection':           'QAbstractItemView::SelectionMode::NoSelection',
    'QAbstractItemView::SingleSelection':       'QAbstractItemView::SelectionMode::SingleSelection',
    'QAbstractItemView::MultiSelection':        'QAbstractItemView::SelectionMode::MultiSelection',
    'QAbstractItemView::ExtendedSelection':     'QAbstractItemView::SelectionMode::ExtendedSelection',
    'QAbstractItemView::ContiguousSelection':   'QAbstractItemView::SelectionMode::ContiguousSelection',

    'QAbstractScrollArea::AdjustIgnored':               'QAbstractScrollArea::SizeAdjustPolicy::AdjustIgnored',
    'QAbstractScrollArea::AdjustToContents':            'QAbstractScrollArea::SizeAdjustPolicy::AdjustToContents',
    'QAbstractScrollArea::AdjustToContentsOnFirstShow': 'QAbstractScrollArea::SizeAdjustPolicy::AdjustToContentsOnFirstShow',

    'QAbstractSpinBox::NoButtons':      'QAbstractSpinBox::ButtonSymbols::NoButtons',
    'QAbstractSpinBox::PlusMinus':      'QAbstractSpinBox::ButtonSymbols::PlusMinus',
    'QAbstractSpinBox::UpDownArrows':   'QAbstractSpinBox::ButtonSymbols::UpDownArrows',

    'QAbstractSpinBox::CorrectToNearestValue': 'QAbstractSpinBox::CorrectionMode::CorrectToNearestValue',
    'QAbstractSpinBox::CorrectToPreviousValue': 'QAbstractSpinBox::CorrectionMode::CorrectToPreviousValue',

    'QAbstractSpinBox::AdaptiveDecimalStepType':    'QAbstractSpinBox::StepType::AdaptiveDecimalStepType',
    'QAbstractSpinBox::DefaultStepType':            'QAbstractSpinBox::StepType::DefaultStepType',

    'QAction::NoRole':                  'QAction::MenuRole::NoRole',
    'QAction::TextHeuristicRole':       'QAction::MenuRole::TextHeuristicRole',
    'QAction::ApplicationSpecificRole': 'QAction::MenuRole::ApplicationSpecificRole',
    'QAction::AboutQtRole':             'QAction::MenuRole::AboutQtRole',
    'QAction::AboutRole':               'QAction::MenuRole::AboutRole',
    'QAction::PreferencesRole':         'QAction::MenuRole::PreferencesRole',
    'QAction::QuitRole':                'QAction::MenuRole::QuitRole',

    'QCalendarWidget::LongDayNames':            'QCalendarWidget::HorizontalHeaderFormat::LongDayNames',
    'QCalendarWidget::NoHorizontalHeader':      'QCalendarWidget::HorizontalHeaderFormat::NoHorizontalHeader',
    'QCalendarWidget::ShortDayNames':           'QCalendarWidget::HorizontalHeaderFormat::ShortDayNames',
    'QCalendarWidget::SingleLetterDayNames':    'QCalendarWidget::HorizontalHeaderFormat::SingleLetterDayNames',

    'QCalendarWidget::NoSelection':     'QCalendarWidget::SelectionMode::NoSelection',
    'QCalendarWidget::SingleSelection': 'QCalendarWidget::SelectionMode::SingleSelection',

    'QCalendarWidget::ISOWeekNumbers':      'QCalendarWidget::VerticalHeaderFormat::ISOWeekNumbers',
    'QCalendarWidget::NoVerticalHeader':    'QCalendarWidget::VerticalHeaderFormat::NoVerticalHeader',

    'QComboBox::InsertAfterCurrent':    'QComboBox::InsertPolicy::InsertAfterCurrent',
    'QComboBox::InsertAlphabetically':  'QComboBox::InsertPolicy::InsertAlphabetically',
    'QComboBox::InsertAtBottom':        'QComboBox::InsertPolicy::InsertAtBottom',
    'QComboBox::InsertAtCurrent':       'QComboBox::InsertPolicy::InsertAtCurrent',
    'QComboBox::InsertAtTop':           'QComboBox::InsertPolicy::InsertAtTop',
    'QComboBox::InsertBeforeCurrent':   'QComboBox::InsertPolicy::InsertBeforeCurrent',
    'QComboBox::NoInsert':              'QComboBox::InsertPolicy::NoInsert',

    'QComboBox::AdjustToContents':                      'QComboBox::SizeAdjustPolicy::AdjustToContents',
    'QComboBox::AdjustToContentsOnFirstShow':           'QComboBox::SizeAdjustPolicy::AdjustToContentsOnFirstShow',
    'QComboBox::AdjustToMinimumContentsLengthWithIcon': 'QComboBox::SizeAdjustPolicy::AdjustToMinimumContentsLengthWithIcon',

    'QDateTimeEdit::NoSection':             'QDateTimeEdit::Section::NoSection',
    'QDateTimeEdit::AmPmSection':           'QDateTimeEdit::Section::AmPmSection',
    'QDateTimeEdit::MSecSection':           'QDateTimeEdit::Section::MSecSection',
    'QDateTimeEdit::SecondSection':         'QDateTimeEdit::Section::SecondSection',
    'QDateTimeEdit::MinuteSection':         'QDateTimeEdit::Section::MinuteSection',
    'QDateTimeEdit::HourSection':           'QDateTimeEdit::Section::HourSection',
    'QDateTimeEdit::DaySection':            'QDateTimeEdit::Section::DaySection',
    'QDateTimeEdit::MonthSection':          'QDateTimeEdit::Section::MonthSection',
    'QDateTimeEdit::YearSection':           'QDateTimeEdit::Section::YearSection',

    'QDialogButtonBox::NoButton':           'QDialogButtonBox::StandardButton::NoButton',
    'QDialogButtonBox::Ok':                 'QDialogButtonBox::StandardButton::Ok',
    'QDialogButtonBox::Save':               'QDialogButtonBox::StandardButton::Save',
    'QDialogButtonBox::SaveAll':            'QDialogButtonBox::StandardButton::SaveAll',
    'QDialogButtonBox::Open':               'QDialogButtonBox::StandardButton::Open',
    'QDialogButtonBox::Yes':                'QDialogButtonBox::StandardButton::Yes',
    'QDialogButtonBox::YesToAll':           'QDialogButtonBox::StandardButton::YesToAll',
    'QDialogButtonBox::No':                 'QDialogButtonBox::StandardButton::No',
    'QDialogButtonBox::NoToAll':            'QDialogButtonBox::StandardButton::NoToAll',
    'QDialogButtonBox::Abort':              'QDialogButtonBox::StandardButton::Abort',
    'QDialogButtonBox::Retry':              'QDialogButtonBox::StandardButton::Retry',
    'QDialogButtonBox::Ignore':             'QDialogButtonBox::StandardButton::Ignore',
    'QDialogButtonBox::Close':              'QDialogButtonBox::StandardButton::Close',
    'QDialogButtonBox::Cancel':             'QDialogButtonBox::StandardButton::Cancel',
    'QDialogButtonBox::Discard':            'QDialogButtonBox::StandardButton::Discard',
    'QDialogButtonBox::Help':               'QDialogButtonBox::StandardButton::Help',
    'QDialogButtonBox::Apply':              'QDialogButtonBox::StandardButton::Apply',
    'QDialogButtonBox::Reset':              'QDialogButtonBox::StandardButton::Reset',
    'QDialogButtonBox::RestoreDefaults':    'QDialogButtonBox::StandardButton::RestoreDefaults',

    'QDockWidget::DockWidgetClosable':          'QDockWidget::DockWidgetFeature::DockWidgetClosable',
    'QDockWidget::DockWidgetFloatable':         'QDockWidget::DockWidgetFeature::DockWidgetFloatable',
    'QDockWidget::DockWidgetMovable':           'QDockWidget::DockWidgetFeature::DockWidgetMovable',
    'QDockWidget::DockWidgetVerticalTitleBar':  'QDockWidget::DockWidgetFeature::DockWidgetVerticalTitleBar',
    'QDockWidget::NoDockWidgetFeatures':        'QDockWidget::DockWidgetFeature::NoDockWidgetFeatures',

    'QFontComboBox::AllFonts':          'QFontComboBox::FontFilter::AllFonts',
    'QFontComboBox::MonospacedFonts':   'QFontComboBox::FontFilter::MonospacedFonts',
    'QFontComboBox::NonScalableFonts':  'QFontComboBox::FontFilter::NonScalableFonts',
    'QFontComboBox::ProportionalFonts': 'QFontComboBox::FontFilter::ProportionalFonts',
    'QFontComboBox::ScalableFonts':     'QFontComboBox::FontFilter::ScalableFonts',

    'QFontDatabase::Any':                   'QFontDatabase::WritingSystem::Any',
    'QFontDatabase::Latin':                 'QFontDatabase::WritingSystem::Latin',
    'QFontDatabase::Greek':                 'QFontDatabase::WritingSystem::Greek',
    'QFontDatabase::Cyrillic':              'QFontDatabase::WritingSystem::Cyrillic',
    'QFontDatabase::Armenian':              'QFontDatabase::WritingSystem::Armenian',
    'QFontDatabase::Hebrew':                'QFontDatabase::WritingSystem::Hebrew',
    'QFontDatabase::Arabic':                'QFontDatabase::WritingSystem::Arabic',
    'QFontDatabase::Syriac':                'QFontDatabase::WritingSystem::Syriac',
    'QFontDatabase::Thaana':                'QFontDatabase::WritingSystem::Thaana',
    'QFontDatabase::Devanagari':            'QFontDatabase::WritingSystem::Devanagari',
    'QFontDatabase::Bengali':               'QFontDatabase::WritingSystem::Bengali',
    'QFontDatabase::Gurmukhi':              'QFontDatabase::WritingSystem::Gurmukhi',
    'QFontDatabase::Gujarati':              'QFontDatabase::WritingSystem::Gujarati',
    'QFontDatabase::Oriya':                 'QFontDatabase::WritingSystem::Oriya',
    'QFontDatabase::Tamil':                 'QFontDatabase::WritingSystem::Tamil',
    'QFontDatabase::Telugu':                'QFontDatabase::WritingSystem::Telugu',
    'QFontDatabase::Kannada':               'QFontDatabase::WritingSystem::Kannada',
    'QFontDatabase::Malayalam':             'QFontDatabase::WritingSystem::Malayalam',
    'QFontDatabase::Sinhala':               'QFontDatabase::WritingSystem::Sinhala',
    'QFontDatabase::Thai':                  'QFontDatabase::WritingSystem::Thai',
    'QFontDatabase::Lao':                   'QFontDatabase::WritingSystem::Lao',
    'QFontDatabase::Tibetan':               'QFontDatabase::WritingSystem::Tibetan',
    'QFontDatabase::Myanmar':               'QFontDatabase::WritingSystem::Myanmar',
    'QFontDatabase::Georgian':              'QFontDatabase::WritingSystem::Georgian',
    'QFontDatabase::Khmer':                 'QFontDatabase::WritingSystem::Khmer',
    'QFontDatabase::SimplifiedChinese':     'QFontDatabase::WritingSystem::SimplifiedChinese',
    'QFontDatabase::TraditionalChinese':    'QFontDatabase::WritingSystem::TraditionalChinese',
    'QFontDatabase::Japanese':              'QFontDatabase::WritingSystem::Japanese',
    'QFontDatabase::Korean':                'QFontDatabase::WritingSystem::Korean',
    'QFontDatabase::Vietnamese':            'QFontDatabase::WritingSystem::Vietnamese',
    'QFontDatabase::Other':                 'QFontDatabase::WritingSystem::Other',
    'QFontDatabase::Symbol':                'QFontDatabase::WritingSystem::Symbol',
    'QFontDatabase::Ogham':                 'QFontDatabase::WritingSystem::Ogham',
    'QFontDatabase::Runic':                 'QFontDatabase::WritingSystem::Runic',
    'QFontDatabase::Nko':                   'QFontDatabase::WritingSystem::Nko',

    'QFormLayout::AllNonFixedFieldsGrow':   'QFormLayout::FieldGrowthPolicy::AllNonFixedFieldsGrow',
    'QFormLayout::ExpandingFieldsGrow':     'QFormLayout::FieldGrowthPolicy::ExpandingFieldsGrow',
    'QFormLayout::FieldsStayAtSizeHint':    'QFormLayout::FieldGrowthPolicy::FieldsStayAtSizeHint',

    'QFormLayout::DontWrapRows':    'QFormLayout::RowWrapPolicy::DontWrapRows',
    'QFormLayout::WrapLongRows':    'QFormLayout::RowWrapPolicy::WrapLongRows',
    'QFormLayout::WrapAllRows':     'QFormLayout::RowWrapPolicy::WrapAllRows',

    'QFrame::Box':          'QFrame::Shape::Box',
    'QFrame::HLine':        'QFrame::Shape::HLine',
    'QFrame::NoFrame':      'QFrame::Shape::NoFrame',
    'QFrame::Panel':        'QFrame::Shape::Panel',
    'QFrame::StyledPanel':  'QFrame::Shape::StyledPanel',
    'QFrame::VLine':        'QFrame::Shape::VLine',
    'QFrame::WinPanel':     'QFrame::Shape::WinPanel',

    'QFrame::Plain':    'QFrame::Shadow::Plain',
    'QFrame::Raised':   'QFrame::Shadow::Raised',
    'QFrame::Sunken':   'QFrame::Shadow::Sunken',

    'QGraphicsView::CacheNone':         'QGraphicsView::CacheMode::CacheNone',
    'QGraphicsView::CacheBackground':   'QGraphicsView::CacheMode::CacheBackground',

    'QGraphicsView::DontAdjustForAntialiasing': 'QGraphicsView::OptimizationFlags::DontAdjustForAntialiasing',
    'QGraphicsView::DontSavePainterState':      'QGraphicsView::OptimizationFlags::DontSavePainterState',

    'QGraphicsView::NoAnchor':          'QGraphicsView::ViewportAnchor::NoAnchor',
    'QGraphicsView::AnchorViewCenter':  'QGraphicsView::ViewportAnchor::AnchorViewCenter',
    'QGraphicsView::AnchorUnderMouse':  'QGraphicsView::ViewportAnchor::AnchorUnderMouse',

    'QGraphicsView::BoundingRectViewportUpdate':    'QGraphicsView::ViewportUpdateMode::BoundingRectViewportUpdate',
    'QGraphicsView::FullViewportUpdate':            'QGraphicsView::ViewportUpdateMode::FullViewportUpdate',
    'QGraphicsView::MinimalViewportUpdate':         'QGraphicsView::ViewportUpdateMode::MinimalViewportUpdate',
    'QGraphicsView::NoViewportUpdate':              'QGraphicsView::ViewportUpdateMode::NoViewportUpdate',
    'QGraphicsView::SmartViewportUpdate':           'QGraphicsView::ViewportUpdateMode::SmartViewportUpdate',

    'QLayout::SetDefaultConstraint':    'QLayout::SizeConstraint::SetDefaultConstraint',
    'QLayout::SetFixedSize':            'QLayout::SizeConstraint::SetFixedSize',
    'QLayout::SetMaximumSize':          'QLayout::SizeConstraint::SetMaximumSize',
    'QLayout::SetMinAndMaxSize':        'QLayout::SizeConstraint::SetMinAndMaxSize',
    'QLayout::SetMinimumSize':          'QLayout::SizeConstraint::SetMinimumSize',
    'QLayout::SetNoConstraint':         'QLayout::SizeConstraint::SetNoConstraint',

    'QLCDNumber::Bin':  'QLCDNumber::Mode::Bin',
    'QLCDNumber::Dec':  'QLCDNumber::Mode::Dec',
    'QLCDNumber::Hex':  'QLCDNumber::Mode::Hex',
    'QLCDNumber::Oct':  'QLCDNumber::Mode::Oct',

    'QLCDNumber::Filled':   'QLCDNumber::SegmentStyle::Filled',
    'QLCDNumber::Flat':     'QLCDNumber::SegmentStyle::Flat',
    'QLCDNumber::Outline':  'QLCDNumber::SegmentStyle::Outline',

    'QLineEdit::NoEcho':                'QLineEdit::EchoMode::NoEcho',
    'QLineEdit::Normal':                'QLineEdit::EchoMode::Normal',
    'QLineEdit::Password':              'QLineEdit::EchoMode::Password',
    'QLineEdit::PasswordEchoOnEdit':    'QLineEdit::EchoMode::PasswordEchoOnEdit',

    'QListView::LeftToRight':   'QListView::Flow::LeftToRight',
    'QListView::TopToBottom':   'QListView::Flow::TopToBottom',

    'QListView::Batched':       'QListView::LayoutMode::Batched',
    'QListView::SinglePass':    'QListView::LayoutMode::SinglePass',

    'QListView::Free':      'QListView::Movement::Free',
    'QListView::Snap':      'QListView::Movement::Snap',
    'QListView::Static':    'QListView::Movement::Static',

    'QListView::Adjust':    'QListView::ResizeMode::Adjust',
    'QListView::Fixed':     'QListView::ResizeMode::Fixed',

    'QListView::IconMode':  'QListView::ViewMode::IconMode',
    'QListView::ListMode':  'QListView::ViewMode::ListMode',

    'QMdiArea::SubWindowView':  'QMdiArea::ViewMode::SubWindowView',
    'QMdiArea::TabbedView':     'QMdiArea::ViewMode::TabbedView',

    'QMdiArea::ActivationHistoryOrder': 'QMdiArea::WindowOrder::ActivationHistoryOrder',
    'QMdiArea::CreationOrder':          'QMdiArea::WindowOrder::CreationOrder',
    'QMdiArea::StackingOrder':          'QMdiArea::WindowOrder::StackingOrder',

    'QPainter::Antialiasing':           'QPainter::RenderHint::Antialiasing',
    'QPainter::LosslessImageRendering': 'QPainter::RenderHint::LosslessImageRendering',
    'QPainter::SmoothPixmapTransform':  'QPainter::RenderHint::SmoothPixmapTransform',
    'QPainter::TextAntialiasing':       'QPainter::RenderHint::TextAntialiasing',

    'QPlainTextEdit::NoWrap':       'QPlainTextEdit::LineWrapMode::NoWrap',
    'QPlainTextEdit::WidgetWidth':  'QPlainTextEdit::LineWrapMode::WidgetWidth',

    'QProgressBar::BottomToTop':  'QProgressBar::Direction::BottomToTop',
    'QProgressBar::TopToBottom':  'QProgressBar::Direction::TopToBottom',

    'QQuickWidget::SizeRootObjectToView':   'QQuickWidget::ResizeMode::SizeRootObjectToView',
    'QQuickWidget::SizeViewToRootObject':   'QQuickWidget::ResizeMode::SizeViewToRootObject',

    'QSizePolicy::Fixed':               'QSizePolicy::Policy::Fixed',
    'QSizePolicy::Minimum':             'QSizePolicy::Policy::Minimum',
    'QSizePolicy::Maximum':             'QSizePolicy::Policy::Maximum',
    'QSizePolicy::Preferred':           'QSizePolicy::Policy::Preferred',
    'QSizePolicy::MinimumExpanding':    'QSizePolicy::Policy::MinimumExpanding',
    'QSizePolicy::Expanding':           'QSizePolicy::Policy::Expanding',
    'QSizePolicy::Ignored':             'QSizePolicy::Policy::Ignored',

    'QSlider::NoTicks':         'QSlider::TickPosition::NoTicks',
    'QSlider::TicksAbove':      'QSlider::TickPosition::TicksAbove',
    'QSlider::TicksBelow':      'QSlider::TickPosition::TicksBelow',
    'QSlider::TicksBothSides':  'QSlider::TickPosition::TicksBothSides',
    'QSlider::TicksLeft':       'QSlider::TickPosition::TicksLeft',
    'QSlider::TicksRight':      'QSlider::TickPosition::TicksRight',

    'QTabWidget::North':    'QTabWidget::TabPosition::North',
    'QTabWidget::South':    'QTabWidget::TabPosition::South',
    'QTabWidget::West':     'QTabWidget::TabPosition::West',
    'QTabWidget::East':     'QTabWidget::TabPosition::East',

    'QTabWidget::Rounded':      'QTabWidget::TabShape::Rounded',
    'QTabWidget::Triangular':   'QTabWidget::TabShape::Triangular',

    'QTextEdit::AutoAll':           'QTextEdit::AutoFormattingFlag::AutoAll',
    'QTextEdit::AutoBulletList':    'QTextEdit::AutoFormattingFlag::AutoBulletList',
    'QTextEdit::AutoNone':          'QTextEdit::AutoFormattingFlag::AutoNone',

    'QTextEdit::FixedColumnWidth':  'QTextEdit::LineWrapMode::FixedColumnWidth',
    'QTextEdit::FixedPixelWidth':   'QTextEdit::LineWrapMode::FixedPixelWidth',
    'QTextEdit::NoWrap':            'QTextEdit::LineWrapMode::NoWrap',
    'QTextEdit::WidgetWidth':       'QTextEdit::LineWrapMode::WidgetWidth',

    'QToolButton::DelayedPopup':    'QToolButton::ToolButtonPopupMode::DelayedPopup',
    'QToolButton::InstantPopup':    'QToolButton::ToolButtonPopupMode::InstantPopup',
    'QToolButton::MenuButtonPopup': 'QToolButton::ToolButtonPopupMode::MenuButtonPopup',

    'QWizard::CancelButtonOnLeft':              'QWizard::WizardOption::CancelButtonOnLeft',
    'QWizard::DisabledBackButtonOnLastPage':    'QWizard::WizardOption::DisabledBackButtonOnLastPage',
    'QWizard::ExtendedWatermarkPixmap':         'QWizard::WizardOption::ExtendedWatermarkPixmap',
    'QWizard::HaveCustomButton1':               'QWizard::WizardOption::HaveCustomButton1',
    'QWizard::HaveCustomButton2':               'QWizard::WizardOption::HaveCustomButton2',
    'QWizard::HaveCustomButton3':               'QWizard::WizardOption::HaveCustomButton3',
    'QWizard::HaveFinishButtonOnEarlyPages':    'QWizard::WizardOption::HaveFinishButtonOnEarlyPages',
    'QWizard::HaveHelpButton':                  'QWizard::WizardOption::HaveHelpButton',
    'QWizard::HaveNextButtonOnLastPage':        'QWizard::WizardOption::HaveNextButtonOnLastPage',
    'QWizard::HelpButtonOnRight':               'QWizard::WizardOption::HelpButtonOnRight',
    'QWizard::IgnoreSubTitles':                 'QWizard::WizardOption::IgnoreSubTitles',
    'QWizard::IndependentPages':                'QWizard::WizardOption::IndependentPages',
    'QWizard::NoBackButtonOnLastPage':          'QWizard::WizardOption::NoBackButtonOnLastPage',
    'QWizard::NoBackButtonOnStartPage':         'QWizard::WizardOption::NoBackButtonOnStartPage',
    'QWizard::NoCancelButton':                  'QWizard::WizardOption::NoCancelButton',
    'QWizard::NoCancelButtonOnLastPage':        'QWizard::WizardOption::NoCancelButtonOnLastPage',
    'QWizard::NoDefaultButton':                 'QWizard::WizardOption::NoDefaultButton',

    'QWizard::AeroStyle':       'QWizard::WizardStyle::AeroStyle',
    'QWizard::ClassicStyle':    'QWizard::WizardStyle::ClassicStyle',
    'QWizard::MacStyle':        'QWizard::WizardStyle::MacStyle',
    'QWizard::ModernStyle':     'QWizard::WizardStyle::ModernStyle',
}
