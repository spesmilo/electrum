from kivy.uix.boxlayout import BoxLayout
from kivy.adapters.dictadapter import DictAdapter
from kivy.adapters.listadapter import ListAdapter
from kivy.properties import ObjectProperty, ListProperty, AliasProperty
from kivy.uix.listview import (ListItemButton, ListItemLabel, CompositeListItem,
                               ListView)
from kivy.lang import Builder
from kivy.metrics import dp, sp

Builder.load_string('''
<GridView>
    header_view: header_view
    content_view: content_view
    BoxLayout:
        orientation: 'vertical'
        padding: '0dp', '2dp'
        BoxLayout:
            id: header_box
            orientation: 'vertical'
            size_hint: 1, None
            height: '30dp'
            ListView:
                id: header_view
        BoxLayout:
            id: content_box
            orientation: 'vertical'
            ListView:
                id: content_view

<-HorizVertGrid>
    header_view: header_view
    content_view: content_view
    ScrollView:
        id: scrl
        do_scroll_y: False
        RelativeLayout:
            size_hint_x: None
            width: max(scrl.width, dp(sum(root.widths)))
            BoxLayout:
                orientation: 'vertical'
                padding: '0dp', '2dp'
                BoxLayout:
                    id: header_box
                    orientation: 'vertical'
                    size_hint: 1, None
                    height: '30dp'
                    ListView:
                        id: header_view
                BoxLayout:
                    id: content_box
                    orientation: 'vertical'
                    ListView:
                        id: content_view

''')

class GridView(BoxLayout):
    """Workaround solution for grid view by using 2 list view.
    Sometimes the height of lines is shown properly."""

    def _get_hd_adpt(self):
        return self.ids.header_view.adapter

    header_adapter = AliasProperty(_get_hd_adpt, None)
    '''
    '''

    def _get_cnt_adpt(self):
        return self.ids.content_view.adapter

    content_adapter = AliasProperty(_get_cnt_adpt, None)
    '''
    '''

    headers = ListProperty([])
    '''
    '''

    widths = ListProperty([])
    '''
    '''

    data = ListProperty([])
    '''
    '''

    getter = ObjectProperty(lambda item, i: item[i])
    '''
    '''
    on_context_menu = ObjectProperty(None)

    def __init__(self, **kwargs):
        self._from_widths = False
        super(GridView, self).__init__(**kwargs)
        #self.on_headers(self, self.headers)

    def on_widths(self, instance, value):
        if not self.get_root_window():
            return
        self._from_widths = True
        self.on_headers(instance, self.headers)
        self._from_widths = False

    def on_headers(self, instance, value):
        if not self._from_widths:
            return
        if not (value and self.canvas and self.headers):
            return
        widths = self.widths
        if len(self.widths) != len(value):
            return
        #if widths is not None:
        #    widths = ['%sdp' % i for i in widths]

        def generic_args_converter(row_index,
                                   item,
                                   is_header=True,
                                   getter=self.getter):
            cls_dicts = []
            _widths = self.widths
            getter = self.getter
            on_context_menu = self.on_context_menu

            for i, header in enumerate(self.headers):
                kwargs = {
                    'padding': ('2dp','2dp'),
                    'halign': 'center',
                    'valign': 'middle',
                    'size_hint_y': None,
                    'shorten': True,
                    'height': '30dp',
                    'text_size': (_widths[i], dp(30)),
                    'text': getter(item, i),
                }

                kwargs['font_size'] = '9sp'
                if is_header:
                    kwargs['deselected_color'] = kwargs['selected_color']  =\
                        [0, 1, 1, 1]
                else:  # this is content
                    kwargs['deselected_color'] = 1, 1, 1, 1
                    if on_context_menu is not None:
                        kwargs['on_press'] = on_context_menu

                if widths is not None:  # set width manually
                    kwargs['size_hint_x'] = None
                    kwargs['width'] = widths[i]

                cls_dicts.append({
                    'cls': ListItemButton,
                    'kwargs': kwargs,
                })

            return {
                'id': item[-1],
                'size_hint_y': None,
                'height': '30dp',
                'cls_dicts': cls_dicts,
            }

        def header_args_converter(row_index, item):
            return generic_args_converter(row_index, item)

        def content_args_converter(row_index, item):
            return generic_args_converter(row_index, item, is_header=False)


        self.ids.header_view.adapter = ListAdapter(data=[self.headers],
                                   args_converter=header_args_converter,
                                   selection_mode='single',
                                   allow_empty_selection=False,
                                   cls=CompositeListItem)

        self.ids.content_view.adapter = ListAdapter(data=self.data,
                                   args_converter=content_args_converter,
                                   selection_mode='single',
                                   allow_empty_selection=False,
                                   cls=CompositeListItem)
        self.content_adapter.bind_triggers_to_view(self.ids.content_view._trigger_reset_populate)

class HorizVertGrid(GridView):
    pass


if __name__ == "__main__":
    from kivy.app import App
    class MainApp(App):

        def build(self):
            data = []
            for i in range(90):
                data.append((str(i), str(i)))
            self.data = data
            return Builder.load_string('''
BoxLayout:
    orientation: 'vertical'
    HorizVertGrid:
        on_parent: if args[1]: self.content_adapter.data = app.data
        headers:['Address', 'Previous output']
        widths: [400, 500]

<Label>
    font_size: '16sp'
''')
    MainApp().run()
