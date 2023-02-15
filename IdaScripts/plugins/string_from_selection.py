import idaapi
import ida_bytes
import ida_nalt

popup_action_names = []
class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)
 
    def finish_populating_widget_popup(self, form, popup):
        global popup_action_names
        form_type = idaapi.get_widget_type(form)
        if form_type == idaapi.BWN_DISASM:
            for action_name in popup_action_names:
                idaapi.attach_action_to_popup(form, popup, action_name, None)
 
class StringFromSelectionPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_PROC
    comment = "Define a string from selection, useful for non-null terminated strings"
    help = "Select a region and right click to define as a string of that length"
    wanted_name = "String From Selection"
    wanted_hotkey = ""
    
    def init(self):
        idaapi.msg("String From Selection :: init\n")
        AddToPopup('definestr:add_action', 'Define string from selection', DefineStringAction(), '', None)
 
        self.hooks = Hooks()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP
 
    def run(self):
        idaapi.msg("String From Selection :: run\n")
 
    def term(self):
        idaapi.msg("String From Selection :: term\n")
        if self.hooks:
            self.hooks.unhook()
 
        idaapi.unregister_action('definestr:add_action')
 
class EA_Action(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
 
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET
 
class DefineStringAction(EA_Action):
    def activate(self, ctx):
        t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
        if idaapi.read_selection(view, t0, t1):
            start, end = t0.place(view).toea(), t1.place(view).toea()
            end += idaapi.get_item_size(end)
        else:
            start = idaapi.get_screen_ea()
 
            if start == idaapi.BADADDR:
                print('String From Selection  :: Screen EA == idaapi.BADADDR')
                return 0
 
            end = start + idaapi.get_item_size(start)
 
        if start == idaapi.BADADDR:
            print('String From Selection :: Selection EA == idaapi.BADADDR')
            return 0
 
        if start == end:
            print('String From Selection :: Selection is of zero length, nothing to define')
            return 0
 
        ida_bytes.create_strlit(start, end-start, ida_nalt.STRTYPE_TERMCHR)
        return 1
 
def AddToPopup(action_name, display, handler, shortcut, tooltip, icon=None):
    global popup_action_names
 
    if tooltip == None:
        tooltip = action_name
 
    if idaapi.register_action(idaapi.action_desc_t(
                action_name,
                display,
                handler,
                shortcut,
                tooltip
            )):
 
        popup_action_names.append(action_name)
    else:
        print('String From Selection :: Error registering action %s' % (action_name))
 
def PLUGIN_ENTRY(*args, **kwargs):
    return StringFromSelectionPlugin()
