## mev: https://www.unknowncheats.me/forum/general-programming-and-reversing/343177-easy-nop-ida-plugin.html
import idaapi

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
 
class EasyNopPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_PROC
    comment = "Easy nopping tool for you nopping needs"
    help = "Use Shift+N to nop out current line or selection"
    wanted_name = "Easy Nop"
    wanted_hotkey = ""
 
    def init(self):
        idaapi.msg("Easy Nop :: init\n")
        AddToPopup('nopaction:add_action', 'Nop line or selection', NopAction(), 'Shift+N', None)
 
        self.hooks = Hooks()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP
 
    def run(self):
        idaapi.msg("Easy Nop :: run\n")
 
    def term(self):
        idaapi.msg("Easy Nop :: term\n")
        if self.hooks:
            self.hooks.unhook()
 
        idaapi.unregister_action('nopaction:add_action')
 
class EA_Action(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
 
    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_WIDGET
 
class NopAction(EA_Action):
    def activate(self, ctx):
        t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
        if idaapi.read_selection(view, t0, t1):
            start, end = t0.place(view).toea(), t1.place(view).toea()
            end += idaapi.get_item_size(end)
        else:
            start = idaapi.get_screen_ea()
 
            if start == idaapi.BADADDR:
                print('Easy Nop :: Screen EA == idaapi.BADADDR')
                return 0
 
            end = start + idaapi.get_item_size(start)
 
        if start == idaapi.BADADDR:
            print('Easy Nop :: Selection EA == idaapi.BADADDR')
            return 0
 
        if start == end:
            print('Easy Nop :: Nothing to nop')
            return 0
 
        for x in range(start, end):
            # will prob fail on archs that don't have a nop instruction but whatever
            idaapi.assemble(x, 0, x, True, "nop")
 
        for x in range(start + 1, end):
            idaapi.hide_item(x)
 
        # Must do this else it bugs out on 2x 1 byte instructions being nopped
        idaapi.hide_item(start)
        idaapi.unhide_item(start)
 
        # Search for hidden nops and add to count
        while idaapi.get_byte(end) == 0x90 and idaapi.is_hidden_item(end) == True:
            end += 1
 
        count = end - start
 
        if count > 1:
            idaapi.set_cmt(start, "truncated nops (%d)" % (count), False)
 
        print(end)
        print(start)
 
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
        print('Easy Nop :: Error registering action %s' % (action_name))
 
def PLUGIN_ENTRY(*args, **kwargs):
    return EasyNopPlugin()
