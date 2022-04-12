import ida_idaapi
import ida_kernwin
import idaapi
import logging
import os
import tempfile


log = logging.getLogger("medigate")
file_handler = logging.FileHandler(os.path.join(tempfile.gettempdir(),'medigate.log'))
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)

log.addHandler(file_handler)

from .hooks import CPPHooks, CPPUIHooks, HexRaysHooks
from ..rtti_parsers.parser_registry import ParserRegistry

class CPPPlugin(ida_idaapi.plugin_t):
    """
    This is the main class of the plugin. It subclasses plugin_t as required
    by IDA. It holds the modules of plugin, which themselves provides the
    functionality of the plugin (hooking/events, interface, networking, etc.).
    """

    # Mandatory definitions
    PLUGIN_NAME = "ida_cpp"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "Medigate"
    TOGGLE_HOTKEY = "CTRL+ALT+C"

    # These flags specify that the plugin should persist between databases
    # loading and saving, and should not have a menu entry.
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_HIDE
    comment = "CPP support plugin"
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        print("Im up")
        self.core_hook = None
        self.gui_hook = None
        self.hexrays_hooks = None
        self.hooking = False
        self.is_decompiler_on = False

    def init(self):
        """
        This method is called when IDA is loading the plugin. It will first
        load the configuration file, then initialize all the modules.
        """
        if idaapi.init_hexrays_plugin():
            self.hexrays_hooks = HexRaysHooks()
            self.is_decompiler_on = True
        self.core_hook = CPPHooks(self.is_decompiler_on)
        self.gui_hook = CPPUIHooks()
        self.hook()
        self.install_hotkey()
        def create_parser():
            if idaapi.get_auto_state() == idaapi.AU_NONE:
                idaapi.auto_wait()
                if idaapi.get_inf_structure().cc.id == 0 and not(idaapi.get_inf_structure().is_64bit() or idaapi.get_inf_structure().is_32bit()):
                    return 1000
                parser = ParserRegistry.get_fitting_parser()
                if parser is not None:
                    parser.init_parser()
                    parser.build_all()
                return -1
            return 1000
        def start_timer(code, old=0):
            idaapi.register_timer(1000, create_parser)
        idaapi.notify_when(idaapi.NW_OPENIDB, start_timer)
        
        keep = ida_idaapi.PLUGIN_KEEP
        return keep

    def toggle_hooks(self):
        if self.hooking:
            self.unhook()
        else:
            self.hook()
        print("C++ plugin is now: %s" % ("On" if self.hooking else "Off"))

    def hook(self):
        if self.hexrays_hooks:
            self.hexrays_hooks.hook()
        self.core_hook.hook()
        self.gui_hook.hook()
        self.hooking = True

    def unhook(self):
        if self.hexrays_hooks:
            self.hexrays_hooks.unhook()
        self.core_hook.unhook()
        self.gui_hook.unhook()
        self.hooking = False

    def install_hotkey(self):
        ida_kernwin.add_hotkey(self.TOGGLE_HOTKEY, self.toggle_hooks)

    @classmethod
    def description(cls):
        """Return the description displayed in the console."""
        return "{} v{}".format(cls.PLUGIN_NAME, cls.PLUGIN_VERSION)

    def run(self, _):
        """
        This method is called when IDA is running the plugin as a script.
        """
        ida_kernwin.warning("IDACpp cannot be run as a script")
        return False

    def term(self):
        """
        This method is called when IDA is unloading the plugin. It will
        terminated all the modules, then save the configuration file.
        """
        self.unhook()
        idaapi.term_hexrays_plugin()
