import ida_idaapi
import ida_kernwin
import ida_auto
import ida_hexrays
import logging
import os
import tempfile
from .. import utils


log = logging.getLogger("medigate")
file_handler = logging.FileHandler(os.path.join(tempfile.gettempdir(), 'medigate.log'))
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)

log.addHandler(file_handler)

from .hooks import CPPHooks, CPPUIHooks, HexRaysHooks
from ..rtti_parsers.parser_registry import ParserRegistry

plugin_state = 0
last_state = None
parser = None


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
        self.initialized = False

    def init(self):
        """
        This method is called when IDA is loading the plugin. It will first
        load the configuration file, then initialize all the modules.
        """
        def start_timer(code, old=0):
            def parser_yield():
                global parser
                global plugin_state
                if plugin_state == 0 and ida_auto.auto_is_ok():
                    if not ida_hexrays.init_hexrays_plugin():
                        log.info("hexrays not initialized yet")
                        return 1000
                    self.hexrays_hooks = HexRaysHooks()
                    self.is_decompiler_on = True
                    self.core_hook = CPPHooks(self.is_decompiler_on)
                    self.gui_hook = CPPUIHooks()
                    self.hook()
                    self.install_hotkey()
                    self.initialized = True

                    parser = ParserRegistry.get_fitting_parser()
                    parser.init_parser()
                    if parser is None:
                        log.info("parser failed")
                        return -1
                    plugin_state = 1
                if plugin_state == 1:
                    if not parser.finished:
                        parser.next_state()
                        return 100
                    return -1
                return 1000
            ida_kernwin.register_timer(1000, parser_yield)
        if utils.WORD_LEN is None:
            ida_idaapi.notify_when(ida_idaapi.NW_OPENIDB, start_timer)
        else:
            start_timer(0, 0)

        # check the PLUGIN_SKIP option, might remove the need for a timer
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
        if self.core_hook:
            self.core_hook.hook()
        if self.gui_hook:
            self.gui_hook.hook()
        self.hooking = True

    def unhook(self):
        if not self.initialized:
            return
        if self.hexrays_hooks:
            self.hexrays_hooks.unhook()
        if self.core_hook:
            self.core_hook.unhook()
        if self.gui_hook:
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
        ida_hexrays.term_hexrays_plugin()
