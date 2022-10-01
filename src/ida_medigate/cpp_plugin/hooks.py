import logging
import ida_frame
import ida_funcs
import ida_hexrays
import ida_idp
import ida_kernwin
import ida_nalt
import ida_name
import ida_struct
import idaapi
import idc
from idc import BADADDR
from .. import cpp_utils, utils
import time


log = logging.getLogger("medigate")


class CPPHooks(ida_idp.IDB_Hooks):
    def __init__(self, is_decompiler_on):
        super(CPPHooks, self).__init__()
        self.is_decompiler_on = is_decompiler_on
        self.last_update_action = 0

    def renamed(self, ea, new_name, local_name):
        current_time = time.time() * 1000
        if current_time - self.last_update_action < 10:
            return
        if utils.is_func(ea):
            self.unhook()
            func, args_list = cpp_utils.post_func_name_change(new_name, ea)
            for args in args_list:
                func(*args)
            self.hook()
        self.last_update_action = current_time

    def func_updated(self, pfn):
        self.unhook()
        func, args_list = cpp_utils.post_func_type_change(pfn)
        for args in args_list:
            func(*args)
        self.hook()
        return 0

    def renaming_struc_member(self, sptr, mptr, newname):
        if sptr.is_frame():
            return 0
        cpp_utils.post_struct_member_name_change(mptr, newname)
        return 0

    def struc_member_changed(self, sptr, mptr):
        self.unhook()
        cpp_utils.post_struct_member_type_change(mptr)
        self.hook()
        self.should_update = True
        return 0

    def ti_changed(self, ea, typeinf, fnames):
        if self.is_decompiler_on:
            res = ida_struct.get_member_by_id(ea)
            if res is not None:
                m, name, sptr = res
                if sptr.is_frame():
                    func = ida_funcs.get_func(ida_frame.get_func_by_frame(sptr.id))
                    if func is not None:
                        self.func_updated(func)
            elif utils.is_func(ea):
                self.func_updated(ida_funcs.get_func(ea))


class CPPUIHooks(ida_kernwin.View_Hooks):
    def view_dblclick(self, viewer, point):
        widget_type = ida_kernwin.get_widget_type(viewer)
        if not (widget_type == ida_kernwin.BWN_PSEUDOCODE or widget_type == ida_kernwin.BWN_STRUCTS):
            return
        # Decompiler or Structures window
        func_cand_name = None
        place, x, y = ida_kernwin.get_custom_viewer_place(viewer, False)
        if place.name() == "structplace_t":  # Structure window:
            structplace = ida_kernwin.place_t_as_structplace_t(place)
            if structplace is not None:
                s = ida_struct.get_struc(ida_struct.get_struc_by_idx(structplace.idx))
                if s:
                    member = ida_struct.get_member(s, structplace.offset)
                    if member:
                        func_cand_name = ida_struct.get_member_name(member.id)
        if func_cand_name is None:
            line = utils.get_curline_striped_from_viewer(viewer)
            func_cand_name = cpp_utils.find_valid_cppname_in_line(line, x)
        if func_cand_name is not None:
            func_cand_ea = ida_name.get_name_ea(BADADDR, func_cand_name)
            if func_cand_ea is not None and utils.is_func(func_cand_ea):
                idc.jumpto(func_cand_ea)


class Polymorphism_fixer_visitor_t(ida_hexrays.ctree_visitor_t):
    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self.counter = 0
        self.selections = []

    def get_vtables_union_name(self, expr):
        if expr.op != ida_hexrays.cot_memref:  # ///< x.m
            return None
        typeinf = expr.type
        if typeinf is None:
            return None
        if not typeinf.is_union():
            return None
        union_name = typeinf.get_type_name()
        if not cpp_utils.is_vtables_union_name(union_name):
            return None
        return union_name

    def build_classes_chain(self, expr):
        chain = []
        n_expr = expr.x
        while n_expr.op == ida_hexrays.cot_memref:
            chain.insert(0, n_expr.type.get_type_name())
            n_expr = n_expr.x
        chain.insert(0, n_expr.type.get_type_name())
        if n_expr.op == ida_hexrays.cot_memptr:
            chain.insert(0, n_expr.x.type.get_pointed_object().get_type_name())
        elif n_expr.op == ida_hexrays.cot_idx:
            log.debug("encountered idx, skipping")
            return None
        return chain

    def find_best_member(self, chain, union_name):
        for cand in chain:
            result = ida_struct.get_member_by_fullname(union_name + "." + cand)
            if result:
                m, s = result
                log.debug("Found class: %s, offset=%d", cand, m.soff)
                return m
        return None

    def get_vtable_sptr(self, m):
        vtable_type = utils.get_member_tinfo(m)
        if not (vtable_type and vtable_type.is_ptr()):
            log.debug("vtable_type isn't ptr %s", vtable_type)
            return None

        vtable_struc_typeinf = vtable_type.get_pointed_object()
        if not (vtable_struc_typeinf and vtable_struc_typeinf.is_struct()):
            log.debug("vtable isn't struct (%s)", vtable_struc_typeinf.dstr())
            return None

        vtable_struct_name = vtable_struc_typeinf.get_type_name()
        vtable_sptr = utils.get_sptr_by_name(vtable_struct_name)
        if vtable_sptr is None:
            log.debug(
                "0x%x: Oh no %s is not a valid struct",
                self.cfunc.entry_ea,
                vtable_struct_name,
            )
            return None

        return vtable_sptr

    def get_ancestors(self):
        vtable_expr = self.parents.back().cexpr
        if vtable_expr.op not in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
            return None

        if self.parents.size() < 2:
            log.debug("parents size less than 2 (%d)", self.parents.size())
            return None

        idx_cexpr = None
        funcptr_parent = None
        funcptr_item = self.parents.at(self.parents.size() - 2)
        if not funcptr_item.is_expr():
            log.debug(
                "funcptr_item is not expr!: %s %s %d",
                type(funcptr_item),
                funcptr_item.is_expr(),
                funcptr_item.op,
            )
            return None
        funcptr_expr = funcptr_item.cexpr
        if funcptr_expr.op == ida_hexrays.cot_idx:
            idx_cexpr = funcptr_expr
            if self.parents.size() < 4:
                log.debug(
                    "there is idx but parents size less than 3 (%d)",
                    self.parents.size(),
                )
                return None

            funcptr_expr = self.parents.at(self.parents.size() - 3)
            if not funcptr_expr.is_expr():
                log.debug("funcptr isn't expr")
                return None
            funcptr_expr = funcptr_expr.cexpr
            funcptr_parent = self.parents.at(self.parents.size() - 4)
            if not funcptr_parent.is_expr():
                log.debug("funcptr_parent isn't expr")
                return None
            funcptr_parent = funcptr_parent.cexpr
        if funcptr_expr.op not in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):

            log.debug("funcptr_expr isn't -> (%s)", funcptr_expr.opname)
            return None

        return funcptr_parent, funcptr_expr, idx_cexpr, vtable_expr

    def fix_member_idx(self, idx_cexpr):
        num = 0
        if idx_cexpr:
            # wrong vtable*, so it might be too short struct, like:
            #   .vtable.PdmAcqServiceIf[1].___cxa_pure_virtual_2
            if idx_cexpr.y.op != ida_hexrays.cot_num:
                log.debug(
                    "0x%x: idx doesn't contains a num but %s",
                    self.cfunc.entry_ea,
                    idx_cexpr.y.opname,
                )
                return -1
            num = idx_cexpr.y.get_const_value()
            if not (idx_cexpr.type and idx_cexpr.type.is_struct()):
                log.debug(
                    "0x%x idx type isn't struct %s", self.cfunc.entry_ea, idx_cexpr.type
                )
                return -1
            idx_struct = utils.get_struc_from_tinfo(idx_cexpr.type)
            if idx_struct is None:
                log.debug(
                    "0x%x idx type isn't pointing to struct %s",
                    self.cfunc.entry_ea,
                    idx_cexpr.type,
                )
                return -1
            struct_size = ida_struct.get_struc_size(idx_struct)
            num *= struct_size
        return num

    def get_vtable_member_type(self, vtable_sptr, offset):
        vtable_struct_name = ida_struct.get_struc_name(vtable_sptr.id)
        try:
            funcptr_member = ida_struct.get_member(vtable_sptr, offset)
        except TypeError as _:
            log.exception("0x%x: bad offset: 0x%x", self.cfunc.entry_ea, offset)
            return None

        if funcptr_member is None:
            log.debug(
                "0x%x:  %s.%d is not a valid struct member",
                self.cfunc.entry_ea,
                vtable_struct_name,
                offset,
            )
            return None

        funcptr_member_type = utils.get_member_tinfo(funcptr_member)
        if not funcptr_member_type.is_funcptr():
            log.debug(
                "0x%x: member type (%s) isn't funcptr!",
                self.cfunc.entry_ea,
                funcptr_member_type.dstr(),
            )
            return None

        return funcptr_member_type

    def find_funcptr(self, m):
        ancestors = self.get_ancestors()
        if ancestors is None:
            return None
        funcptr_parent, funcptr_expr, idx_cexpr, vtable_expr = ancestors

        vtable_sptr = self.get_vtable_sptr(m)
        if vtable_sptr is None:
            return None
        offset = self.fix_member_idx(idx_cexpr)
        if offset == -1:
            return None
        funcptr_member_type = self.get_vtable_member_type(
            vtable_sptr, funcptr_expr.m + offset
        )
        return funcptr_member_type

    def dump_expr(self, e):
        log.debug("dump: %s", e.opname)
        while e.op in [
            ida_hexrays.cot_memref,
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_cast,
            ida_hexrays.cot_call,
        ]:
            if e.op in [ida_hexrays.cot_memref, ida_hexrays.cot_memptr]:
                log.debug("(%s, %d, %s)", e.opname, e.m, e.type.dstr())
            else:
                log.debug("(%s, %s)", e.opname, e.type.dstr())
            e = e.x

    def find_ea(self):
        i = self.parents.size() - 1
        parent = self.parents.at(i)
        ea = BADADDR
        while i >= 0 and (parent.is_expr() or parent.op == ida_hexrays.cit_expr):
            if parent.cexpr.ea != BADADDR:
                ea = parent.cexpr.ea
                break
            i -= 1
            parent = self.parents.at(i)
        return ea

    def visit_expr(self, expr):
        union_name = self.get_vtables_union_name(expr)
        if union_name is None:
            return 0
        log.debug("Found union -%s", union_name)

        chain = self.build_classes_chain(expr)
        if chain is None:
            return 0

        m = self.find_best_member(chain, union_name)
        if m is None:
            return 0

        ea = self.find_ea()

        funcptr_member_type = self.find_funcptr(m)

        if ea == BADADDR:
            log.debug("BADADDR")
            return 0
        log.debug("Found VTABLES, ea: 0x%x", ea)
        self.selections.append((ea, m.soff, funcptr_member_type))
        return 0


class HexRaysHooks(idaapi.Hexrays_Hooks):
    def __init__(self, *args):
        idaapi.Hexrays_Hooks.__init__(self, *args)
        self.another_decompile_ea = False

    def maturity(self, cfunc, maturity):
        if maturity in [idaapi.CMAT_FINAL]:
            if self.another_decompile_ea:
                self.another_decompile_ea = None
                return 0
            # if maturity in [idaapi. CMAT_CPA]:
            # if maturity in [idaapi.CPA]:
            pfv = Polymorphism_fixer_visitor_t(cfunc)
            pfv.apply_to_exprs(cfunc.body, None)
            log.debug("results: %s", pfv.selections)
            if pfv.selections != []:
                for ea, offset, funcptr_member_type in pfv.selections:
                    intvec = idaapi.intvec_t()
                    # TODO: Think if needed to distinguished between user
                    #   union members chooses and plugin chooses
                    if not cfunc.get_user_union_selection(ea, intvec):
                        intvec.push_back(offset)
                        cfunc.set_user_union_selection(ea, intvec)
                        if funcptr_member_type is not None:
                            ida_nalt.set_op_tinfo(ea, 0, funcptr_member_type)
                cfunc.save_user_unions()
                self.another_decompile_ea = cfunc.entry_ea

        return 0

    def refresh_pseudocode(self, vu):
        if self.another_decompile_ea:
            log.debug("decompile again")
            ea = self.another_decompile_ea
            ida_hexrays.mark_cfunc_dirty(ea, False)
            cfunc = ida_hexrays.decompile(ea)
            self.another_decompile_ea = None
            vu.switch_to(cfunc, True)
        return 0
