import logging

import ida_name
import ida_struct
import idc
import idaapi
from idaapi import BADADDR

from .. import cpp_utils
from .. import utils

log = logging.getLogger("medigate")

class RTTIParser(object):
    RTTI_OBJ_STRUC_NAME = "rtti_obj"

    @classmethod
    def init_parser(cls):
        cls.found_classes = set()
    
    @classmethod
    def get_compiler_abbr(cls):
        return idaapi.get_compiler_abbr(idaapi.get_inf_structure().cc.id)
    
    @classmethod
    def extract_rtti_info_from_data(cls, ea=None):
        if ea is None:
            ea = idc.here()
        typeinfo = cls.parse_rtti_header(ea)
        return cls.extract_rtti_info_from_typeinfo(typeinfo)

    @classmethod
    def extract_rtti_info_from_typeinfo(cls, typeinfo):
        if typeinfo in cls.found_classes:
            return
        rtti_obj = cls.parse_typeinfo(typeinfo)
        if rtti_obj is None:
            return
        log.info("%s: Parsed typeinfo", rtti_obj.name)
        cls.found_classes.add(rtti_obj.typeinfo)
        for parent_typeinfo, _, offset in rtti_obj.raw_parents:
            parent_updated_name = None
            parent_rtti_obj = cls.extract_rtti_info_from_typeinfo(parent_typeinfo)
            if parent_rtti_obj:
                parent_updated_name = parent_rtti_obj.name
            else:
                built_rtti_obj_name = ida_name.get_ea_name(parent_typeinfo)
                if built_rtti_obj_name.endswith(cls.RTTI_OBJ_STRUC_NAME):
                    parent_updated_name = built_rtti_obj_name.rstrip(
                        "_" + cls.RTTI_OBJ_STRUC_NAME
                    )
            if parent_updated_name is not None:
                rtti_obj.updated_parents.append((parent_updated_name, offset))

        log.debug("%s: Finish setup parents", rtti_obj.name)
        if not rtti_obj.create_structs():
            return False
        rtti_obj.make_rtti_obj_pretty()
        rtti_obj.find_vtables()
        return rtti_obj

    def __init__(self, parents, typeinfo):
        self.raw_parents = []
        self.updated_parents = []
        self.typeinfo = typeinfo
        self.orig_name = self.name = self.get_typeinfo_name(self.typeinfo)
        for parent_typeinf, parent_offset in parents:
            parent_name = self.get_typeinfo_name(parent_typeinf)
            if parent_name is not None:
                self.raw_parents.append((parent_typeinf, parent_name, parent_offset))
        self.struct_id = None
        self.struct_ptr = None

    def create_structs(self):
        self.name, self.struct_id = utils.add_struc_retry(self.name)
        if self.struct_id == BADADDR or self.name is None:
            return False
        self.struct_ptr = ida_struct.get_struc(self.struct_id)
        if self.struct_ptr is None:
            log.exception("self.struct_ptr is None at %s", self.name)
        previous_parent_offset = 0
        previous_parent_size = 0
        previous_parent_struct_id = BADADDR
        for parent_name, parent_offset in self.updated_parents:
            if (
                parent_offset - previous_parent_offset > previous_parent_size
                and previous_parent_struct_id != BADADDR
            ):
                utils.expand_struct(
                    previous_parent_struct_id, parent_offset - previous_parent_offset
                )
            baseclass_id = ida_struct.get_struc_id(parent_name)
            baseclass_size = ida_struct.get_struc_size(baseclass_id)
            if baseclass_id == BADADDR or baseclass_size == 0:
                log.warning(
                    "bad struct id or size: %s(0x%x:%s) - %s, %d",
                    self.name,
                    parent_offset,
                    parent_name,
                    baseclass_id,
                    baseclass_size,
                )

            cpp_utils.add_baseclass(self.name, parent_name, parent_offset)
            previous_parent_offset = parent_offset
            previous_parent_size = baseclass_size
            previous_parent_struct_id = baseclass_id
        if self.updated_parents:
            utils.refresh_struct(self.struct_ptr)

        return True

    def find_vtables(self):
        is_vtable_found = False
        for xref in utils.get_drefs(self.typeinfo):
            if self.try_parse_vtable(xref) is not None:
                is_vtable_found = True
        if not is_vtable_found:
            log.debug(
                "find_vtable(%s): Couldn't find any vtable ->" " Interface!", self.name
            )
            if len(self.updated_parents) == 0:
                cpp_utils.install_vtables_union(self.name)
                pass

    def try_parse_vtable(self, ea):
        pass

    def create_vtable_struct(self, vtable_offset):
        return cpp_utils.create_vtable_struct(self.struct_ptr, self.name, vtable_offset)

    def make_rtti_obj_pretty(self):
        pass

    @classmethod
    def parse_rtti_header(cls, ea):
        pass

    @classmethod
    def parse_typeinfo(cls, typeinfo):
        pass

    def get_typeinfo_name(self, typeinfo):
        pass
