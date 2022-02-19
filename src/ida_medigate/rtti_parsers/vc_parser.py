import logging

import ida_name
import idaapi
import idautils
import ida_bytes
import ida_xref
import idc
from idaapi import BADADDR

from .rtti_parser_base import RTTIParser
from .parser_registry import ParserRegistry
from .. import cpp_utils
from .. import utils


class VcRTTIParser(RTTIParser):
    type_info_string = ".?AVtype_info@@"
    pure_virtual_name = "_purecall"

    @classmethod
    def init_parser(cls):
        super(VcRTTIParser, cls).init_parser()
        cls.RVA_SIZE = 4
        # COL means Complete Object Locator
        # RTD means RTTI Type Descriptor
        cls.COL_RTD = 12
        # CHD means Class Hierarchy Descriptor
        cls.COL_CHD = cls.COL_RTD + cls.RVA_SIZE
        cls.COL_VTABLE_OFFSET = 4

        cls.RTD_NAME = utils.WORD_LEN * 2

        cls.CHD_COUNT = 8
        cls.CHD_ARRAY = 12
        

        # RBCD means RTTI Base Class Descriptor
        cls.RBCD_RTD = 0
        cls.RBCD_SUB_COUNT = cls.RVA_SIZE
        cls.RBCD_MEMBER_DISPLACEMENT = cls.RBCD_SUB_COUNT + 4
        
        cls.ZERO_INHERITANCE = 1

        cls.TYPE_DESCRIPTION_TO_HIERARCHEY_OFFSET = utils.WORD_LEN
        cls.type_info = None

        for string in idautils.Strings():
            if str(string) == cls.type_info_string:
                cls.type_info = utils.get_word(string.ea - cls.RTD_NAME)
                break

    @classmethod
    def build_all(cls):
        if cls.type_info is None:
            logging.error("Couldn't Find any rtti information")
            return
        # every rtti type descriptor is a static struct containing pointer to the vtable of type_info
        for rtd in idautils.XrefsTo(cls.type_info):
            # make sure the pointer to the vtable is from a data object and not a function
            if idc.get_func_name(rtd.frm):
                continue
            cls.build_class_type(rtd.frm)
            logging.info("Done %s", rtd)

    @classmethod
    @utils.batchmode
    def build_class_type(cls, class_type):
            try:
                cls.extract_rtti_info_from_typeinfo(class_type)
            except Exception as e:
                logging.exception("Exception at 0x%x:", class_type)

    @classmethod
    def parse_rtti_header(cls, ea):
        # offset = cls.read_offset(ea)
        typeinfo = cls.get_typeinfo_ea(ea)
        return typeinfo

    @classmethod
    def parse_typeinfo(cls, typeinfo):
        parents = list() 
        # check refrences to the type descriptor
        for xref in idautils.XrefsTo(typeinfo):
            # if the next word after the reference to our type descriptor is also a reference it means we are inside
            # the complete object locator
            if len(list(idautils.XrefsFrom(xref.frm - cls.COL_RTD + cls.COL_CHD))) > 0:
                break
        # get the COL
        class_type = xref.frm - cls.COL_RTD
        
        chd_ptr = class_type + cls.COL_CHD
        
        chd =  cls.get_rva_dref(chd_ptr) 
        parents_len = utils.get_signed_int(chd + cls.CHD_COUNT)
        # iterate over the Base class array
        if parents_len > cls.ZERO_INHERITANCE:
            parent_array = cls.get_rva_dref(chd + cls.CHD_ARRAY)
            i = cls.ZERO_INHERITANCE
            while i < parents_len:
                current_parent = parent_array + i * cls.RVA_SIZE
                current_parent_RBCD = cls.get_rva_dref(current_parent)
                current_parent_RTD = cls.get_rva_dref(current_parent_RBCD + cls.RBCD_RTD)
                # get rtti type descriptor for our parent class
                parents.append((current_parent_RTD, utils.get_signed_int(current_parent_RBCD + cls.RBCD_MEMBER_DISPLACEMENT)))
                i += utils.get_signed_int(current_parent_RBCD + cls.RBCD_SUB_COUNT) + 1
        return VcRTTIParser(parents, typeinfo)

    # rvas reference both the wanted reference and the imagebase
    @classmethod
    def get_rva_dref(cls, ea):
        imagebase = idaapi.get_imagebase()
        xref = ida_xref.get_first_dref_from(ea)
        while xref != idaapi.BADADDR:
            if xref != imagebase:
                return xref
            xref = ida_xref.get_next_dref_from(ea, xref)

    @classmethod
    def get_typeinfo_ea(cls, ea):
        return utils.get_ptr(ea + cls.RECORD_TYPEINFO_OFFSET)

    @classmethod
    def get_typeinfo_name(cls, typeinfo_ea):
        mangled_class_name = idc.get_strlit_contents(typeinfo_ea + cls.RTD_NAME).decode("ascii")
        return cls.strip_class_name(cls.demangle_name(mangled_class_name))

    @classmethod
    def demangle_name(cls, cls_name):
        if cls_name.startswith(".?A"):
            cls_name = cls_name[4:]
            new_name = "??1" + cls_name + "QAE@XZ"
            class_name = ida_name.demangle_name(new_name, ida_name.MNG_NODEFINIT)
            parts = class_name.split("~")
            name = parts[0][:-2]
            return name

    @classmethod
    def strip_class_name(cls, cls_name):
        pre_dict = {"`typeinfo for": ":"}
        words_dict = {
            "`anonymous namespace'": "ANONYMOUS",
            "`anonymous_namespace'": "ANONYMOUS",
            "`typeinfo for'": "",
        }
        chars_dict = {
            "<": "X",
            ">": "Z",
            "&": "A",
            "*": "P",
            " ": "_",
            ",": "C",
            "'": "U",
            "`": "T",
            "[": "O",
            "]": "P",
        }
        for target, strip in words_dict.items():
            cls_name = cls_name.replace(target, strip)
        for target, strip in chars_dict.items():
            cls_name = cls_name.replace(target, strip)
        return cls_name

    @classmethod
    def is_suitable(cls):
        return cls.get_compiler_abbr() == 'vc'

    def try_parse_vtable(self, ea):
        # check if we are in the COL
        col = ea - self.COL_RTD
        if len(list(idautils.XrefsFrom(col + self.COL_CHD))) == 0:
            return

        # get a valid reference to the virtual table with our rtti
        for ea in utils.get_drefs(col):
            functions_ea = ea + utils.WORD_LEN
            func_ea, _ = cpp_utils.get_vtable_line(
                functions_ea,
                pure_virtual_name=self.pure_virtual_name,
            )
            if func_ea:
                break

        if func_ea is None:
            return

        vtable_offset = utils.get_signed_int(col + self.COL_VTABLE_OFFSET)  
        vtable_struct, this_type = self.create_vtable_struct(vtable_offset)
        cpp_utils.update_vtable_struct(
            functions_ea,
            vtable_struct,
            self.name,
            this_type,
            pure_virtual_name=self.pure_virtual_name,
        )
        return vtable_struct
    

ParserRegistry.register_parser(VcRTTIParser)