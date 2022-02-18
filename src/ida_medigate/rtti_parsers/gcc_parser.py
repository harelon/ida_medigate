import logging

import ida_name
import idaapi
import idautils
import idc
from idaapi import BADADDR

from .rtti_parser_base import RTTIParser
from .parser_registry import ParserRegistry
from .. import cpp_utils
from .. import utils


class GccRTTIParser(RTTIParser):
    VMI = "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
    SI = "_ZTVN10__cxxabiv120__si_class_type_infoE"
    NONE = "_ZTVN10__cxxabiv117__class_type_infoE"
    pure_virtual_name = "__cxa_pure_virtual"

    @classmethod
    def init_parser(cls):
        super(GccRTTIParser, cls).init_parser()
        cls.OFFSET_FROM_TYPEINF_SYM = 2 * utils.WORD_LEN

        cls.RECORD_TYPEINFO_OFFSET = utils.WORD_LEN
        # class_type_info consts
        cls.CLASS_TYPE_TYPEINFO_OFFSET = 0
        cls.CLASS_TYPE_NAME_OFFSET = utils.WORD_LEN
        cls.CLASS_TYPE_SIZE = 2 * utils.WORD_LEN

        # si_class_type_info consts
        cls.SI_TYPEINFO_BASE_OFFSET = cls.CLASS_TYPE_SIZE

        # vmi_class_type_info consts
        cls.VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET = cls.CLASS_TYPE_SIZE + 4
        cls.VMI_TYPEINFO_BASE_CLASSES_OFFSET = cls.VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET + 4

        # base_class vmi helper
        cls.BASE_CLASS_TYPEINFO_OFFSET = 0
        cls.BASE_CLASS_ATTRS_OFFSET = cls.BASE_CLASS_TYPEINFO_OFFSET + utils.WORD_LEN
        cls.BASE_CLASS_SIZE = utils.WORD_LEN * 2

        cls.type_vmi = (
            ida_name.get_name_ea(idaapi.BADADDR, cls.VMI) + cls.OFFSET_FROM_TYPEINF_SYM
        )
        cls.type_si = (
            ida_name.get_name_ea(idaapi.BADADDR, cls.SI) + cls.OFFSET_FROM_TYPEINF_SYM
        )
        cls.type_none = (
            ida_name.get_name_ea(idaapi.BADADDR, cls.NONE) + cls.OFFSET_FROM_TYPEINF_SYM
        )
        cls.types = (cls.type_vmi, cls.type_si, cls.type_none)

    @classmethod
    def build_all(cls):
        for class_type in cls.types:
            logging.debug("Starting :%s %s" % (class_type, hex(class_type)))
            cls.build_class_type(class_type)
            logging.info("Done %s", class_type)

    @classmethod
    @utils.batchmode
    def build_class_type(cls, class_type):
        idx = 0
        for xref in idautils.XrefsTo(class_type - cls.OFFSET_FROM_TYPEINF_SYM):
            if (idx + 1) % 200 == 0:
                # idc.batch(0)
                logging.info("\t Done %s", idx)
                # ida_loader.save_database(None, 0)
                # idc.batch(1)
            if utils.get_ptr(xref.frm) != class_type:
                continue
            try:
                cls.extract_rtti_info_from_typeinfo(xref.frm)
            except Exception as e:
                logging.exception("Exception at 0x%x:", xref.frm)
            idx += 1

    @classmethod
    def parse_rtti_header(cls, ea):
        # offset = cls.read_offset(ea)
        typeinfo = cls.get_typeinfo_ea(ea)
        return typeinfo

    @classmethod
    def parse_typeinfo(cls, typeinfo):
        typeinfo_type = utils.get_ptr(typeinfo + cls.CLASS_TYPE_TYPEINFO_OFFSET)
        if typeinfo_type == cls.type_none:
            parents = []
        elif typeinfo_type == cls.type_si:
            parents = cls.parse_si_typeinfo(typeinfo)
        elif typeinfo_type == cls.type_vmi:
            parents = cls.parse_vmi_typeinfo(typeinfo)
        else:
            return None
        return GccRTTIParser(parents, typeinfo)

    @classmethod
    def parse_si_typeinfo(cls, typeinfo_ea):
        parent_typinfo_ea = utils.get_ptr(typeinfo_ea + cls.SI_TYPEINFO_BASE_OFFSET)
        return [(parent_typinfo_ea, 0)]

    @classmethod
    def parse_vmi_typeinfo(cls, typeinfo_ea):
        base_classes_num = idaapi.get_32bit(
            typeinfo_ea + cls.VMI_TYPEINFO_BASE_CLASSES_NUM_OFFSET
        )
        parents = []
        for i in range(base_classes_num):
            base_class_desc_ea = (
                typeinfo_ea
                + cls.VMI_TYPEINFO_BASE_CLASSES_OFFSET
                + i * cls.BASE_CLASS_SIZE
            )
            parent_typeinfo_ea = utils.get_ptr(
                base_class_desc_ea + cls.BASE_CLASS_TYPEINFO_OFFSET
            )
            parent_attrs = utils.get_word(
                base_class_desc_ea + cls.BASE_CLASS_ATTRS_OFFSET
            )
            parent_offset_in_cls = parent_attrs >> 8
            parents.append((parent_typeinfo_ea, parent_offset_in_cls))
        return parents

    @classmethod
    def get_typeinfo_ea(cls, ea):
        return utils.get_ptr(ea + cls.RECORD_TYPEINFO_OFFSET)

    @classmethod
    def get_typeinfo_name(cls, typeinfo_ea):
        name_ea = utils.get_ptr(typeinfo_ea + cls.CLASS_TYPE_NAME_OFFSET)
        if name_ea is None or name_ea == BADADDR:
            mangled_class_name = ida_name.get_ea_name(typeinfo_ea)
        else:
            mangled_class_name = "_Z" + idc.get_strlit_contents(name_ea).decode()
        class_name = ida_name.demangle_name(mangled_class_name, idc.INF_LONG_DN)
        return cls.strip_class_name(class_name)

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
        return cls.get_compiler_abbr() == 'gcc'

    def try_parse_vtable(self, ea):
        functions_ea = ea + utils.WORD_LEN
        func_ea, _ = cpp_utils.get_vtable_line(
            functions_ea,
            ignore_list=self.types,
            pure_virtual_name=self.pure_virtual_name,
        )
        if func_ea is None:
            return
        vtable_offset = utils.get_signed_int(ea - utils.WORD_LEN) * (-1)
        vtable_struct, this_type = self.create_vtable_struct(vtable_offset)
        cpp_utils.update_vtable_struct(
            functions_ea,
            vtable_struct,
            self.name,
            this_type,
            ignore_list=self.types,
            pure_virtual_name=self.pure_virtual_name,
        )
        return vtable_struct
    

ParserRegistry.register_parser(GccRTTIParser)
