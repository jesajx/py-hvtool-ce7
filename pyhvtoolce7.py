#!/usr/bin/env python3
#
# MIT License
#
# Copyright (c) 2022 Johannes Olegård
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

class Unpacker:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def seek(self, new_index):
        if new_index not in range(len(self.data)+1):
            raise IndexError("out of bounds")
        self.index = new_index

    def remaining_len(self):
        return len(self.data) - self.index

    def read_n(self, n):
        if n > self.remaining_len():
            raise IndexError("out of bounds")
        res = self.data[self.index : self.index + n]
        self.index += n
        return res

    def _read_int(self, num_bytes, endian, signed=False):
        return int.from_bytes(self.read_n(num_bytes), endian, signed=signed)

    def read_u8(self): return self.read_n(1)[0]
    def read_u16le(self): return self._read_int(2, 'little', signed=False)
    def read_u32le(self): return self._read_int(4, 'little', signed=False)

# See also: https://github.com/nlitsme/hvtool/
ENTRY_TYPE_NUMBER_FROM_NAME = {
    "ET_DATABASE" : 0x7,
    "ET_RECORD"   : 0x8,
    "ET_RECMORE"  : 0x9,
    "ET_VOLUME"   : 0xa,
    "ET_ROOTS"    : 0xb,
    "ET_KEY"      : 0xc,
    "ET_VALUE"    : 0xd,
    "ET_INDEX"    : 0xe,
}

ENTRY_TYPE_NAME_FROM_NUMBER = {v:k for k,v in ENTRY_TYPE_NUMBER_FROM_NAME.items()}

VALUE_TYPE_STRING     = 1
VALUE_TYPE_BINARY     = 3
VALUE_TYPE_DWORD      = 4
VALUE_TYPE_STRINGLIST = 7
VALUE_TYPE_MUI        = 21

# See also: <https://en.wikipedia.org/wiki/Windows_Registry#Root_keys>
ROOT_NAME_FROM_INDEX = ["HKCR", "HKCU", "HKLM", "HKU"] # indices matter

def make_reg_flatmap(res_dict, prefix, entry_id):
    if entry_id not in res_dict:
        return dict()
    entry_type = res_dict[entry_id]["type"]
    if entry_type == "ET_ROOTS":
        res = dict()
        for root_index,root_id in enumerate(res_dict[entry_id]["data"]):
            root_name = ROOT_NAME_FROM_INDEX[root_index]
            x = make_reg_flatmap(res_dict, prefix + "/" + root_name, root_id)
            if len(set(x.keys()).intersection(res.keys())) != 0:
                raise NotImplementedError()
            res.update(x)
        return res
    elif entry_type == "ET_VALUE":
        res = dict()
        while entry_id != 0 and entry_id in res_dict:
            if res_dict[entry_id]["type"] != "ET_VALUE":
                raise ValueError() # bug
            entry_data = res_dict[entry_id]["data"]
            entry_name = entry_data["name"]
            if entry_name in res:
                raise ValueError() # bug
            res[prefix + "/" + entry_name] = entry_data["value"]
            entry_id  = entry_data["next"]
        return res
    elif entry_type == "ET_KEY":
        res = dict()
        while entry_id != 0 and entry_id in res_dict:
            if res_dict[entry_id]["type"] != "ET_KEY":
                raise ValueError() # bug
            entry_data = res_dict[entry_id]["data"]
            entry_name = entry_data["name"]
            path = prefix + "/" + entry_name

            children = dict()
            if entry_data["first_child"] != 0:
                children = make_reg_flatmap(res_dict, path, entry_data["first_child"])
            if entry_data["first_value"] != 0:
                values = make_reg_flatmap(res_dict, path, entry_data["first_value"])
                if len(set(values.keys()).intersection(children.keys())) != 0:
                    raise ValueError() # bug
                children.update(values)

            if len(set(children.keys()).intersection(res.keys())) != 0:
                raise ValueError() # bug

            res.update(children)

            entry_id = entry_data["next_sibling"]

        return res
    else:
        raise NotImplementedError()

def parse_hivefile(data):
    p = Unpacker(data)

    header_size       = p.read_u32le() # 0x400
    _                 = p.read_u32le() # 0
    magic             = p.read_u32le()
    file_md5          = p.read_n(16)
    _                 = p.read_u32le() # 0
    file_size         = p.read_u32le()
    file_type         = p.read_u32le() # 0x1000
    boot_md5          = p.read_n(16)
    _                 = p.read_n(172)  # 0 0 ... 0
    base              = p.read_u32le() # 0xcd4f5000
    recovery_log_size = p.read_u32le() # 0
    is_reghive        = p.read_u32le() # 0xffffffff
    is_dbvol          = p.read_u32le() # 0
    _                 = p.read_n(24)


    if magic != int.from_bytes(b'EKIM', 'little'):
        raise ValueError("bad magic", magic)

    p.seek(0x1000)

    section_list = [p.read_u32le()] # always read the first entry even if null
    while True:
        section_offset = p.read_u32le()
        if section_offset == 0: # null as stop-value
            break
        section_list.append(section_offset)

    entry_dict = dict()
    for section_offset in section_list:
        p.seek(0x5000 + section_offset)
        section_magic = p.read_u32le()
        if section_magic != 0x20001004:
            raise ValueError("bad magic", magic)
        _ = p.read_u32le()
        _ = p.read_u32le()
        section_entry_list = [p.read_u32le() for _ in range(0x400)]

        for entry_header in section_entry_list:
            entry_offset = entry_header & 0x0ffffffc
            entry_flags = entry_header & 0b11
            if entry_flags != 0b01 or entry_offset >= len(p.data):
                continue

            p.seek(0x5000 + entry_offset)

            entry_rawsize = p.read_u32le()
            entry_type = entry_rawsize >> 28
            entry_size = entry_rawsize & ~0xf0000000

            _ = p.read_u32le() # 0
            entry_id = p.read_u32le()
            entry_rawdata = p.read_n(entry_size)

            entry_type_name = ENTRY_TYPE_NAME_FROM_NUMBER[entry_type]
            vp = Unpacker(entry_rawdata)

            if entry_type == ENTRY_TYPE_NUMBER_FROM_NAME["ET_ROOTS"]:
                root_ids = [vp.read_u32le() for _ in range(8)]
                entry_data = [x for x in root_ids if x != 0]
            elif entry_type == ENTRY_TYPE_NUMBER_FROM_NAME["ET_KEY"]:
                next_sibling = vp.read_u32le()
                first_child  = vp.read_u32le()
                first_value  = vp.read_u32le()
                name_len     = vp.read_u8()
                flags        = vp.read_u16le()
                _            = vp.read_u8()

                name = vp.read_n(name_len*2)
                name = name.decode("utf-16")
                entry_data = {
                    "name"         : name,
                    "next_sibling" : next_sibling,
                    "first_child"  : first_child,
                    "first_value"  : first_value,
                    "flags"        : flags,
                }
            elif entry_type == ENTRY_TYPE_NUMBER_FROM_NAME["ET_VALUE"]:
                value_next = vp.read_u32le()
                value_type = vp.read_u16le()
                value_value_len          = vp.read_u16le()
                value_name_len_and_stuff = vp.read_u16le()

                value_name_len = value_name_len_and_stuff & 0xFF
                value_name = vp.read_n(value_name_len*2).decode("utf-16")
                raw_value  = vp.read_n(value_value_len)

                interpreted_value = None

                if value_type == VALUE_TYPE_DWORD:
                    interpreted_value = int.from_bytes(raw_value, 'little')
                elif value_type in [VALUE_TYPE_BINARY, 0x0]: # TODO 0x0 => "blob"?
                    interpreted_value = raw_value
                elif value_type == VALUE_TYPE_STRING:
                    wide_char_list = []
                    vvp = Unpacker(raw_value)
                    while vvp.remaining_len() != 0:
                        wc = vvp.read_u16le()
                        if wc == 0:
                            break
                        wide_char_list.append(wc)
                    interpreted_value = b''.join(x.to_bytes(2, 'little')
                            for x in wide_char_list).decode("utf-16")
                elif value_type == VALUE_TYPE_MUI:
                    raise NotImplementedError()
                elif value_type == VALUE_TYPE_STRINGLIST: # "\0"-separated list of string
                    interpreted_value = raw_value.decode("utf-16")
                    if not interpreted_value.endswith("\0\0"): # last string is empty
                        raise ValueError()
                    interpreted_value = interpreted_value[:-2].split("\0")
                else:
                    raise NotImplementedError("unknown registry entry type", hex(value_type))
                entry_data = {"name": value_name, "value": interpreted_value,
                              "next": value_next}
            elif entry_type in ENTRY_TYPE_NAME_FROM_NUMBER.keys():
                raise NotImplementedError()
            else:
                raise ValueError("unknown reg entry type")

            entry_dict[entry_id] = {"type": entry_type_name, "data": entry_data}

    # XXX: the file seems to continue with a clone of the first part of the file. (backup?)

    flatreg = dict()
    for entry_id in entry_dict:
        if entry_dict[entry_id]["type"] == "ET_ROOTS":
            flatreg.update(make_reg_flatmap(entry_dict, "", entry_id))

    return flatreg

if __name__ == '__main__':
    [_, path] = sys.argv
    for k,v in sorted(parse_hivefile(open(path, "rb").read()).items()):
        print(k, repr(v))
