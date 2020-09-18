"""
                        _____       _         _           _
     /\                / ____|     | |       | |         | |
    /  \   _ __  _ __ | |  __  __ _| |_ ___  | |     __ _| |__  ___
   / /\ \ | '_ \| '_ \| | |_ |/ _` | __/ _ \ | |    / _` | '_ \/ __|
  / ____ \| |_) | |_) | |__| | (_| | ||  __/ | |___| (_| | |_) \__ \
 /_/    \_\ .__/| .__/ \_____|\__,_|\__\___| |______\__,_|_.__/|___/
          | |   | |
          |_|   |_|
## IDA Script to resolve Dridex API
"""

import idautils
import pefile
import zlib
import os

# ---------------------- Functions ---------------------- #

def get_path_dirs():
    return [x for x in os.path.expandvars("%PATH%").split(";") if x]

def generate_hashes_table(key):
    hashes = []
    for path_dir in get_path_dirs():
        for dll_name in os.listdir(path_dir):
            dll_hash = get_dridex_hash(dll_name, dll=True, key=key)
            dll_dict = {'name': dll_name, 'hash': dll_hash, 'imports': []}
            hashes.append(dll_dict)
    return hashes

def get_dridex_hash(s, dll, key):
    return hex(((zlib.crc32(s.upper().encode() if dll else s.encode()) & 0xffffffff) ^ key))

def api_resolver(dll_hash, api_hash, hashes, key):
    for item in hashes:
        if dll_hash != item['hash']:
            continue
        if not item['imports']:
            for path_dir in get_path_dirs():
                if not os.path.exists(os.path.join(path_dir, item["name"])):
                    continue
                pe = pefile.PE(os.path.join(path_dir, item["name"]))
                exp_list = []
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    try:
                        exp_list.append(exp.name.decode())
                    except:
                        continue
                for import_name in exp_list:
                    _hash = get_dridex_hash(import_name, dll=False, key=key)
                    item['imports'].append({'name': import_name, 'hash': _hash})
        for api in item['imports']:
            if api_hash == api['hash']:
                return "{}!{}".format(item['name'], api['name'])
        return "{}!unknown".format(item['name'])

def resolve_apis(resolver_offset, hashes_table, xor_key):
    for xref in idautils.XrefsTo(resolver_offset):
        off = idc.prev_head(xref.frm)
        # This loop will search for the hash that is being passed by the function
        # It's limited to 100 searches to avoid possible infinite loops.
        dll, api = None, None
        for i in range(1, 101):
            if i == 100:
                print "[-] Cannot find hash for address: %s" % hex(xref.frm)
                break
            # If it's not a "push" operation, keep looking
            if idc.GetMnem(off) != "push":
                off = idc.prev_head(off)
                continue
            # If a "push" is identified, checks if it's the DLL or the API hash
            if not dll:
                dll = hex(idc.GetOperandValue(off, 0))
                off = idc.prev_head(off)
                continue
            # If the DLL was already found, then the second push is the API hash
            api_name = api_resolver(dll, hex(idc.GetOperandValue(off, 0)), hashes_table, xor_key)
            comment = "Unknown" if not api_name else api_name
            idc.set_cmt(xref.frm, comment, True)
            break

# ---------------------- Main ---------------------- #
def main(xor_key, resolver_function):
    hashes = generate_hashes_table(xor_key)
    resolve_apis(resolver_function, hashes, xor_key)

main(0xCBCB795B, 0x414F60)
