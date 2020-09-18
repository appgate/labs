import argparse
import os
import re
import socket
import struct
import sys
from binascii import hexlify, unhexlify
from datetime import datetime
from hashlib import sha256
from shutil import rmtree
from zlib import crc32

import pefile as pefile
from Crypto.Cipher import ARC4

banner = \
    """
                            _____       _         _           _         
         /\                / ____|     | |       | |         | |        
        /  \   _ __  _ __ | |  __  __ _| |_ ___  | |     __ _| |__  ___ 
       / /\ \ | '_ \| '_ \| | |_ |/ _` | __/ _ \ | |    / _` | '_ \/ __|
      / ____ \| |_) | |_) | |__| | (_| | ||  __/ | |___| (_| | |_) \__ \\
     /_/    \_\ .__/| .__/ \_____|\__,_|\__\___| |______\__,_|_.__/|___/
              | |   | |                                                 
              |_|   |_|    

    ## Dridex Analysis Toolkit                                             
    """
NULL_BYTES = b'\x00' * 32
RC4_KEY_LENGTH = 0x28
C2_FUNCTIONS = {
    '2020': [
        b'0fb70d([a-f0-9]{8})a3[a-f0-9]{8}a1[a-f0-9]{8}8908803d([a-f0-9]{8})0a77[a-f0-9]{2}a0[a-f0-9]{8}5?7?33ff803d[a-f0-9]{8}00',
        b'66a1([a-f0-9]{8})8b[a-f0-9]{10}0fb7[a-f0-9]{2}89[a-f0-9]{2}a0([a-f0-9]{8})3c0a77[a-f0-9]{2}8a'],
    '2019': [b'66a1([a-f0-9]{8})8b0d[a-f0-9]{8}0fb7c08901a0([a-f0-9]{8})3c0a77[a-f0-9]{2}a0[a-f0-9]{8}']
}


# ---------------------------------- Standalone Functions ---------------------------------- #


def rc4_decrypt(key, data):
    """
    Decrypt data using RC4
    :param key: RC4 Key
    :param data: data
    :return: str
    """
    return ARC4.new(key).decrypt(data)


def decrypt_network_data(data_path, decryption_key):
    """
    Decrypts Dridex network communication
    :param data_path: File with binary data sent to C2 server
    :param decryption_key: RC4 decryption key
    :return: str
    """
    with open(data_path, 'rb') as f:
        data = f.read()

    checksum, enc_data = data[:4], data[4:]

    if int(hexlify(checksum), 16) != crc32(enc_data):
        print("\n[-] Invalid checksum for the data, probably corrupted")
        return

    print("[+] Checksum is valid, trying to decrypt")
    try:
        enc_data = rc4_decrypt(decryption_key, enc_data)
        return enc_data
    except Exception as e:
        print(f"[-] Cannot decrypt: {repr(e)}")


# ---------------------------------- Helper Class ---------------------------------- #

class DridexHelper:

    def __init__(self, file_path):
        if not os.path.isfile(file_path):
            print("[-] Please, provide a valid file.\n")
            sys.exit(1)

        try:
            self.pe = pefile.PE(file_path)
            if not self.pe.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE:
                print("[-] This script doesn't support 64-bit binaries (yet)")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Problem loading PE file: {repr(e)}\n")
            sys.exit(1)

        self.dridex_data = {}
        self.file_path = file_path

        with open(self.file_path, 'rb') as f:
            self.file_binary = f.read()

        self.__print_file_info()
        self.__pe_unmapper()

    def extract_c2(self):
        """
        Searches Dridex binary using regex to find the function where the addresses are parsed.
        :return: None
        """
        data = self.__find_c2_function()
        if not data:
            print("\n[-] Didn't found the C2 parsing function.\n")
            return

        offsets = {
            'bot_id': {
                'rva': int(hexlify(unhexlify(data[0][0])[::-1]), 16),
            },
            'c2_table': {
                'rva': int(hexlify(unhexlify(data[0][1])[::-1]), 16),
            }
        }
        offsets = self.__calculate_offsets(offsets)
        if 'raw' in offsets['bot_id']:
            bot_id_off = offsets['bot_id']['raw']
            self.dridex_data['bot_id'] = int(hexlify(self.file_binary[bot_id_off:bot_id_off + 2][::-1]), 16)

        if 'raw' in offsets['c2_table']:
            c2_off = offsets['c2_table']['raw']
            c2_total = int(hexlify(self.file_binary[c2_off:c2_off + 1]), 16)

            self.dridex_data['c2'] = {'total': c2_total, 'addresses': []}

            c2_ips_off = c2_off + 1
            for i in range(0, c2_total):
                ip = socket.inet_ntoa(self.file_binary[c2_ips_off:c2_ips_off + 4])
                port = int(hexlify(self.file_binary[c2_ips_off + 4:c2_ips_off + 6][::-1]), 16)
                self.dridex_data['c2']['addresses'].append(f"{ip}:{port}")
                c2_ips_off += 6

    def decrypt_strings(self):
        """
        Tries to decrypt strings from Dridex.
        :return: None
        """
        rdata = None
        for section in self.pe.sections:
            if b'.rdata' in section.Name:
                rdata = section
                break

        if not rdata:
            print('\n[-] Cannot find .rdata section')
            return

        strings_offsets = self.__search_enc_strings(rdata)
        raw_strings = self.__decrypt_strings(strings_offsets)
        decrypted_strings = self.__get_treated_strings(raw_strings)
        if decrypted_strings:
            self.dridex_data['strings'] = decrypted_strings

    # ---------------------------------- Internal ---------------------------------- #

    def __find_c2_function(self):
        """
        Searches for the function that parses the C2 address
        :return: list
        """
        for year in C2_FUNCTIONS:
            for pattern in C2_FUNCTIONS[year]:
                data = re.findall(pattern, hexlify(self.file_binary))
                if data:
                    print(f"\n[+] Found C2 parsing function, pattern from {year}\n")
                    return data

    def __calculate_offsets(self, offsets):
        """
        Calculate raw offsets for the items we need to parse
        :param offsets: dict + RVA addresses
        :return: dict
        """
        found = False
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        for item in offsets:
            for section in self.pe.sections:
                if offsets[item]['rva'] >= (section.VirtualAddress + section.Misc_VirtualSize + image_base):
                    continue
                found = True
                print("'{}' at section '{}'".format(item, section.Name.strip(b'\x00').decode()))
                offsets[item]['raw'] = self.__get_raw_offset(offsets[item]['rva'], section)
                break

        if not found:
            print("[-] Cannot find the raw offsets, please, check if the file was dumped correctly.")
        return offsets

    def __get_raw_offset(self, rva_offset, section):
        """
        Calculates the raw offset based on the RVA
        :param rva_offset: RVA address
        :param section: Section where data is located
        :return: int
        """
        return (rva_offset - section.VirtualAddress + section.PointerToRawData) - self.pe.OPTIONAL_HEADER.ImageBase

    def __pe_unmapper(self):
        """
        Since Dridex payload is usually dumped from memory, checks if the PE is mapped to memory.
        If yes, tries to unmap, since we need the correct offsets to extract the data
        :return: None
        """
        if len(self.pe.sections) == 0:
            return

        off_loc = self.pe.sections[0].PointerToRawData
        if self.file_binary[off_loc:off_loc + 32] != NULL_BYTES:
            return

        print("\n[-] File seems to be mapped, trying to fix...")
        new_pe = self.file_binary[:self.pe.OPTIONAL_HEADER.SizeOfHeaders]
        for section in self.pe.sections:
            section_data = self.file_binary[section.VirtualAddress:section.VirtualAddress + section.SizeOfRawData]
            if len(new_pe) > section.PointerToRawData:
                print("\n[-] Cannot unmap the file")
                return
            while len(new_pe) < section.PointerToRawData:
                new_pe += b'\x00'
            new_pe += section_data
            section_name = section.Name.decode().strip('\x00')
            print("[+] Section '{}' moved to {}".format(section_name, hex(section.PointerToRawData)))

        new_file_path = f"{self.file_path}_unmapped.bin"
        print(f"[+] Saving unmapped file to: {new_file_path}")
        with open(new_file_path, 'wb') as f:
            f.write(new_pe)

        self.file_path = new_file_path
        self.file_binary = new_pe
        try:
            self.pe = pefile.PE(new_file_path)
        except Exception as e:
            print(f"[-] Problem loading new PE file: {repr(e)}\n")
            sys.exit(1)

        print("[+] Done")

    def __search_enc_strings(self, section):
        """
        Searches for offsets with encrypted strings
        :param section: .rdata section
        :return: dict
        """
        print('\n[+] Searching for encrypted strings (this might take a while)')
        data = self.file_binary[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
        strings_offsets = {}
        off = section.PointerToRawData
        key = 0
        for i in range(0, len(data), 4):
            addr = (off - section.PointerToRawData + section.VirtualAddress + self.pe.OPTIONAL_HEADER.ImageBase)
            if re.findall(hexlify(struct.pack("<I", addr)), hexlify(self.file_binary)):
                strings_offsets[key] = {'rva': hex(addr), 'raw': off}
                key += 1
            off += 4
        print(f"[+] Found possible {len(strings_offsets)} encrypted blocks")
        return strings_offsets

    def __decrypt_strings(self, strings_offsets):
        """
        Tries to decrypt the blocks we found and return data in raw format
        :param strings_offsets: offsets of possible encrypted blocks
        :return: dict
        """
        raw_strings = {}
        for index in strings_offsets:
            last = False if index + 1 in strings_offsets else True
            start = strings_offsets[index]['raw']
            end = start + self.file_binary[start:].find(b'\x00') + 1 if last else strings_offsets[index + 1]['raw']

            if (end - start) <= RC4_KEY_LENGTH:
                continue

            enc = self.file_binary[start:end]
            block_size = 4

            # checking if at least the 4 first bytes can be decrypted without generating gibberish
            dec = rc4_decrypt(enc[:RC4_KEY_LENGTH][::-1], enc[RC4_KEY_LENGTH:RC4_KEY_LENGTH + block_size])
            if any(c != 0x00 and not (37 < c < 127) for c in dec):
                # ignore block
                continue

            # increasing the decryption block 4 by 4
            while block_size < len(enc) - RC4_KEY_LENGTH:
                block_size += 4
                dec_temp = rc4_decrypt(enc[:RC4_KEY_LENGTH][::-1], enc[RC4_KEY_LENGTH:RC4_KEY_LENGTH + block_size])
                if any(c != 0x00 and not (31 < c < 127) for c in dec_temp):
                    break
                dec = dec_temp

            rc4_keys = re.findall(b"ShellFolder\x00(.+?);(.+?)\x00", dec)
            if rc4_keys:
                self.dridex_data['rc4_keys'] = [rc4_keys[0][0], rc4_keys[0][1]]

            raw_strings[index] = {
                'rva': strings_offsets[index]['rva'],
                'encrypted': enc,
                'decrypted': dec
            }
        return raw_strings

    @staticmethod
    def __get_treated_strings(raw_strings):
        """
        Tries to polish the decrypted strings.
        :param raw_strings:
        :return: list
        """
        final_strings = {}
        for i in raw_strings:
            strings = raw_strings[i]['decrypted'].decode(errors='ignore')
            if len(strings.split('\x00')) > 20:
                final_strings[raw_strings[i]['rva']] = [ii.replace('\x00', '') for ii in strings.split('\x00\x00')]
                continue
            final_strings[raw_strings[i]['rva']] = strings.split('\x00')
        return final_strings

    def __print_file_info(self):
        """
        Displays basic info about the PE file.
        :return: None
        """
        print("\n[+] Binary info\n")
        print(f"## Type: {'DLL' if self.pe.is_dll() else 'Executable'}")
        print(f"## Compilation Date: {str(datetime.fromtimestamp(self.pe.FILE_HEADER.TimeDateStamp))}")
        print(f"## SHA256: {sha256(self.file_binary).hexdigest()}")


# ---------------------------------- Main ---------------------------------- #

if __name__ == '__main__':

    print(banner)

    parser = argparse.ArgumentParser(description='This script tries to extract C2 addresses from Dridex.')
    parser.add_argument('-f', '--file', help='Unpacked Dridex sample to parse.')
    parser.add_argument('-a', '--all', help='Runs C2 extractor and strings decrypter.', action='store_true')
    parser.add_argument('-n', '--network_key', help='RC4 key to decrypt network data')
    parser.add_argument('-c', '--c2', help='Extracts Botnet ID and C2 server.', action='store_true')
    parser.add_argument('-s', '--strings', help='Decrypts strings.', action='store_true')
    parser.add_argument('-v', '--verbose', help='Prints output in console.', action='store_true')
    args = parser.parse_args()

    if not args.file:
        print("[-] Please, provide the file.\n")
        sys.exit(1)

    output_path = os.path.join(os.path.dirname(args.file), f'{os.path.basename(args.file)}_output')
    if os.path.isdir(output_path):
        rmtree(output_path, ignore_errors=True)
    os.mkdir(output_path)
    print(f"[+] Output will be saved at: {output_path}")

    if args.network_key:
        print("\n[+] RC4 key provided, trying to decrypt data")
        dec_data = decrypt_network_data(args.file, args.network_key)
        if dec_data:
            with open(os.path.join(output_path, f"{os.path.basename(args.file)}_decrypted"), 'w') as f:
                f.write(dec_data.decode(errors='ignore'))
            if args.verbose:
                print(f"\n[+] Decrypted data: \n\n{dec_data}")
        print(f"\n[+] Done\n")
        sys.exit(0)

    if not args.c2 and not args.strings:
        args.all = True

    # ----------------------------- Helper ---------------------------- #

    helper = DridexHelper(args.file)

    if args.c2 or args.all:
        helper.extract_c2()

    if args.strings or args.all:
        helper.decrypt_strings()

    # ----------------------------- Output ---------------------------- #

    if 'bot_id' in helper.dridex_data:
        if args.verbose:
            print(f"\n## Botnet ID:\n{helper.dridex_data['bot_id']}")

        with open(os.path.join(output_path, 'botnet_id.txt'), 'w') as f:
            f.write(str(helper.dridex_data['bot_id']))

    if 'c2' in helper.dridex_data:

        if args.verbose:
            print("\n## C2 Addresses")

        with open(os.path.join(output_path, 'c2_addresses.txt'), 'w') as f:
            for item in helper.dridex_data['c2']['addresses']:
                f.write(f"{item}\n")

                if args.verbose:
                    print(item)

    if 'rc4_keys' in helper.dridex_data:
        if args.verbose:
            print("\n[+] Found possible RC4 keys used to encrypt network communication")
            with open(os.path.join(output_path, 'rc4_keys.txt'), 'w') as f:
                for rc4_key in helper.dridex_data['rc4_keys']:
                    f.write(f"{rc4_key.decode(errors='ignore')}\n")
                    if args.verbose:
                        print(rc4_key)

    if 'strings' in helper.dridex_data:
        if args.verbose:
            print("\n## Please, check the output folder to see the decrypted strings")

        strings_path = os.path.join(output_path, 'decrypted_strings')
        os.mkdir(strings_path)

        for rva in helper.dridex_data['strings']:
            with open(os.path.join(strings_path, f"{rva}.txt"), 'w') as f:
                for string in helper.dridex_data['strings'][rva]:
                    f.write(f"{string}\n")

    print("\n[+] Done\n")
