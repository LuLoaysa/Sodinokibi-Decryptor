"""
@author: Luis Loaysa 2022

Sodinokibi decryptor. Finds Salsa20 keys in memory and decrypts
files encrypted by Sodinokibi
"""

import re
import os
from Crypto.Cipher import Salsa20


def decrypt_file(folder_src, file_key_nonce):
    """Decrypting found files with Salsa20 algorithm, nonce and key"""
    new_folder = os.getcwd() + "\\" + 'Restored'
    for file in os.listdir(os.getcwd() + "\\" + folder_src):
        for secret, file_nonce in file_key_nonce.items():
            if file == file_nonce[1]:
                rel_nonce = file_nonce[0]  # Nonce is within list in a dictionary
                with open(os.path.join(os.getcwd() + "\\" + folder_src, file), 'rb') as f:
                    chunk = f.read()
                    nonce = bytes.fromhex(rel_nonce)  # converting to bytes
                    secret = bytes.fromhex(secret)
                    size = len(chunk)
                    end_64 = chunk[-64:]  # Start decrypting at the end of the file -64 bytes
                    begin = chunk[:size - 64]
                    encrypted = end_64 + begin
                    cipher = Salsa20.new(key=secret, nonce=nonce)
                    decrypted = cipher.decrypt(encrypted)
                    if not os.path.exists(new_folder):
                        os.makedirs(new_folder)
                    file_bytes = bytes.fromhex(decrypted.hex()[128:-336])  # Exact amount of metadata for the file
                    new_file = "recovered_" + os.path.splitext(file)[0]
                    print('[*]', new_file)
                    fho = open(new_folder + '\\' + new_file, 'wb')
                    fho.write(file_bytes)
                    fho.close()
                    f.close()


def search_file(incl_nonce, folder):
    """Finding files with a given nonce included in them"""
    files_nonce = {}
    for nonce in incl_nonce:
        for file in os.listdir(os.getcwd() + "\\" + folder):
            with open(os.path.join(os.getcwd() + "\\" + folder, file), 'rb') as f:
                reading = f.read().hex()[-232:]
                match = re.findall(nonce, reading)
                if match:
                    files_nonce.update({file: nonce})

    return files_nonce


def extracting_key(lists):
    """Matching and verifying keys found in memory"""
    filtered_keys = {}
    storing_keys = {}
    expand = [item for sublist in lists for item in sublist]  # Unpacking lists
    for key in expand:
        if key[40:48] == '6e642033' and key[120:128] == '7465206b':
            filtered_keys.update({key[8:40] + key[88:120]: key[48:64]})
            #  If second and fourth words exist in their location add to dictionary
            # key[8:40] + key[88:120] -> Key key[48:64] -> Nonce
    for key, nonce in filtered_keys.items():
        if key not in storing_keys.values():
            storing_keys.update({key: nonce})

    return storing_keys


def reading_file(name_file):
    """Reading dump file to extract Salsa20 keys"""
    chunk_sz = 131072
    count = 0
    read_ahead = []
    storing_keys = []
    try:
        print('[+] Finding Salsa20 keys loaded in memory...', '\n')
        with open(name_file, 'rb') as f:
            while True:
                count += 1
                dump = f.read(chunk_sz)
                chunk = dump.hex()
                expand = re.findall(r'65787061.{128}', chunk)
                if expand:
                    storing_keys.append(expand)

                if count % 2 != 0:
                    read_ahead.insert(0, dump[-500:])
                if count % 2 == 0:
                    read_ahead.insert(0, dump[:500])

                gap_bytes = [b''.join(read_ahead[0:2])]  # Join hex bytes to avoid breaks from cutting bytes
                for gap in gap_bytes:
                    gap_hex = gap.hex()
                    expand = re.findall(r'65787061.{128}', gap_hex)
                    if expand:
                        storing_keys.append(expand)

                if len(read_ahead) == 20:  # Prevents list getting too big
                    read_ahead = []
                if not dump:
                    break
    except IOError:
        print('[-] Error opening the file')
        exit()

    return storing_keys


def main():
    """Main menu"""
    number_keys_found = 0
    name_file = input("[+] Enter the name of the memory dump and its extension: ")
    key = reading_file(name_file)
    storing_keys = extracting_key(key)
    for key, nonce in storing_keys.items():
        number_keys_found += 1
        print('[*] 32 byte Salsa20 Key -', key)
        print('[*] Nonce -', nonce)
    print('[*] Total number of keys found:', number_keys_found)
    print("[+] That's all we could find!", '\n')
    with open("Sodinokibi_keys.txt", "w") as file_keys:
        for key, value in storing_keys.items():
            file_keys.write(key)
            file_keys.write(value)
            file_keys.write('\n')

    incl_nonce = storing_keys.values()
    if len(storing_keys) >= 1:
        answer_files = input("[+] Find files for these keys and decrypt them? Y or N: ").lower()
        if answer_files == 'y':
            file_key_nonce = {}
            folder_src = input("[+] Enter folder with files: ")
            files_nonce = search_file(incl_nonce, folder_src)
            for f, n in files_nonce.items():
                print("[*] Nonce:", n, 'in file:', f, 'found.')
            # files_nonce contain file as key and nonce as value
            for file, nonce in files_nonce.items():
                list_file_nonce = []
                if nonce in storing_keys.values():
                    keys = list(storing_keys.keys())  # Keys converted to list
                    nonce_list = list(storing_keys.values())  # Values converted to list
                    nonce_position = nonce_list.index(nonce)  # Select nonce from list
                    key_extract = keys[nonce_position]  # Store key for the specific nonce
                    list_file_nonce.append(nonce)
                    list_file_nonce.append(file)
                    file_key_nonce[key_extract] = list_file_nonce  # Create dictionary with file, key and noce
            if len(files_nonce) >= 1:
                print('[+] Decrypting files... placing them in "Restored_files"')
                decrypt_file(folder_src, file_key_nonce)
        else:
            exit()
    else:
        exit()

    print("[+] That's all we could decrypt!")


if __name__ == '__main__':
    main()
