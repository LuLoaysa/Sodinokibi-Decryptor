# Sodinokibi-Decryptor
Finds encryption keys in memory and decrypts files encrypted by Sodinokibi (REvil)

Please note that memory dumps must be taken during encryption, otherwise the encryption keys won't be found.

This script is part of my dissertation which successfully extracted Salsa20 keys from memory dumps and decrypted files compromised by the Sodinokibi ransomware. The process is detailed in the PDF document of my dissertation also available in this repository.

The script will read binary memory files, after, it will prompt the user for the path of a folder with the encrypted files in it and will decrypt them restoring them to the original version.

Additional Information:

This was developed after thorough research which found that Sodinokibi appends 64 bytes of data before encryption changing the position of the cipher that the original file would have.
