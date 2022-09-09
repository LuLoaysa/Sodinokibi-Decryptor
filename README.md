# Sodinokibi-Decryptor
Finds encryption keys in memory and decrypts files encrypted by Sodinokibi (REvil)

This script is part of my dissertation which successfully extracted Salsa20 keys from memory dumps and decrypted files compromised by the Sodinokibi ransomware. The process is detailed in the PDF document of my dissertation also available in this repository.

The script will read binary memory files, after it will prompt the user of a folder with the encrypted files in it and will decrypt them restoring them to the original version.
