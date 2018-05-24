from base64 import b64decode, b64encode
import urllib
import sys

from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

class AESCipher:
    def __init__( self, key ):
        self.key = key.decode("hex")

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = '\x00' * 16
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return (cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = enc.decode("hex")
        iv = '\x00' * 16
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc))

if __name__== "__main__":
    if len(sys.argv) != 2:
        quit()
    ciphertext = sys.argv[1]
    
    ciphertext = urllib.unquote(ciphertext).decode('utf8') 
    key = 'key goes here'.encode('hex_codec')
    ciphertext = b64decode(ciphertext).encode('hex_codec')
    key=key[:32]
    decryptor = AESCipher(key)
    plaintext = decryptor.decrypt(ciphertext)
    print "%s" % plaintext