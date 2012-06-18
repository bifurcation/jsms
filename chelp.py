#!/usr/bin/python

import sys
import base64
import re
from CryptoHelper import CryptoHelper

# Wrapper functions, because base64 doesn't deal well with unpadded
def b64d(x):
    while len(x) % 4 > 0:
        x = x + "="
    return base64.urlsafe_b64decode(x)
def b64e(x):
    y = base64.urlsafe_b64encode(x)
    return re.sub(r'=+$', "", y)

def long_b64e(x):
    a = []
    while x > 0:
        a.append(x % 256)
        x >>= 8
    a.reverse()
    return b64e(bytearray(a))

def long_b64d(b):
    a = b64d(b)
    x = long(a.encode("hex"), 16)
    return x


def main():
    usage = """-
        Usage: {0} <command> [args]
        The following commands are available:
            random <bytes>
            sign_pkcs1_sha256 <n> <e> <d> <content>
            verify_pkcs1_sha256 <n> <e> <content>
            aes_key_wrap <key> <p>
            aes_key_unwrap <key> <c>
            rsa_oaep_key_wrap <n> <e> <p>
            rsa_oaep_key_unwrap <n> <e> <d> <p>
            hmac_sha256 <key> <content>
            encrypt_gen_aead_AES128CBC_HMACSHA256 <key> <n> <iv> <content>
            decrypt_gen_aead_AES128CBC_HMACSHA256 <key> <n> <iv> <content>
            encrypt_AES128CCM <key> <n> <M> <content> <assoc>
            decrypt_AES128CCM <key> <n> <M> <content> <assoc>

        All arguments should be base64url encoded, except if they're integers.  
        Results will come back base64url encoded.
    """

    usage_msg = usage.format(sys.argv[0])
    if len(sys.argv) < 3:
        print usage_msg
        quit()

    cmd = sys.argv[1]
    a = sys.argv[2:]
    
    ret = b''
    if cmd == "random": # <bytes>
        b = int(a.pop(0))
        ret = CryptoHelper.random(b)
    elif cmd == "sign_pkcs1_sha256": # <n> <e> <d> <content>
        n = long_b64d(a.pop(0))
        e = long_b64d(a.pop(0))
        d = long_b64d(a.pop(0))
        content = b64d(a.pop(0))
        ret = CryptoHelper.sign_pkcs1_sha256(n, e, d, content)
    elif cmd == "verify_pkcs1_sha256": # <n> <e> <content>
        n = long_b64d(a.pop(0))
        e = long_b64d(a.pop(0))
        content = b64d(a.pop(0))
        sig = b64d(a.pop(0))
        ret = CryptoHelper.verify_pkcs1_sha256(n, e, content, sig)
    elif cmd == "aes_key_wrap": # <key> <p>
        key = b64d(a.pop(0))
        p = b64d(a.pop(0))
        ret = CryptoHelper.aes_key_wrap(key, p)
    elif cmd == "aes_key_unwrap": # <key> <c>
        key = b64d(a.pop(0))
        c = b64d(a.pop(0))
        ret = CryptoHelper.aes_key_unwrap(key, c)
    elif cmd == "rsa_oaep_key_wrap": # <n> <e> <p>
        n = long_b64d(a.pop(0))
        e = long_b64d(a.pop(0))
        p = b64d(a.pop(0))
        ret = CryptoHelper.rsa_oaep_key_wrap(n, e, p)
    elif cmd == "rsa_oaep_key_unwrap": # <n> <e> <d> <c>
        n = long_b64d(a.pop(0))
        e = long_b64d(a.pop(0))
        d = long_b64d(a.pop(0))
        c = b64d(a.pop(0))
        ret = CryptoHelper.rsa_oaep_key_unwrap(n, e, d, c)
    elif cmd == "hmac_sha256": # <key> <content>
        key = b64d(a.pop(0))
        content = b64d(a.pop(0))
        ret = CryptoHelper.hmac_sha256(key, content)
    elif cmd == "encrypt_gen_aead_AES128CBC_HMACSHA256": # <key> <n> <iv> <content>
        key = b64d(a.pop(0))
        n = b64d(a.pop(0))
        iv = b64d(a.pop(0))
        content = b64d(a.pop(0))
        ret = CryptoHelper.encrypt_gen_aead_AES128CBC_HMACSHA256(key, n, iv, content)
    elif cmd == "decrypt_gen_aead_AES128CBC_HMACSHA256": # <key> <n> <iv> <content>
        key = b64d(a.pop(0))
        n = b64d(a.pop(0))
        iv = b64d(a.pop(0))
        content = b64d(a.pop(0))
        ret = CryptoHelper.decrypt_gen_aead_AES128CBC_HMACSHA256(key, n, iv, content)
    elif cmd == "encrypt_AES128CCM": # <key> <n> <M> <content> <assoc>
        key = b64d(a.pop(0))
        n = b64d(a.pop(0))
        M = int(a.pop(0))
        content = b64d(a.pop(0))
        assoc = b64d(a.pop(0))
        ret = CryptoHelper.encrypt_AES128CCM(key, n, M, content, assoc)
    elif cmd == "decrypt_AES128CCM": # <key> <n> <M> <content> <assoc>
        key = b64d(a.pop(0))
        n = b64d(a.pop(0))
        M = int(a.pop(0))
        content = b64d(a.pop(0))
        assoc = b64d(a.pop(0))
        ret = CryptoHelper.decrypt_AES128CCM(key, n, M, content, assoc)
    else:
        print "-" + "Unknown command"

    if isinstance(ret,bool):
        print "+{0}".format(ret)
    else:
        print "+" + b64e(ret)


main()


