from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def file_Decryption(enc_message:str,key,iv):
    cipher=AES.new(key,AES.MODE_CBC,iv)
    paddParams=cipher.decrypt(bytearray.fromhex(enc_message))
    return unpad(paddParams,16,style='pkcs7')
def seq_Decryption(enc_seq_number:bytes ,key:bytes):
    cipher=AES.new(key,AES.MODE_ECB)
    paddParams=cipher.decrypt(enc_seq_number)
    return int((unpad(paddParams,16,style='pkcs7')).decode())     ##int