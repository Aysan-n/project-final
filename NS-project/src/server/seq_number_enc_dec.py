from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
def seq_Encryption(seq_num:int,key:bytes):
    seq_num=bytes(str(seq_num),'utf-8')
    cipher=AES.new(key, AES.MODE_ECB)
    enc_seq_num=cipher.encrypt(pad(seq_num,16,style='pkcs7'))
    return enc_seq_num  ##bytes
def seq_Decryption(enc_seq_number:bytes ,key:bytes):
    cipher=AES.new(key,AES.MODE_ECB)
    paddParams=cipher.decrypt(enc_seq_number)
    return int((unpad(paddParams,16,style='pkcs7')).decode())     ##int  