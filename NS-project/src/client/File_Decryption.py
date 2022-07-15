from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from key_managemnt_table import find_key
def find_key_iv(file_name:str):
     key_iv=find_key(file_name)
     return key_iv[0],key_iv[1]
def file_Decryption(file_name:str ,encr_file:str):
    key,iv=find_key(file_name)
    cipher=AES.new(key,AES.MODE_CBC,iv)
    paddParams=cipher.decrypt(encr_file)
    return unpad(paddParams,16,style='pkcs7')
def seq_Decryption(enc_seq_number:bytes ,key:bytes):
    cipher=AES.new(key,AES.MODE_ECB)
    paddParams=cipher.decrypt(enc_seq_number)
    return int((unpad(paddParams,16,style='pkcs7')).decode())     ##int