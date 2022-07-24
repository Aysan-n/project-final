from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import re
from key_managemnt_table import create,insert
def generate_key_iv():
    key=get_random_bytes(16)
    iv=get_random_bytes(16)
    return key,iv
#def file_Encryption(file_address:str):
 #   file_name=re.findall(r'\w+\.{0,1}\w+$',file_address)
 #   with open(file_address,mode='rb') as file:
 #       orginal_file=file.read()
 #   key,iv=generate_key_iv()
  #  cipher=AES.new(key, AES.MODE_CBC, iv)
  #  enc=cipher.encrypt(pad(orginal_file,16,style='pkcs7'))
 #   create()
 #   insert(file_name[0],key,iv)
  #  return enc

def Encryption(user_name,file_name:str):
    if file_name=='Shared_file':
        return 'Shared_file'
    else:
        key,iv=generate_key_iv()
        cipher=AES.new(key, AES.MODE_CBC, iv)
        enc_file_name=cipher.encrypt(pad(file_name.encode(),16,style='pkcs7')).hex()
        insert(user_name,file_name,enc_file_name,key,iv)
        return enc_file_name
def file_encryption(user,content,key,iv):
    cipher=AES.new(key, AES.MODE_CBC, iv)
    enc=cipher.encrypt(pad(content.encode(),16,style='pkcs7')).hex()
    return enc

def seq_Encryption(seq_num:int,key:bytes):
    seq_num=bytes(str(seq_num),'utf-8')
    cipher=AES.new(key, AES.MODE_ECB)
    enc_seq_num=cipher.encrypt(pad(seq_num,16,style='pkcs7'))
    return enc_seq_num.hex()  ##bytes


