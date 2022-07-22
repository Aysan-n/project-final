from multiprocessing import shared_memory
import re

import rsa

from File_Encryption import Encryption
from key_managemnt_table import find_file, create
from File_Encryption import seq_Encryption


def command_handler(messaging, command: str, seq_num: int, session_key: bytes, client_user_name: str):
    create()
    command_string = command
    support_command = ['mkdir', 'touch', 'cd', 'ls', 'rm', 'mv','share']
    client_command = (re.findall(r'^\w+', command_string))[0]
    enc_seq_num = seq_Encryption(seq_num, session_key)
    if client_command not in support_command:
        return False
    if client_command in ['mkdir', 'touch', 'cd', 'ls']:
        path = re.findall(r'\s(.+$)', command_string)

        if len(path) == 0 and client_command in ['mkdir', 'touch', 'cd']:
            return False
        elif len(path) == 0 and client_command == 'ls':
            client_message = {'message_type': 'client_command', 'command': client_command, 'path': '',
                              'command_type': client_command, 'enc_seq_num': enc_seq_num,
                              'client_user_name': client_user_name}
            messaging.send_message(client_message)
            return True
        if path[0][0] == '/':
            path[0] = path[0][1:]
        directory_name = path[0].split('/')

        enc_dir_name = []

        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.':
                enc_dir_name += [dir_name]
            else:
                record = find_file(dir_name)
                if (client_command == 'cd' or client_command == 'ls') and len(record) == 0:
                    return False
                elif len(record) == 0:
                    enc_dir_name += [Encryption(dir_name)]
                else:
                    enc_dir_name += [record[0][1]]

        enc_path = '/'.join(enc_dir_name)

        client_message = {'message_type': 'client_command', 'command': client_command + enc_path, 'path': enc_path,
                          'command_type': client_command, 'enc_seq_num': enc_seq_num,
                          'client_user_name': client_user_name}
        messaging.send_message(client_message)

    if client_command == 'rm':
        path = re.findall(r'\s-{0,1}\w{0,1}\s{0,1}(.+$)', command_string)
        directory_name = path[0].split('/')
        enc_dir_name = []
        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.':
                enc_dir_name += [dir_name]
            else:
                record = find_file(dir_name)
                if len(record) == 0:
                    return False
                else:
                    enc_dir_name+=[record[0][1]]
        enc_path = '/'.join(enc_dir_name)
        command_flag = re.findall(r'\s(-{0,1}\w{0,1})\s{0,1}.+$',command_string)
        client_message = {'message_type':'client_command','command':client_command+command_flag[0]+enc_path,'path':enc_path,'command_flag':command_flag[0],'command_type':client_command,'enc_seq_num':enc_seq_num,'client_user_name':client_user_name}
        messaging.send_message(client_message)
    if client_command == 'mv':
        access_path = re.findall(r'\s-{0,1}\w{0,1}\s{0,1}(.+)\s',command_string)
        dest_path = re.findall(r'\s-{0,1}\w{0,1}\s{0,1}.+\s(.+)',command_string)
        access_directory_name = access_path[0].split('/')
        dest_directory_name =dest_path[0].split('/')
        enc_access_dir_name=[]
        enc_des_dir_name=[]
        for dir_name in access_directory_name:
            if dir_name == '..' or dir_name == '.':
                enc_access_dir_name += [dir_name]
            else:
                record = find_file(dir_name)
                if len(record) == 0:
                    return False
                else:
                    enc_access_dir_name += [record[0][1]]
        for dir_name in dest_directory_name:
            if dir_name == '..' or dir_name == '.':
                enc_des_dir_name += [dir_name]
            else:
                record = find_file(dir_name)
                if len(record) == 0:
                    enc_dir_name += [Encryption(dir_name)]
                else:
                    enc_access_dir_name += [record[0][1]]
        enc_access_path = '/'.join(enc_access_dir_name)
        enc_dest_path = '/'.join(enc_des_dir_name)
        command_flag = re.findall(r'\s(-{0,1}\w{0,1})\s{0,1}.+$', command_string)
        client_message = {'message_type': 'client_command',
                          'command': client_command + command_flag[0] + enc_access_path + enc_dest_path,
                          'access_path': enc_access_path, 'dest_path': enc_dest_path, 'command_type': client_command,
                          'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name}
        messaging.send_message(client_message)
    

    ##################دستور جدید
    if client_command == 'share':
        flag = re.findall(r'-(\w{1,2})\s{0,1}$',command_string)
        if len(flag) == 0 or len(flag[0])>2 or (flag[0] not in ['rw','wr','r','w']):
            print("ERROR: Permisions not right.")
            return False  ###### کامند اشتباه
        path = re.findall(r'^\w+\s(.*?)\s',command_string)
        if len(path) == 0:
            print("ERROR: Path not right.")
            return False   #### کامند اشتباه
        if path[0][0] == '/':
            path[0] = path[0][1:]
        directory_name = path[0].split('/')
        file_name=directory_name.pop()
        record=find_file(file_name)
        if len(record)==0:
            print("ERROR: File not found.")
            return False  #### کامند اشتباه
        enc_file_name=record[0][1]
        enc_key=record[0][2]
        iv=record[0][3]
        enc_dir_name = []
        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.':
                enc_dir_name += [dir_name]
            else:
                record = find_file(dir_name)
                if len(record) == 0:
                    print("ERROR: Path not right.")
                    return False   #####   کامند اشتباه
                else:
                    enc_dir_name += [record[0][1]]
        enc_path= '/'.join(enc_dir_name)
        subscriber_username=re.findall(r'^\w+\s.*?\s(\w+)',command_string)
        if len(subscriber_username)==0:
            print("ERROR: Username not found.")
            return False   #### کامند اشتباه
        
        ###############  ارسال درخواست کلاینت برای دریافت کلید عمومی کاربر مشترک
        client_message = {'message_type': 'client_command', 'command_type': "share", 'subscriber_username': subscriber_username, 'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name}    #####seq num در صورت سخت کردن قضیه نادیده گرفته شود
        messaging.send_message(client_message)
        ####### دریافت کلید عمومی
        reply = messaging.receive()
        key_data = bytes.fromhex(reply["key"])
        public_key = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)
        print(public_key)

        enc_key_encrypted = rsa.encrypt(enc_key.encode(), public_key)
        iv_encrypted = rsa.encrypt(iv.encode(), public_key)

        ###########                  رمز کردن , enc_key, iv

        client_message = {'message_type': 'client_command',
                          'path': enc_path, 'command_type': client_command, 'enc_key': enc_key_encrypted.hex(),
                          'enc_iv': iv_encrypted.hex(), 'flag': flag[0], 'subscriber_username': subscriber_username,
                          'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name, 'file_name': enc_file_name}

        messaging.send_message(client_message)
        #### درخواست اولی می تواند در قسمت messaging سرور پرداخته شود
        #################       ارسال آخرین پیام کلاینت




