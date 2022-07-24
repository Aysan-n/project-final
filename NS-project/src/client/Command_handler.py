import time
from multiprocessing import shared_memory
import re, subprocess, os, rsa
from File_Encryption import Encryption, file_encryption, seq_Encryption
from File_Decryption import file_Decryption
from key_managemnt_table import find_file, create,find_decrypted,del_file
import platform


def command_handler(user, messaging, command: str, seq_num: int, session_key: bytes, client_user_name: str,cwd:str):
    create(user)
    command_string = command
    support_command = ['mkdir', 'touch', 'cd', 'ls', 'rm', 'mv', 'share', 'revoke', 'edit']
    client_command = (re.findall(r'^\w+', command_string))[0]
    enc_seq_num = seq_Encryption(seq_num, session_key)
    if client_command not in support_command:
        return False
    if client_command in ['mkdir', 'touch', 'cd', 'ls']:
        path = re.findall(r'\s(.+$)', command_string)

        if len(path) == 0 and client_command in ['mkdir', 'touch', 'cd']:
            return False
        elif len(path) == 0 and client_command == 'ls':
            client_message = {'message_type': 'client_command', 'command': client_command, 'path': './',
                              'command_type': client_command, 'enc_seq_num': enc_seq_num,
                              'client_user_name': client_user_name}
            messaging.send_message(client_message)
            return True
        if path[0][0] == '/':
            path[0] = path[0][1:]
        directory_name = path[0].split('/')
        enc_dir_name = []

        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.' or dir_name=='':
                enc_dir_name += [dir_name]
            else:
                record = find_file(user,dir_name)
                if (client_command == 'cd' or client_command == 'ls') and len(record) == 0 and dir_name!='Shared_file':
                    return False
                elif len(record) == 0:
                    enc_dir_name += [Encryption(user,dir_name)]
                else:
                    enc_dir_name += [record[0][1]]

        enc_path = '/'.join(enc_dir_name)
        client_message = {'message_type': 'client_command', 'command': client_command + enc_path, 'path': enc_path,
                          'command_type': client_command, 'enc_seq_num': enc_seq_num,
                          'client_user_name': client_user_name}
        messaging.send_message(client_message)
    if client_command == 'rm':
        path = re.findall(r'^\w+\s-{0,1}r{0,1}\s{0,1}(\w+)', command_string)
        directory_name = path[0].split('/')
        print('dir*********',directory_name)
        enc_dir_name = []
        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.' or dir_name=='':
                enc_dir_name += [dir_name]
            else:
                record = find_file(user,dir_name)
                if len(record) == 0:
                    return False
                else:
                    enc_dir_name += [record[0][1]]
        enc_path = '/'.join(enc_dir_name)
        print('enc_path*****************',enc_path)
        command_flag = re.findall(r'\s(-\w{0,1})\s{0,1}.+$',command_string)
        print('command_flag*****************',command_flag)
        if len(command_flag)==0:
            command_flag=''
        else:
            command_flag=command_flag[0]
        client_message = {'message_type':'client_command','command':client_command+command_flag+enc_path,'path':enc_path,'command_flag':command_flag,'command_type':client_command,'enc_seq_num':enc_seq_num,'client_user_name':client_user_name}
        messaging.send_message(client_message)
    if client_command == 'mv':
        access_path = re.findall(r'^\w+\s-{0,1}r{0,1}\s{0,1}(\w+)',command_string)
        dest_path = re.findall(r'\s-{0,1}\w{0,1}\s{0,1}.+\s(.+)',command_string)
        access_directory_name = access_path[0].split('/')
        dest_directory_name = dest_path[0].split('/')
        enc_access_dir_name = []
        enc_des_dir_name = []
        for dir_name in access_directory_name:
            if dir_name == '..' or dir_name == '.' or dir_name=='':
                enc_access_dir_name += [dir_name]
            else:
                record = find_file(user, dir_name)
                if len(record) == 0:
                    return False
                else:
                    enc_access_dir_name += [record[0][1]]
        for dir_name in dest_directory_name:
            if dir_name == '..' or dir_name == '.' or dir_name=='':
                enc_des_dir_name += [dir_name]
            else:
                record = find_file(user,dir_name)
                if len(record) == 0:
                    enc_des_dir_name += [Encryption(user,dir_name)]
                else:
                    enc_des_dir_name += [record[0][1]]
        enc_access_path = '/'.join(enc_access_dir_name)
        enc_dest_path = '/'.join(enc_des_dir_name)
        command_flag = re.findall(r'\s(-\w{0,1})\s{0,1}.+$', command_string)
        if len(command_flag)==0:
            command_flag=''
        else:
            command_flag=command_flag[0]

        client_message = {'message_type': 'client_command',
                          'access_path': enc_access_path, 'dest_path': enc_dest_path, 'command_type': client_command,
                          'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name,'command_flag':command_flag}
        messaging.send_message(client_message)

    ##################دستور جدید
    if client_command == 'share':
        flag = re.findall(r'-(\w{1,2})\s{0,1}$', command_string)
        if len(flag) == 0 or len(flag[0]) > 2 or (flag[0] not in ['rw', 'wr', 'r']):
            print("ERROR: Permisions not right.")
            return False  ###### کامند اشتباه
        path = re.findall(r'^\w+\s(.*?)\s', command_string)
        if len(path) == 0:
            print("ERROR: Path not right.")
            return False  #### کامند اشتباه
        if path[0][0] == '/':
            path[0] = path[0][1:]
        directory_name = path[0].split('/')
        file_name = directory_name.pop()
        record = find_file(user,file_name)
        if len(record) == 0:
            print("ERROR: File not found.")
            return False  #### کامند اشتباه
        enc_file_name = record[0][1]
        enc_key = record[0][2]
        iv = record[0][3]
        enc_dir_name = []
        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.' or dir_name=='':
                enc_dir_name += [dir_name]
            else:
                record = find_file(user,dir_name)
                if len(record) == 0:
                    print("ERROR: Path not right.")
                    return False  #####   کامند اشتباه
                else:
                    enc_dir_name += [record[0][1]]
        enc_path = '/'.join(enc_dir_name)
        subscriber_username = re.findall(r'^\w+\s.*?\s(\w+)', command_string)
        if len(subscriber_username) == 0:
            print("ERROR: Username not found.")
            return False  #### کامند اشتباه

        ###############  ارسال درخواست کلاینت برای دریافت کلید عمومی کاربر مشترک
        client_message = {'message_type': 'client_command', 'command_type': "share",
                          'subscriber_username': subscriber_username, 'enc_seq_num': enc_seq_num,
                          'client_user_name': client_user_name}  #####seq num در صورت سخت کردن قضیه نادیده گرفته شود
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

    if client_command == 'revoke':
        path = re.findall(r'^\w+\s(.*)', command_string)
        if len(path) == 0:
            print(1)
            return False  #### کامند اشتباه
        if path[0][0] == '/':
            path[0] = path[0][1:]
        directory_name = path[0].split('/')
        file_name = directory_name.pop()
        record = find_file(user,file_name)
        print('*******',record)
        if len(record) == 0:
            print(2)
            return False  #### کامند اشتباه
        enc_file_name = record[0][1]
        print('enc_file_name***********',enc_file_name)
        enc_dir_name = []
        for dir_name in directory_name:
            if dir_name == '..' or dir_name == '.' or dir_name=='':
                enc_dir_name += [dir_name]
            else:
                record = find_file(user,dir_name)
                if len(record) == 0:
                    print(3)
                    return False  #####   کامند اشتباه
                else:
                    enc_dir_name += [record[0][1]]
        enc_path = '/'.join(enc_dir_name)
        print('encpaht***********',enc_path)
        client_message = {'message_type': 'client_command',
                          'path': enc_path, 'command_type': client_command,
                          'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name, 'file_name': enc_file_name}
        messaging.send_message(client_message)
        server_message = messaging.receive()
        print(server_message)
        change_file_key(user,messaging, server_message["enc_file_name"] , server_message["enc_message"])

    if client_command == 'edit':
        print("Entered")
        path = re.findall(r'^\w+\s(.+)', command_string)
        if len(path) == 0:
            print(1)
            return False  #### کامند اشتباه
        if path[0][0] == '/':
            path[0] = path[0][1:]
        directory_name = path[0].split('/')
        print(directory_name)
        file_name = directory_name.pop()
        if 'Shared_file' in path[0] or 'Shared_file' in cwd:
            client_message = {'message_type': 'client_command',
                              'path': path[0], 'command_type': client_command,
                              'enc_seq_num': enc_seq_num, 'Shared_file': 'True', 'client_user_name': client_user_name,
                              'file_name': file_name}
            messaging.send_message(client_message)
            ###############    فرستادن پیام وانتظار برای دریافت آن
            ################  دریافت پیام
            server_message = messaging.receive()
            print(server_message)
            with open(os.getcwd() +"/"+ user +'_private.txt', 'r') as file:
                key_data = file.read()
            private_key = rsa.PrivateKey.load_pkcs1(bytes.fromhex(key_data), 'PEM')

            enc_key = server_message['enc_key']
            enc_iv = server_message['enc_iv']

            key=rsa.decrypt(bytes.fromhex(enc_key), private_key).decode()
            iv=rsa.decrypt(bytes.fromhex(enc_iv), private_key).decode()
            key=bytes.fromhex(key)
            iv=bytes.fromhex(iv)
            enc_message = server_message['enc_message']
            print(server_message['permission_type'])
            if len(enc_message) > 0:
                dec_messgae = file_Decryption(enc_message, key, iv)
                if server_message['permission_type'] == 'r':
                    return dec_messgae  #################   در حالتی که فقط مجوز خواندن وجود دارد، متن پرینت می شود
                else:
                    with open(os.getcwd() + '/src/client/cache_file/cache_file.txt', 'w') as file:
                        file.write(dec_messgae.decode())
            elif len(enc_message) == 0 and server_message['permission_type'] == "r":
                print("FILE IS EMPTY")
                return 0
            operating_system = platform.system()

            if operating_system == "Windows":
                process = subprocess.Popen(["notepad.exe", os.getcwd() + '/src/client/cache_file/cache_file.txt'])
                process.wait()
            else:
                os.system("open " + os.getcwd() + '/src/client/cache_file/cache_file.txt')
                time.sleep(9)
            with open(os.getcwd() + '/src/client/cache_file/cache_file.txt', 'r') as file:
                file_content = file.read()
            with open(os.getcwd() + '/src/client/cache_file/cache_file.txt', 'w') as file:
                file.write('')
            enc_file = file_encryption(file_content, key, iv)
            client_message = {'message_type': 'client_command',
                              ###### پارامتر های این پیام براساس شرایط، می تواند بر اساس پیام رسیده شده از سرور فرستاده شود
                              'path': path[0], 'command_type': client_command,
                              'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name,
                              'file_name': file_name, 'enc_file': enc_file}
            messaging.send_message(client_message)
            print('*************3')
        else:
            record = find_file(user,file_name)
            if len(record) == 0:
                print(2)
                return False  #### کامند اشتباه
            enc_file_name = record[0][1]
            enc_key = record[0][2]
            iv = record[0][3]
            enc_key=bytes.fromhex(enc_key)
            iv=bytes.fromhex(iv)
            enc_dir_name = []
            for dir_name in directory_name:
                if dir_name == '..' or dir_name == '.' or dir_name=='':     ######## new
                    enc_dir_name += [dir_name]
                else:
                    print(dir_name)
                    record = find_file(user,dir_name)
                    if len(record) == 0:
                        print(3)
                        return False  #####   کامند اشتباه
                    else:
                        enc_dir_name += [record[0][1]]
            enc_path = '/'.join(enc_dir_name)

            client_message = {'message_type': 'client_command',
                              'path': enc_path, 'command_type': client_command,
                              'enc_seq_num': enc_seq_num, 'Shared_file': 'False', 'client_user_name': client_user_name,
                              'file_name': enc_file_name}

            messaging.send_message(client_message)
            server_message = messaging.receive()
            print(server_message)
            ########    فرستادن پیام و انتظار برای دریافت جواب آن
            #######  دریافت محتوای رمز شده
            enc_message = server_message['enc_message']

            if len(enc_message) > 0:
                dec_messgae=file_Decryption(enc_message, enc_key, iv)
                with open(os.getcwd() + '/src/client/cache_file/cache_file.txt', 'w') as file:
                    file.write(dec_messgae.decode())

            operating_system = platform.system()

            if operating_system == "Windows":
                process = subprocess.Popen(["notepad.exe", os.getcwd() + '/src/client/cache_file/cache_file.txt'])
                process.wait()
            else:
                os.system("open " + os.getcwd() + '/src/client/cache_file/cache_file.txt')
                time.sleep(9)

            with open(os.getcwd() + '/src/client/cache_file/cache_file.txt', 'r') as file:
                file_content = file.read()
            with open(os.getcwd() + '/src/client/cache_file/cache_file.txt', 'w') as file:
                file.write('')
            enc_file = file_encryption(file_content, enc_key, iv)
            client_message = {'message_type': 'client_command',
                              'path': enc_path, 'command_type': client_command,
                              'enc_seq_num': enc_seq_num, 'client_user_name': client_user_name,
                              'file_name': enc_file_name, 'enc_file': enc_file}
            messaging.send_message(client_message)


        ##################  فرستادن، محتوای رمز شده، سمت سرور


def change_file_key(user, messaging, file_name, file_content):
    record = find_decrypted(user,file_name)
    print(record)
    if len(record) == 0:
        return False  #### کامند اشتباه
    enc_key = record[2]
    iv = record[3]
    enc_key = bytes.fromhex(enc_key)
    iv = bytes.fromhex(iv)
    file_name = find_decrypted(user,file_name)[0]
    if len(file_content) > 0:
        print(file_content)
        print("****")
        dec_messgae = file_Decryption(file_content, enc_key, iv).decode()
        print(dec_messgae)
    else:
        dec_messgae = file_content
    del_file(user,file_name)
    enc_file_name = Encryption(user,file_name)
    record = find_file(user,file_name)
    enc_key = record[0][2]
    iv = record[0][3]
    enc_key = bytes.fromhex(enc_key)
    iv = bytes.fromhex(iv)
    if len(dec_messgae)>0:
        enc_file = file_encryption(dec_messgae, enc_key, iv)
    else:
        enc_file=dec_messgae
    iv = iv.hex()
    enc_key = enc_key.hex()
    ######################################                             نکته مهم.کلید و ای وی باید با کلید عمومی کاربر رمز شوند
    client_message = {'message_type': 'client_command',    ######### در صورت لزوم سکوئنس نامبر هم اضافه شود.
                      'file_name': enc_file_name, 'enc_file': enc_file,'enc_key':enc_key,'enc_iv':iv}
    messaging.send_message(client_message)
