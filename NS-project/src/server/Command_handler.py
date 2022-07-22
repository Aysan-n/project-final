from fileinput import filename
import json
from tkinter.tix import TEXT
from Client_table import find_auth_user, delete_auth_user, update_cwd, find_client, update_sequence_number,add_file,delete_file,update_file,find_file,update_shared_file,create_file_table
from seq_number_enc_dec import seq_Decryption, seq_Encryption
import datetime
import os
import subprocess
import re
import platform

create_file_table()


def server_command_handler(messaging, connection, client_message):
    client_user_name = client_message['client_user_name']
    command_type = client_message['command_type']
    record = find_auth_user(client_user_name)
    client_record = find_client(client_user_name)
    critical_path = os.getcwd() + '/Repository/' + client_record[3]
    cwd = os.getcwd() + "/Repository/" + client_record[3] + "/" + record[4]

    if len(record) == 0:  ###عدم احراز اصالت کاربر
        server_message = {'message_type': 'authentication', 'status': 'not authenticated'}
        messaging.send_message(server_message, connection)
        return False

    current_time = datetime.datetime.now()

    time_stamp = record[3]
    print(time_stamp)
    print(record)

    time_stamp = datetime.datetime.strptime(time_stamp, "%Y-%m-%d %H:%M:%S.%f")

    delta_time = current_time - time_stamp

    max_delta_time = datetime.timedelta(seconds=7200)
    if delta_time > max_delta_time:
        delete_auth_user(client_user_name)
        server_message = {'message_type': 'authentication', 'status': 'timeout'}
        messaging.send_message(server_message, connection)
        return False  ## منقضی شدن احراز اصالت

    session_key = record[1]
    seq_number = record[2]
    enc_seq_number = bytes.fromhex(client_message['enc_seq_num'])
    dec_seq_num = seq_Decryption(enc_seq_number, session_key)

    if dec_seq_num != seq_number + 1:
        server_message = {'message_type': 'authentication', 'status': 'Invalid sequance number.'}
        messaging.send_message(server_message, connection)
        return False  ##کاریر نامعتبر
    else:
        sequence_number = seq_number + 1
        update_sequence_number(client_user_name, sequence_number)

    if client_message['command_type'] == 'share':
        pub_key = client_record[5]
        print(pub_key)
        server_message = {'message_type': 'key', 'key': pub_key}
        messaging.send_message(server_message, connection)
        client_message = deserialize(connection.recv(2048))
        print(client_message)

    if client_message['command_type'] != 'mv':

        path = client_message['path']
        path_list = path.split('/')

        cwd_list = record[4].split('/')[1:]  

        if path_list.count('..') > (len(cwd_list)) - 1:
            server_message = {'message_type': 'authentication', 'status': 'invalid access'}
            messaging.send_message(server_message, connection)
            return False  # دسترسی غیر مجازی
        elif len(lcs(critical_path, path)) > 0 and critical_path.find(path) == 0:
            server_message = {'message_type': 'authentication', 'status': 'invalid access'}
            messaging.send_message(server_message, connection)
            return False  ######دسترسی غیر مجاز
    else:
        access_path = client_message['access_path']
        dest_path = client_message['dest_path']
        access_path_list = access_path.split('/')
        dest_path_list = dest_path.split('/')
        cwd_list = record[5].split('/')[1:]  ##################### جدول باید درست شود
        if access_path_list.count('..') > (len(cwd_list)) - 1 or dest_path_list.count('..') > (len(cwd_list)) - 1:
            server_message = {'message_type': 'authentication', 'status': 'invalid access'}
            messaging.send_message(server_message, connection)
            return False  # دسترسی غیر مجازی
        elif (len(lcs(critical_path, access_path) > 0 and critical_path.find(access_path) == 0)) or (
                len(lcs(critical_path, dest_path) > 0 and critical_path.find(dest_path) == 0)):
            server_message = {'message_type': 'authentication', 'status': 'invalid access'}
            messaging.send_message(server_message, connection)
            return False  ###دسترسی غیر مجاز


            
        ########################################################################################### کدجدید

    if client_message['command_type'] == 'share':

        file_name = client_message['file_name']
        enc_key = client_message['enc_key']
        enc_iv = client_message['enc_iv']
        record = find_file(file_name, client_message['client_user_name'])
        path = client_message['path']
        if len(record) == 0 or check_path(path,record[0][4],cwd):
            return False     ######## کامند اشتباه
        subscriber_username = client_message['subscriber_username']
        permission_type = client_message['flag']
        client_record = find_client(subscriber_username)
        if len(client_record) == 0:
            return False     ##########کامند اشتباه
        update_shared_file(file_name, client_message['client_user_name'], subscriber_username, permission_type)
        cwd = os.getcwd() + "/src/server/Repository/" + client_record[3] + "/Shared_file"
        with cd(cwd):
            process = subprocess.Popen('echo "%s/%s/%s/%s" > %s.txt' %(file_name,client_message['client_user_name'],enc_key,enc_iv,file_name), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait()
        output, error = process.communicate()
        if len(error) != 0:
            return False  # دستور دچار خطا شد
        else:    
            return True                ########## کامند به درستی اجراشد

    if client_message['command_type'] == 'revoke':
        file_name=client_message['enc_file_name']
        record=find_file(file_name,client_message['client_user_name'])
        path=client_message['path']
        if len(record)==0 or path!=record[0][4]:
            return False     ######## کامند اشتباه
        subscriber_username=record[0][2]
        if len(subscriber_username)!=0:
            client_record=find_client(subscriber_username)
            cwd=os.getcwd() + "/src/server/Repository/" + client_record[3] + "/Shared_file/%s" %file_name
            os.remove(cwd + '.txt')
        update_shared_file(file_name,client_message['client_user_name'],'','')
        return True    








    if client_message['command_type']=='edit':
        file_name=client_message['enc_file_name']
        record=find_file(file_name,client_message['client_user_name'])
        path=client_message['path']
        if len(record)==0 or path!=record[0][4]:
            return False     ######## کامند اشتباه
        subscriber_username=record[0][2]
        if len(subscriber_username)!=0:
            client_record=find_client(subscriber_username)
            cwd=os.getcwd() + "/src/server/Repository/" + client_record[3] + "/Shared_file/%s" %file_name
            os.remove(cwd + '.txt')
        update_shared_file(file_name,client_message['client_user_name'],'','')
        return True 




    ######################################################################

    operating_system = platform.system()

    

    server_message = {'message_type': 'authentication', 'status': 'ok'}
    messaging.send_message(server_message, connection)

    if command_type == "mv":
        if operating_system == "Windows":
            mv_handler(cwd, client_message)
        else:
            mv_handler_linux(cwd, client_message)

        server_message = {'message_type': 'command_result', 'status': 'ok'}
        messaging.send_message(server_message, connection)

    elif command_type == "ls":
        if operating_system == "Windows":
            status = ls_handler(cwd, client_message)
        else:
            status = ls_handler_linux(cwd, client_message)

        server_message = {'message_type': 'command_result', 'status': status}
        messaging.send_message(server_message, connection)

    elif command_type == "touch":
        touch_handler(cwd, client_message)
        server_message = {'message_type': 'command_result', 'status': 'ok'}
        messaging.send_message(server_message, connection)

    elif command_type == "rm":
        if operating_system == "Windows":
            rm_handler(cwd, client_message)
        else:
            rm_handler_linux(cwd, client_message)
        server_message = {'message_type': 'command_result', 'status': 'ok'}
        messaging.send_message(server_message, connection)

    elif command_type == "cd":
        status = cd_handler(cwd, client_message)
        server_message = {'message_type': 'command_result', 'status': status}
        messaging.send_message(server_message, connection)

    elif command_type == "mkdir":
        mkdir_handler(cwd, client_message)
        server_message = {'message_type': 'command_result', 'status': 'ok'}
        messaging.send_message(server_message, connection)

    return True


def ls_handler(cwd_total, client_message):
    path = client_message['path']
    if len(path) == 0:
        pass
    elif path[0] == '/':
        path = path[1:]
    cwd_total = cwd_total.replace('/', '\\')
    path = path.replace('/', '\\')
    with cd(cwd_total):
        process = subprocess.Popen(["dir", "%s" % path], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
    output, error = process.communicate()
    if len(error) != 0:
        return False  # دستور دچار خطا شد
    else:
        result = re.sub(r'.*\r\n\r\n', '', output.decode())
        result = re.sub(r'^\s{0,1}.*?\.\r\n', '', result)  ########## خروجی رو درست کن سپس بفرست
        return result


def cd_handler(cwd_total, critical_path, client_message):
    savedPath = os.getcwd()
    os.chdir(cwd_total)
    path = client_message['path']
    if path[0] == '/':
        path = path[1:]
    path = path.replace('/', '\\')
    os.chdir(path)
    new_cwd = os.getcwd()
    os.chdir(savedPath)
    critical_path = critical_path.replace('/', '\\')
    critical_path = critical_path.split('\\')
    new_cwd = new_cwd.split('\\')
    new_cwd = new_cwd[len(critical_path):]
    new_cwd = '/' + '/'.join(new_cwd)
    client_user_name = client_message['client_user_name']
    update_cwd(client_user_name, new_cwd)
    return new_cwd


def touch_handler(cwd_total, client_message):
    path = client_message['path']
    if path[0] == '/':
        path = path[1:]
    path = path.replace('/', '\\')
    path = path.split('\\')
    file_name = path.pop()
    if len(path) == 0:
        savedPath = os.getcwd()
        os.chdir(cwd_total)
        new_path = os.getcwd()
    else:
        savedPath = os.getcwd()
        os.chdir(cwd_total)
        path = '\\'.join(path)
        os.chdir(path)
        new_path = os.getcwd()
    os.chdir(savedPath)
    with cd(new_path):
        process = subprocess.Popen('type nul >> "%s.txt"' % file_name, shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        process.wait()
    output, error = process.communicate()
    if len(error) > 0:
        return False  ########### خطای اجرا کد
    add_file(file_name,client_message['client_user_name'],new_path)    ###################################new new new new
    return True


def mkdir_handler(cwd_total, client_message):
    path = client_message['path']
    print(path)
    if path[0] == '/':
        path = path[1:]
    print(cwd_total)
    with cd(cwd_total):
        return os.makedirs(path)


def rm_handler(cwd_total, client_message):
    path = client_message['path']
    if path[0] == '/':
        path = path[1:]
    path = os.path.join(cwd_total, path)
    path = path.replace('/', '\\')
    enc_file_name=path.split('\\')[-1]
    if client_message['command_flag'] == '-r':
        process = subprocess.Popen(['rmdir', '/s', '/q', '%s' % path], shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        process.wait()
        output, error = process.communicate()
        if len(error) == 0:
            return False
        else:
            return True
    try:
        os.remove(path + '.txt')
        delete_file(enc_file_name,client_message['client_user_name'])       ################################# new new 
        return True
    except:
        return False


def ls_handler_linux(cwd_total, client_message):
    path = client_message['path']
    if len(path) == 0:
        pass
    elif path[0] == '/':
        path = path[1:]
    with cd(cwd_total):
        process = subprocess.Popen(["ls", "-l", "%s" % path], shell=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        process.wait()
    output, error = process.communicate()
    if len(error) != 0:
        return False  # دستور دچار خطا شد
    else:
        result = re.sub(r'.*\r\n\r\n', '', output.decode())
        result = re.sub(r'^\s{0,1}.*?\.\r\n', '', result)  ########## خروجی رو درست کن سپس بفرست
        return result


def rm_handler_linux(cwd_total, client_message):
    path = client_message['path']
    if path[0] == '/':
        path = path[1:]
    path = os.path.join(cwd_total, path)
    enc_file_name=path.split('/')[-1]        ############################################### new new
    if client_message['command_flag'] == '-r':
        process = subprocess.Popen(['rm', '-rf', '%s' % path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.wait()
        output, error = process.communicate()
        print(error.decode())
        if len(error) == 0:

            return False
        else:
            return True
    try:
        print("***")
        os.remove(path + '.txt')
        delete_file(enc_file_name,client_message['client_user_name'])  ################## new new new
        return True
    except:
        print("**")
        return False


def mv_handler_linux(cwd_total, client_message):
    access_path = client_message['access_path']
    dest_path = client_message['dest_path']
    if access_path[0] == '/':
        access_path = access_path[1:]
    if dest_path[0] == '/':
        dest_path = dest_path[1:]
    access_path = os.path.join(cwd_total, access_path)
    enc_file_name=access_path.split('/')[-1]      ######new new new
    dest_path = os.path.join(cwd_total, dest_path)
    new_path=dest_path 
    if client_message['command_flag'] == '-r':
        try:
            process = subprocess.Popen(['mv', '%s' % access_path, '%s' % dest_path], shell=True, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            process.wait()
            output, error = process.communicate()
            if len(error) != 0:
                print(error.decode())
                return False
            else:
                return True
        except:
            return False
    else:
        try:
            access_path += '.txt'
            process = subprocess.Popen(['mv', '%s' % access_path, '%s' % dest_path], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            process.wait()
            output, error = process.communicate()
            if len(error) != 0:
                print(error.decode())
                return False
            else:
                update_file(enc_file_name,client_message['client_user_name'],new_path)   ######new new new
                return True
        except:
            print(error.decode())
            return False


class cd:
    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)


command = ['dir']


def lcs(S, T):
    m = len(S)
    n = len(T)
    counter = [[0] * (n + 1) for x in range(m + 1)]
    longest = 0
    lcs_set = set()
    for i in range(m):
        for j in range(n):
            if S[i] == T[j]:
                c = counter[i][j] + 1
                counter[i + 1][j + 1] = c
                if c > longest:
                    lcs_set = set()
                    longest = c
                    lcs_set.add(S[i - c + 1:i + 1])
                elif c == longest:
                    lcs_set.add(S[i - c + 1:i + 1])

    return lcs_set


def mv_handler(cwd_total, client_message):
    access_path = client_message['access_path']
    dest_path = client_message['dest_path']
    if access_path[0] == '/':
        access_path = access_path[1:]
    if dest_path[0] == '/':
        dest_path = dest_path[1:]
    access_path = os.path.join(cwd_total, access_path)
    access_path = access_path.replace('/', '\\')
    enc_file_name=access_path.split('\\')[-1]      ######new new new
    dest_path = os.path.join(cwd_total, dest_path)
    new_path=dest_path                     ######new new new
    dest_path = dest_path.replace('/', '\\')
    if client_message['command_flag'] == '-r':
        try:
            process = subprocess.Popen(['move', '%s' % access_path, '%s' % dest_path], shell=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait()
            output, error = process.communicate()
            if len(error) != 0:
                return False
            else:
                return True
        except:
            return False
    else:
        try:
            access_path += '.txt'
            process = subprocess.Popen(['move', '%s' % access_path, '%s' % dest_path], shell=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait()
            output, error = process.communicate()
            if len(error) != 0:
                return False
            else:
                update_file(enc_file_name,client_message['client_user_name'],new_path)   ######new new new
                return True
        except:
            return False

def check_path(client_path,file_path,cwd_total):
    client_path=os.path.join(cwd_total,client_path)
    return os.path.normpath(client_path)==os.path.normpath(file_path)

def deserialize(message):
    return json.loads(message.decode())
