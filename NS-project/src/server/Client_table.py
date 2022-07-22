import json
import sqlite3


def create():
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS clients(
            firstname text,
            lastname text,
            username text,
            encrypted_username text,
            password text,
            public_key text
            );""")

    client_directory.commit()
    client_directory.close()


def create_session_key_table():
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS session_keys(
            user_name text,
            session_key text,
            seq_num  INTEGER,
            joiningDate timestamp,
            cwd text
            );""")

    client_directory.commit()
    client_directory.close()

    ########################           new new new new


def create_file_table():
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS file_table(
            enc_file_name text,
            user_owner text,
            subscriber_username text,
            permission_type text,
            file_path text,
            integrity text
            );""")

    client_directory.commit()
    client_directory.close()


def add_file(enc_file_name, user_owner, file_path):
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute(
        "INSERT INTO file_table(enc_file_name,user_owner,file_path) VALUES ('" + enc_file_name + "', '" + user_owner + "', '" +
        file_path + "');")
    client_directory.commit()
    client_directory.close()


def delete_file(enc_file_name, user_owner):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """DELETE from file_table where enc_file_name=? and user_owner=?"""
    cursor.execute(sql_select_query, (enc_file_name, user_owner))
    connection.commit()
    cursor.close()
    connection.close()


def update_file(enc_file_name, user_owner, new_path):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """UPDATE file_table SET file_path=? where enc_file_name=? and user_owner=?"""
    cursor.execute(sql_select_query, (new_path, enc_file_name, user_owner))
    connection.commit()
    cursor.close()
    connection.close()


def find_file(enc_file_name, user_owner):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """SELECT * FROM file_table WHERE enc_file_name=? and user_owner=?"""
    cursor.execute(sql_select_query, (enc_file_name, user_owner))
    records = cursor.fetchone()
    cursor.close()
    connection.close()
    return records


def update_shared_file(enc_file_name, user_owner, subscriber_username, permission_type):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """UPDATE file_table SET subscriber_username=?,permission_type=? where enc_file_name=? and user_owner=?"""
    cursor.execute(sql_select_query, (subscriber_username, permission_type, enc_file_name, user_owner))
    connection.commit()
    cursor.close()
    connection.close()

    ######################################


def delete_auth_user(client_user_name):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """DELETE from session_keys where user_name=?"""
    cursor.execute(sql_select_query, (client_user_name,))
    connection.commit()
    cursor.close()
    connection.close()


def update_sequence_number(username, seq_number):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """UPDATE session_keys SET seq_num=? where user_name=?"""
    cursor.execute(sql_select_query, (seq_number, username))
    connection.commit()
    cursor.close()
    connection.close()


def update_cwd(client_user_name, new_cwd):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    sql_select_query = """Update session_keys set cwd=? where user_name= ?"""
    data = (new_cwd, client_user_name)
    cursor.execute(sql_select_query, data)
    connection.commit()
    cursor.close()
    connection.close()


def find_auth_user(client_user_name):
    connection = sqlite3.connect('clients.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM session_keys WHERE user_name='" + client_user_name + "' ")
    records = cursor.fetchone()
    cursor.close()
    connection.close()
    return records


def find_client(username):
    try:
        client_directory = sqlite3.connect('clients.db')
        cursor = client_directory.cursor()
        cursor.execute("SELECT * FROM clients WHERE username = '" + username + "' ")
        return cursor.fetchone()
        client_directory.close()
    except:
        error = 'Failed to find user'
        return error


def add_session_key(user_name, session_key, seq_num, joiningDate, cwd):
    joiningDate = str(joiningDate)
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    sqlite_insert_with_param = """INSERT INTO session_keys
                          (user_name,session_key,seq_num, joiningDate, cwd)
                          VALUES (?, ?, ?, ?, ?);"""

    data_tuple = (user_name, session_key, seq_num, joiningDate, cwd)
    cursor.execute(sqlite_insert_with_param, data_tuple)
    client_directory.commit()
    client_directory.close()


def add_client(first_name, last_name, username, password, enc_username, public_key):
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("INSERT INTO clients VALUES ('" + first_name + "', '" + last_name + "', '" +
                   username + "' , '" + enc_username + "' , '" + password + "' , '" + public_key + "');")
    client_directory.commit()
    client_directory.close()


def delete_key(username):
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("DELETE FROM session_keys WHERE user_name = '" + username + "' ")
    client_directory.commit()
    client_directory.close()


def table_contains_key(username):
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("SELECT * FROM session_keys WHERE user_name = '" + username + "' ")
    item = cursor.fetchone()
    client_directory.close();
    if item is None:
        return False
    else:
        return True


def table_contains_client(username):
    client_directory = sqlite3.connect('clients.db')
    cursor = client_directory.cursor()
    cursor.execute("SELECT * FROM clients WHERE username = '" + username + "' ")
    item = cursor.fetchone()
    client_directory.close();
    if item is None:
        return False
    else:
        return True
