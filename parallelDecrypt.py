import multiprocessing as mp
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
import sys
import os
import time
import sqlite3
import pyodbc

def retrieve_encryption_info(db_file, file_id):
    conn = pyodbc.connect('DRIVER={SQL Server};SERVER=DESKTOP-QRNR7JP\\SQLEXPRESS;DATABASE=' + db_file + ';Trusted_Connection=yes;')
    c = conn.cursor()
    c.execute('''SELECT chunk_size1, chunk_size2, chunk_size3, chunk_size4, chunk_size5, chunk_size6, chunk_size7, chunk_size8, chunk_size9, chunk_size10, chunk_size11, chunk_size12, salt FROM EncryptionInfo WHERE id = ?''', (file_id,))
    result = c.fetchone()
    conn.close()
    dbchunk = []
    if result:
        dbchunk = result[:-1]
        salt = result[-1]
        return dbchunk,salt
    else:
        return None, None


def decrypt_AES(key, ciphertext_with_nonce, output_file, semaphore, id, id_var):
    nonce = ciphertext_with_nonce[:8]
    cipher_data = ciphertext_with_nonce[8:]
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_data = cipher.decrypt(cipher_data)
    try:
        decrypted_data = unpad(decrypted_data, AES.block_size)
    except ValueError:
        # Data is not padded, no need to unpad
        pass
    while True:
        if id_var.value == id:
            if semaphore.acquire(timeout=0.5):
                with open(output_file, 'ab') as f:
                    f.write(decrypted_data)
                id_var.value = id + 1
                semaphore.release()
                break
        else:
            time.sleep(0.1)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        
        print("Usage: python decdatabase.py <input_file> <output_file> <key> <fileid>")
        sys.exit(1)
    start= time.time()
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]
    fileid= sys.argv[4]
    semaphore = mp.Semaphore(1)

    db_file = 'app_database'
    chunk_sizes = []
    chunk_sizes,salt = retrieve_encryption_info(db_file, fileid)
    processor_count = mp.cpu_count()
    key = PBKDF2(password, salt, dkLen=len(salt))
    file_size = os.path.getsize(input_file)
    if file_size == 0:
        print("The file is empty.")
        sys.exit(1)

    id_var = mp.Value('i', 1)
    processes = []
    data_chunks = []
    with open(input_file, 'rb') as f_input:
        for i, chunk_size in enumerate(chunk_sizes):
            chunk = f_input.read(chunk_size)
            p = mp.Process(target=decrypt_AES, args=(key,chunk,output_file,semaphore,i+1,id_var))
            processes.append(p)
            p.start()
    f_input.close()
    for process in processes:
        process.join()
    end=time.time()
    duration=end-start
    print("executed in :",duration,"seconds")