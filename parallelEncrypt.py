import multiprocessing as mp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2
import sys
import os
import time
import pyodbc
import psutil


# Function to insert encryption information into the database
def insert_or_update_encryption_info(db_file, chunk_sizes1, chunk_sizes2, chunk_sizes3, chunk_sizes4, chunk_sizes5, chunk_sizes6, chunk_sizes7, chunk_sizes8, chunk_sizes9, chunk_sizes10, chunk_sizes11, chunk_sizes12, salt,user_id):
    try:
        conn = pyodbc.connect('DRIVER={SQL Server};SERVER=DESKTOP-QRNR7JP\\SQLEXPRESS;DATABASE=' + db_file + ';Trusted_Connection=yes;')
        c = conn.cursor()
        # Insert or replace encryption information in the table

        c.execute('''INSERT INTO EncryptionInfo 
                    (chunk_size1, chunk_size2, chunk_size3, chunk_size4, chunk_size5, 
                    chunk_size6, chunk_size7, chunk_size8, chunk_size9, chunk_size10, 
                    chunk_size11, chunk_size12, salt, user_id) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (chunk_sizes1, chunk_sizes2, chunk_sizes3, chunk_sizes4, 
                    chunk_sizes5, chunk_sizes6, chunk_sizes7, chunk_sizes8, chunk_sizes9, 
                    chunk_sizes10, chunk_sizes11, chunk_sizes12, salt, user_id))
        conn.commit()
        c.execute('SELECT id from EncryptionInfo where salt=?',(salt,) )
        file_id= c.fetchone()
        conn.close()
        return file_id[0]
    except pyodbc.Error as e:
        print("Error inserting encryption information into the database:", e)
        sys.exit(1)

def enough_memory_for_process(chunksize):
    # Get system memory information
    mem = psutil.virtual_memory()
    # Check if there is enough free memory (at least 2GB free)
    return mem.available >= chunksize

def encrypt_AES(key, plaintext, output_file, semaphore, id, id_var, shared_arr):
    try:
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        cipher_data = cipher.encrypt(pad(plaintext, AES.block_size))
        ciphernoncelen = len(cipher_data) + len(nonce)
        #critical section
        while True:
            if id_var.value == id:
                if semaphore.acquire(timeout=0.5):  # Try acquiring semaphore with a timeout
                    with open(output_file, 'ab') as f:
                        shared_arr[id-1] = ciphernoncelen
                        f.write(nonce + cipher_data)
                    id_var.value = id + 1
                    semaphore.release()
                    break
            else:
                time.sleep(0.1) 
    except Exception as e:
        print("Encryption error:", e)
        sys.exit(1)

if __name__ == "__main__":
    try:
        if len(sys.argv) != 6:
            print("Usage: python parallelEncrypt.py <input_file> <output_file> <key> <fileid> <Keysize>")
            sys.exit(1)
            
        
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        password = sys.argv[3]
        fileid = sys.argv[4]
        passlength = int(sys.argv[5])
        if passlength not in [16,24,32]:
            print("Key Size can be only 16,24,32 bytes")
            sys.exit(1)
        db_file = 'app_database'
        start = time.time()
        salt = get_random_bytes(passlength)
        key = PBKDF2(password, salt, dkLen=passlength)
        file_size = os.path.getsize(input_file)
        if file_size == 0:
            print("The file is empty.")
            sys.exit(1)
            
        semaphore = mp.Semaphore(1)
        processor_count = mp.cpu_count()
        shared_arr = mp.Array('i', [0] * processor_count)
        id_var = mp.Value('i', 1)
        chunksize = file_size // processor_count  
        if not enough_memory_for_process(chunksize):
            print("Not Enough Memory")
            sys.exit(1)
        if file_size % processor_count != 0: 
            chunksize += 1
        processes = []
        i = 0
        with open(input_file, 'rb') as f_input:
            while True:
                i += 1
                chunk = f_input.read(chunksize)
                if not chunk:
                    break
                while not enough_memory_for_process(chunksize):
                    time.sleep(0.3)
                p = mp.Process(target=encrypt_AES, args=(key, chunk, output_file, semaphore, i, id_var, shared_arr))
                processes.append(p)
                p.start()

        for process in processes:
            process.join()
            
        insert_or_update_encryption_info(db_file, fileid, shared_arr[0], shared_arr[1], shared_arr[2], shared_arr[3], shared_arr[4], shared_arr[5], shared_arr[6], shared_arr[7], shared_arr[8], shared_arr[9], shared_arr[10], shared_arr[11],salt)

        
        end = time.time()
        duration = end - start
        print("Time taken for Encryption",duration)
    except Exception as e:
        print("An error occurred:", e)