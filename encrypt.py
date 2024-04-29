from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time

start_time = time.time()
salt = b'\xa9\x9fi\xad\xd6~\x9f{UKw\x9d^\xd9E\xa1\xdaA\xd0]Q\xbd^\x13\xf6\x18\x07\xbe\x8e\x84\x1e@'
password = 'dennysanthosh'
key = PBKDF2(password, salt, dkLen=32)
input_file = '600text1_1_1.txt'
output_file = 'encrypted.txt'
nonce = get_random_bytes(8)


with open(input_file, 'rb') as f:
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        with open(output_file,'wb') as w:
                w.write(nonce)
                w.write(cipher.encrypt(pad(f.read(), AES.block_size)))
     
end_time = time.time()
actual_time = end_time-start_time
print("time taken : ",actual_time)