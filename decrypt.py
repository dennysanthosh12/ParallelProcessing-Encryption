from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
import time

start_time = time.time()
salt = b'\xa9\x9fi\xad\xd6~\x9f{UKw\x9d^\xd9E\xa1\xdaA\xd0]Q\xbd^\x13\xf6\x18\x07\xbe\x8e\x84\x1e@'
password = 'dennysanthosh'
key = PBKDF2(password, salt, dkLen=32)
input_file = 'encrypted.txt'
output_file = 'decrypted.txt'

with open(input_file, 'rb') as f:
    nonce = f.read(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    with open(output_file, 'wb') as f1:
        f1.write(unpad(cipher.decrypt(f.read()), AES.block_size))  # Assuming decrypted data is text
end_time = time.time()
actual_time = end_time-start_time
print(actual_time)