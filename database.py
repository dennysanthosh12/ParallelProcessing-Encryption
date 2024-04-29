import pyodbc
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class DatabaseManager:
    def __init__(self, db_name='app_database'):
        self.conn = pyodbc.connect('DRIVER={SQL Server};SERVER=DESKTOP-QRNR7JP\\SQLEXPRESS;DATABASE=' + db_name + ';Trusted_Connection=yes;')

    def generate_rsa_key_pair(self):
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Serialize private key to PEM format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Get public key from private key
        public_key = private_key.public_key()
        # Serialize public key to PEM format
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_private_key, pem_public_key

    def insert_user(self, email, password):
        cursor = self.conn.cursor()
        private_key, public_key = self.generate_rsa_key_pair()
        try:
            cursor.execute('INSERT INTO users (email, password, private_key, public_key) VALUES (?, ?, ?, ?)', (email, password, private_key, public_key))
            self.conn.commit()
            return True
        except pyodbc.IntegrityError:
            # Handle duplicate email error
            return False

    def verify_user(self, email, password):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email=? AND password=?', (email, password))
        user = cursor.fetchone()
        return user is not None 

    def validate_user(self, email, password):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email=? AND password=?', (email, password))
        user = cursor.fetchone()
        return user is not None

    def close_connection(self):
        self.conn.close()
