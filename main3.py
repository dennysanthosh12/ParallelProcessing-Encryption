import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QVBoxLayout, QMessageBox, QLineEdit, QDialog, QLabel, QHBoxLayout,QInputDialog
from PyQt5 import QtCore
import multiprocessing as mp
import psutil
import time
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import os
from PyQt5.QtCore import Qt
from database import DatabaseManager
from login_ui import Ui_Dialog as LoginDialog
from register_ui import Ui_Dialog as RegisterDialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging

from parallelEncrypt import encrypt_AES,enough_memory_for_process,insert_or_update_encryption_info
from parallelDecrypt import retrieve_encryption_info, decrypt_AES
from cryptography.hazmat.primitives import serialization

class CustomInputDialog(QDialog):
    def __init__(self, for_encryption=True, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Enter Encryption Details' if for_encryption else 'Enter Decryption Details')
        # Set up the layout
        layout = QVBoxLayout()

        # Create QLineEdit widgets for password and file ID
        self.password_edit = QLineEdit(self)
        self.password_edit.setPlaceholderText('Enter Password')
        layout.addWidget(self.password_edit)

        # For encryption, include AES key size and recipient email fields
        if for_encryption:
            self.pass_length_edit = QLineEdit(self)
            self.pass_length_edit.setPlaceholderText('Enter AES Key size')
            layout.addWidget(self.pass_length_edit)

            self.receiver_email_edit = QLineEdit(self)
            self.receiver_email_edit.setPlaceholderText('Enter Recipient Username')
            layout.addWidget(self.receiver_email_edit) 

        if not for_encryption:
            self.fileid_edit = QLineEdit(self)
            self.fileid_edit.setPlaceholderText('Enter File ID')
            layout.addWidget(self.fileid_edit)

        # Create OK and Cancel buttons
        button_box = QHBoxLayout()
        ok_button = QPushButton('OK', self)
        ok_button.clicked.connect(self.accept)
        button_box.addWidget(ok_button)

        cancel_button = QPushButton('Cancel', self)
        cancel_button.clicked.connect(self.reject)
        button_box.addWidget(cancel_button)

        layout.addLayout(button_box)
        self.setLayout(layout)
        self.setStyleSheet('''
            QDialog {
                background-color: #333;
                color: white;
            }
            QLineEdit {
                background-color: #555;
                border: 1px solid #888;
                color: white;
                padding: 8px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 18px;
                border-radius: 5px;
                padding: 10px;
                margin-top: 20px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
        ''')

        # Set specific styles for OK and Cancel buttons
        ok_button.setStyleSheet('''
            QPushButton {
                background-color: #4CAF50;
                color: white;
                font-size: 18px;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
        ''')

        cancel_button.setStyleSheet('''
            QPushButton {
                background-color: #f44336;
                color: white;
                font-size: 18px;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
            QPushButton:pressed {
                background-color: #b71c1c;
            }
        ''')

    def get_inputs(self):
        password = self.password_edit.text().strip()
        if hasattr(self, 'pass_length_edit'):
            pass_length = self.pass_length_edit.text().strip()
        else:
            pass_length = None
        if hasattr(self, 'receiver_email_edit'):
            receiver_email = self.receiver_email_edit.text().strip()
        else:
            receiver_email = None

        return password, pass_length, receiver_email
    
    def get_inputs_decrypt(self):
        password = self.password_edit.text().strip()
        file_id = self.fileid_edit.text().strip()
        return password,file_id

class CryptoApp(QWidget):
    def __init__(self, email, db_manager, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Encryption & Decryption Tool')
        self.setMinimumSize(QtCore.QSize(400, 400))
        self.setStyleSheet("background-color: #040840;")
        self.db_manager = db_manager
        self.user_id = self.get_user_id(email)  # Get user ID from database

        # Email label
        self.email_label = QLabel(f'Logged in as: {email}', self)
        self.email_label.setStyleSheet("color: white; font-size: 16px;")

        # Encrypt and Decrypt buttons
        self.btn_encrypt = QPushButton('Encryption', self)
        self.btn_encrypt.setStyleSheet(    "QPushButton {"
                                    "   background-color: #4CAF50;"
                                    "   color: white;"
                                    "   font-size: 18px;"
                                    "   border-radius: 5px;"
                                    "   padding: 10px;"
                                    "}"
                                    "QPushButton:hover {"
                                    "   background-color: #45a049;"
                                    "}"
                                    "QPushButton:pressed {"
                                    "   background-color: #3e8e41;"
                                    "}")

        self.btn_decrypt = QPushButton('Decryption', self)
        self.btn_decrypt.setStyleSheet(    "QPushButton {"
                                    "   background-color: #4CAF50;"
                                    "   color: white;"
                                    "   font-size: 18px;"
                                    "   border-radius: 5px;"
                                    "   padding: 10px;"
                                    "}"
                                    "QPushButton:hover {"
                                    "   background-color: #45a049;"
                                    "}"
                                    "QPushButton:pressed {"
                                    "   background-color: #3e8e41;"
                                    "}")

        # Button click connections
        self.btn_encrypt.clicked.connect(self.encrypt_file)
        self.btn_decrypt.clicked.connect(self.decrypt_file)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.email_label)
        layout.addStretch(1)  # Add stretchable space
        layout.addWidget(self.btn_encrypt)
        layout.addWidget(self.btn_decrypt)
        layout.addStretch(1)  # Add stretchable space

        self.setLayout(layout)

    def get_user_id(self, email):
        # Fetch user ID from the database based on the email
        cursor = self.db_manager.conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email=?', (email,))
        user = cursor.fetchone()
        if user:
            return user[0]
        else:
            return None
    
    def get_public_key(self,receiver_email):
        cursor = self.db_manager.conn.cursor()

        cursor.execute('SELECT public_key from users where email=?',(receiver_email,))
        public_key = cursor.fetchone()
        if public_key:
            
            pem_public_key = serialization.load_pem_public_key(
                public_key[0],
            backend=default_backend()
        )
            return pem_public_key
        else :
            return None
        
    def get_private_key(self):
        cursor = self.db_manager.conn.cursor()

        cursor.execute('SELECT private_key FROM users WHERE id=?', (self.user_id,))
        private_key_row = cursor.fetchone()
        
        if private_key_row:
            # Extract the private key bytes from the database row
            private_key_bytes = private_key_row[0]

            # Load the PEM-encoded private key bytes
            pem_private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,  # No password because it was serialized with NoEncryption()
                backend=default_backend()
            )
            return pem_private_key
        else:
            return None


    def encrypt_file(self):
        try:
            input_file, _ = QFileDialog.getOpenFileName(self, 'Select File to Encrypt', '', 'All Files (*)')
            if not input_file:
                return
            
            _, extension = os.path.splitext(input_file)

            # Construct the output file path with the "Encrypted" prefix and the same extension
            output_file = f'Encrypted{extension}'
            
            input_dialog = CustomInputDialog(self)
            if input_dialog.exec_():
                password, pass_length, receiver_email = input_dialog.get_inputs()
            else:
                return
            receiver_public_key = self.get_public_key(receiver_email)
            if receiver_public_key is None:
                msg_box = QMessageBox()
                msg_box.setStyleSheet(
                    "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                    "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                    "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
                )
                QMessageBox.critical(msg_box, 'Error', f'Public key for receiver {receiver_email} not found.')
                return
            
            try:
                # Launch encryption process
                passlength = int(pass_length.replace(" ", "").replace("\t", "").replace("\n", ""))
                if passlength not in [16,24,32]:
                    msg_box = QMessageBox()
                    msg_box.setStyleSheet(
                    "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                    "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                    "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
                )
                    QMessageBox.critical(msg_box,'Key Size can be only 16,24,32 bytes')
                    return
                db_file = 'app_database'
                start = time.time()
                salt = get_random_bytes(passlength)
                key = PBKDF2(password, salt, dkLen=passlength)
                max_size = 2 * 1024 * 1024 * 1024
                file_size = os.path.getsize(input_file)
                if file_size == 0:
                    msg_box = QMessageBox()
                    msg_box.setStyleSheet(
                    "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                    "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                    "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
                )
                    QMessageBox.critical(msg_box,'The Selected file is empty ')
                    return
                encrypted_salt = receiver_public_key.encrypt(
                    salt,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                semaphore = mp.Semaphore(1)
                processor_count = mp.cpu_count()
                shared_arr = mp.Array('i', [0])
                id_var = mp.Value('i', 1)
                if file_size > max_size:
                    chunksize = 100 * 1024*1024
                else:
                    chunksize = file_size // processor_count  
                
                if not enough_memory_for_process(chunksize):
                    msg_box = QMessageBox()
                    msg_box.setStyleSheet(
                    "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                    "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                    "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
                )
                    QMessageBox.critical(msg_box,'Not enough memory!!')
                    return
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
                    
                file_id = insert_or_update_encryption_info(db_file, shared_arr[0],encrypted_salt,self.user_id)

                
                end = time.time()
                duration = end - start
                msg_box = QMessageBox()
                msg_box.setStyleSheet(
                    "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                    "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                    "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
                )
                QMessageBox.information(msg_box, 'Encryption', f'Encryption process completed.\n Time taken: {duration:.2f} seconds\n File ID: {file_id}')
            except Exception as e:
                msg_box = QMessageBox()
                msg_box.setStyleSheet(
                    "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                    "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                    "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
                )
                QMessageBox.critical(msg_box, 'Error', f'Encryption failed: {str(e)}')
        

        except ValueError as ve:
            logging.error(f'Error converting pass_length to integer: {ve}')
            msg_box = QMessageBox()
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
            )
            QMessageBox.critical(msg_box, 'Error', 'Invalid pass_length value. Please enter a valid integer value.')
        except Exception as e:
            logging.error(f'Encryption failed: {e}')
            msg_box = QMessageBox()
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
            )
            QMessageBox.critical(msg_box, 'Encryption Failed', f'Encryption failed: {str(e)}', QMessageBox.Ok)
            

    def decrypt_file(self):
        input_file, _ = QFileDialog.getOpenFileName(self, 'Select File to Decrypt', '', 'All Files (*)')
        if not input_file:
            return
        
        _, extension = os.path.splitext(input_file)

        # Construct the output file path with the "Encrypted" prefix and the same extension
        output_file = f'Decrypted{extension}'
        
        input_dialog = CustomInputDialog(for_encryption=False)
        if input_dialog.exec_():
            password, file_id = input_dialog.get_inputs_decrypt()
        else:
            return
        
        try:
            # Launch decryption process
            start= time.time()
            semaphore = mp.Semaphore(1)
            fileid = file_id
            db_file = 'app_database'
            chunk_sizes,salt_encrypted = retrieve_encryption_info(db_file, fileid)
            if not salt_encrypted:
                QMessageBox.critical(self, 'Error', 'Salt not found in the database for the specified file ID.')
                return
            private_key = self.get_private_key()
            if private_key is None:
                QMessageBox.critical(self, 'Error', 'Private key not found for the user.')
                return

            salt = private_key.decrypt(
                salt_encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            key = PBKDF2(password, salt, dkLen=len(salt))
            file_size = os.path.getsize(input_file)
            if file_size == 0:
                msg_box = QMessageBox()
                msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
            )
                QMessageBox.critical(msg_box,'The Selected file is empty ')
                return

            id_var = mp.Value('i', 1)
            processes = []
            i = 0
            with open(input_file, 'rb') as f_input:
                while True:
                    chunk = f_input.read(chunk_sizes)
                    if not chunk:
                        break
                    p = mp.Process(target=decrypt_AES, args=(key,chunk,output_file,semaphore,i+1,id_var))
                    processes.append(p)
                    p.start()
                    i +=1
            f_input.close()
            for process in processes:
                process.join()
            end=time.time()
            duration=end-start
            
            msg_box = QMessageBox()
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
            )
            QMessageBox.information(msg_box, 'Decryption', f'Decryption process completed.\n Time taken: {duration:.2f} seconds')
            
        except Exception as e:
            msg_box = QMessageBox()
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
                "QMessageBox QLabel {color: white;}"  # Set the label text color to white
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
            )
            QMessageBox.critical(msg_box, 'Error', f'Decryption failed: {str(e)}')

class RegisterWindow(QDialog):
    def __init__(self, db_manager, parent=None):
        super().__init__(parent)
        self.ui = RegisterDialog()
        self.ui.setupUi(self)
        self.db_manager = db_manager
        self.ui.submit_button.clicked.connect(self.submit_registration)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint)
        self.ui.login_button.clicked.connect(self.open_login)

    def submit_registration(self):
        email = self.ui.email.text()
        password = self.ui.password.text()
        confirm_password = self.ui.confirm_password.text()
        
        if not email or not password or not confirm_password:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Registration Failed")
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"
                "QMessageBox QLabel {color: white;}"
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"
            )
            msg_box.setText("Empty Fields Please fill in all fields")
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            self.close()
        
        # Ensure that the parent window (login window) remains open
            if self.parent():
                self.parent().show()

        # Check if password and confirm password match
        elif password != confirm_password:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Registration Failed")
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"
                "QMessageBox QLabel {color: white;}"
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"
            )
            msg_box.setText("Passwords do not match")
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
            self.close()
        
        # Ensure that the parent window (login window) remains open
            if self.parent():
                self.parent().show()
            
        
        elif self.db_manager.insert_user(email, password):
            msg_box = QMessageBox()
            msg_box.setStyleSheet(
            "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
            "QMessageBox QLabel {color: white;}"  # Set the label text color to white
            "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
        )
            QMessageBox.information(msg_box,'Registration Successful', 'Registration Successful')
            self.close()
        
        # Ensure that the parent window (login window) remains open
            if self.parent():
                self.parent().show()
        else:
            msg_box = QMessageBox()
            msg_box.setStyleSheet(
            "QMessageBox {background-color: #040840; color: white;}"  # Set background color to dark and text color to white
            "QMessageBox QLabel {color: white;}"  # Set the label text color to white
            "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"  # Set button background color to green and text color to white
        )
            QMessageBox.critical(msg_box, 'Registration Failed', 'Username Already exists, use a different username')
            self.close()
        
        # Ensure that the parent window (login window) remains open
            if self.parent():
                self.parent().show()

    def open_login(self):
        self.close()
        if self.parent():
            self.parent().show()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()
            if self.parent():
                self.parent().close_register()

    def handle_error_message_button_click(self, button):
    # Check if the button clicked is the OK button
        if button.text() == "OK":
            # Close the QMessageBox but do not close the application
            button.parent().parent().accept()

class LoginWindow(QDialog):
    def __init__(self, db_manager):
        super().__init__()
        self.ui = LoginDialog()
        self.ui.setupUi(self)
        self.db_manager = db_manager
        self.ui.pushButton.clicked.connect(self.open_register)
        self.ui.loginbutton.clicked.connect(self.login)
        self.setWindowFlags(self.windowFlags() | Qt.WindowMinimizeButtonHint)
        self.crypto_app = None  # This will hold the CryptoApp instance

    def open_register(self):
        self.register_window = RegisterWindow(self.db_manager, parent=self)
        self.hide()
        self.register_window.show()

    def close_register(self):
        self.register_window.close()
        self.show()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.close()

    def login(self):
        email = self.ui.email.text()
        password = self.ui.password.text()

        if not email or not password :
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Registration Failed")
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"
                "QMessageBox QLabel {color: white;}"
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"
            )
            msg_box.setText("Empty Fields Please fill in all fields")
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec_()
        
        # Check login credentials against the database
        elif self.db_manager.validate_user(email, password):  # Use validate_user instead of verify_user
            # Hide the login window
            self.hide()
            # Create CryptoApp instance if not already created
            if not self.crypto_app:
                self.crypto_app = CryptoApp(email, self.db_manager)  # Pass email and db_manager
            # Show the CryptoApp window
            self.crypto_app.show()
        else:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Login Failed")
            msg_box.setText("Invalid Username or password.")
            msg_box.setStyleSheet(
                "QMessageBox {background-color: #040840; color: white;}"
                "QMessageBox QLabel {color: white;}"
                "QMessageBox QPushButton {background-color: #4CAF50; color: white;}"
            )
            msg_box.setStandardButtons(QMessageBox.Ok)
            
            # Disable closing the application when OK button is clicked
            msg_box.buttonClicked.connect(self.handle_error_message_button_click)
            
            # Execute the QMessageBox
            msg_box.exec_()


    def handle_error_message_button_click(self, button):
    # Check if the button clicked is the OK button
        if button.text() == "OK":
            # Close the QMessageBox but do not close the application
            button.parent().parent().accept()

def main():
    app = QApplication(sys.argv)
    db_manager = DatabaseManager()
    login_window = LoginWindow(db_manager)
    login_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()