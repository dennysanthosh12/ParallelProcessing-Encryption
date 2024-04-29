from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.setStyleSheet("background-color: #040840;")

        # Create a vertical layout for the main window
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")

        # Create a frame to hold the form
        self.frame = QtWidgets.QFrame(Dialog)
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.frame.setMinimumSize(QtCore.QSize(300, 400))

        # Create a vertical layout for the frame
        self.frameLayout = QtWidgets.QVBoxLayout(self.frame)
        self.frameLayout.setObjectName("frameLayout")

        # Place widgets inside the frame
        self.label = QtWidgets.QLabel(self.frame)
        self.label.setStyleSheet("color:rgb(225,225,225);font-size:20pt;")
        self.label.setObjectName("label")
        self.frameLayout.addWidget(self.label, alignment=QtCore.Qt.AlignCenter)

        self.label_2 = QtWidgets.QLabel(self.frame)
        self.label_2.setStyleSheet("font-size:18px;color: rgb(0, 167, 250)")
        self.label_2.setObjectName("label_2")
        self.frameLayout.addWidget(self.label_2)

        self.email = QtWidgets.QLineEdit(self.frame)
        self.email.setStyleSheet("color:rgb(0, 0, 0);background-color: white;border-radius: 5px;height:35px;font-size:20px;")
        self.email.setObjectName("email")
        self.frameLayout.addWidget(self.email)

        self.label_3 = QtWidgets.QLabel(self.frame)
        self.label_3.setStyleSheet("font-size:18px;color: rgb(0, 167, 250)")
        self.label_3.setObjectName("label_3")
        self.frameLayout.addWidget(self.label_3)

        self.password = QtWidgets.QLineEdit(self.frame)
        self.password.setStyleSheet("color:rgb(0, 0, 0);background-color: white;border-radius: 5px;height:35px;font-size:20px;")
        self.password.setObjectName("password")
        self.frameLayout.addWidget(self.password)

        self.loginbutton = QtWidgets.QPushButton(self.frame)
        self.loginbutton.setStyleSheet(    "QPushButton {"
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
        self.loginbutton.setObjectName("loginbutton")
        self.frameLayout.addWidget(self.loginbutton, alignment=QtCore.Qt.AlignCenter)

        self.label_4 = QtWidgets.QLabel(self.frame)
        self.label_4.setStyleSheet("color:rgb(163, 163, 163)")
        self.label_4.setObjectName("label_4")
        self.frameLayout.addWidget(self.label_4, alignment=QtCore.Qt.AlignCenter)

        self.pushButton = QtWidgets.QPushButton(self.frame)
        self.pushButton.setStyleSheet(    "QPushButton {"
                                    "   background-color: #4CAF50;"
                                    "   color: white;"
                                    "   font-size: 15px;"
                                    "   border-radius: 5px;"
                                    "   padding: 5px;"
                                    "}"
                                    "QPushButton:hover {"
                                    "   background-color: #45a049;"
                                    "}"
                                    "QPushButton:pressed {"
                                    "   background-color: #3e8e41;"
                                    "}")
        self.pushButton.setObjectName("pushButton")
        self.frameLayout.addWidget(self.pushButton, alignment=QtCore.Qt.AlignCenter)

        # Set size policy for the frame to be Expanding
        self.frame.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        # Add the frame to the main layout
        self.verticalLayout.addWidget(self.frame, alignment=QtCore.Qt.AlignCenter)
        Dialog.setMinimumSize(QtCore.QSize(400, 500))

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Login"))
        self.label.setText(_translate("Dialog", "Login"))
        self.label_2.setText(_translate("Dialog", "Username"))
        self.label_3.setText(_translate("Dialog", "Password"))
        self.loginbutton.setText(_translate("Dialog", "Login"))
        self.label_4.setText(_translate("Dialog", "Don\'t have an account?"))
        self.pushButton.setText(_translate("Dialog", "Sign up"))

# Example usage:
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)

    # Set the size policy for the dialog to be Expanding
    Dialog.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

    Dialog.show()
    sys.exit(app.exec_())
