import sys
from PyQt5.QtWidgets import *
import os
import base64
import ui_main
import shutil
from cryptography.fernet import Fernet

class Main(QDialog, ui_main.Ui_Dialog):
    def __init__(self, parent = None):
        super(Main, self).__init__(parent)
        self.setupUi(self)
        self.groupBox_encryptfile.show()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        # AES key length
        self.keylen = len(Fernet.generate_key())
        # Options Button Functions
        self.btn_encryptfile.clicked.connect(self.fnbtn_enfile_option)
        self.btn_decryptfile.clicked.connect(self.fnbtn_defile_option)
        self.btn_encryptfolder.clicked.connect(self.fnbtn_enfolder_option)
        self.btn_decryptfolder.clicked.connect(self.fnbtn_defolder_option)
        self.btn_filecheck.clicked.connect(self.fnbtn_checkfile)
        # Encrypt File Browser button function
        self.btn_enbrowser.clicked.connect(self.fnbtn_enfile_browser)
        # Encrypt File button Function
        self.btn_encryptfile_2.clicked.connect(self.fnbtn_enfile_encrypt)
        # Decrypt File Browser Button Function
        self.btn_debrowser.clicked.connect(self.fnbtn_defile_browser)
        # Decrypt File button Function
        self.btn_decryptfile_2.clicked.connect(self.fnbtn_defile_decrypt)
        # Encrypt folder Browser button function
        self.btn_enfolderbrowser.clicked.connect(self.fnbtn_enfolder_browser)
        # Encrypt folder Encrypt Button
        self.btn_encryptfolder_2.clicked.connect(self.fnbtn_enfolder_encrypt)


    def count_upper_case_letters(self,str_obj):
        count = 0
        for elem in str_obj:
            if elem.isupper():
                count += 1
        return count

    def count_lower_case_letters(self, str_obj):
        count = 0
        for elem in str_obj:
            if elem.islower():
                count += 1
        return count

    def count_number_letters(self, str_obj):
        count = 0
        for elem in str_obj:
            if elem.isnumeric():
                count += 1
        return count

    def count_special_letters(self, str_obj):
        count = 0
        for elem in str_obj:
            if (elem.isalpha()):
                pass
            elif (elem.isdigit()):
                pass
            else:
                count = count + 1
        return count

    def fnbtn_enfile_option(self):
        self.groupBox_encryptfile.show()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()

    def fnbtn_defile_option(self):
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.show()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()

    def fnbtn_enfolder_option(self):
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.show()
        self.groupBox_Filechecker.hide()

    def fnbtn_defolder_option(self):
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.show()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()

    def fnbtn_checkfile(self):
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.show()

    def fnbtn_enfile_browser(self):
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))
        self.input_enfile.setText(opendlg[0])

    def fnbtn_enfile_encrypt(self):
        m_password = self.input_password.text()
        m_confirmpwd = self.input_confirmpwd.text()
        if m_password == "" or m_confirmpwd == "":
            QMessageBox.warning(self, "warning", "Please input password")
            return
        if m_password != m_confirmpwd:
            QMessageBox.warning(self, "warning", "Don't match password and confirm password")
            return
        if m_password == m_confirmpwd:
            if len(m_password) >= 8 and self.count_upper_case_letters(m_password) >= 1 and self.count_lower_case_letters(m_password) >= 1 and self.count_number_letters(m_password) >= 2 and self.count_special_letters(m_password) >= 1:
                file_path = self.input_enfile.text()
                try:
                    self.fnEncryptFile(file_path, m_password)
                except:
                    QMessageBox.warning(self, "warning", "Please check all elements")
            else:
                QMessageBox.warning(self, "warning", "Password must be above 8 length and included 1 lowercase/uppercase letter and 2 numberand 1 special charcter")

    def fnEncryptFile(self, inputfile_path, key):
        if len(key) < 32:
            key += '0' * (32 - len(key))
        else:
            key = key[0:32]
        key = bytes(key, 'utf-8')
        aes_key = base64.urlsafe_b64encode(key)
        fernet = Fernet(aes_key)
        with open(inputfile_path, 'rb') as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        os.remove(inputfile_path)
        with open(inputfile_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        QMessageBox.information(self, "Success", "Success Encrypt")

    def fnDecryptFile(self, inputfile_path, key):
        if len(key) < 32:
            key += '0' * (32 - len(key))
        else:
            key = key[0:32]
        key = bytes(key, 'utf-8')
        aes_key = base64.urlsafe_b64encode(key)
        fernet = Fernet(aes_key)
        with open(inputfile_path, 'rb') as file:
            original = file.read()
        try:
            decrypted = fernet.decrypt(original)
        except:
            QMessageBox.warning(self, "Failed", "Please input correct password")
            return
        os.remove(inputfile_path)
        with open(inputfile_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        QMessageBox.information(self, "Success", "Success Decrypt")

    def fnbtn_defile_browser(self):
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))
        self.input_defile.setText(opendlg[0])

    def fnbtn_defile_decrypt(self):
        m_password = self.input_depassword.text()
        file_path = self.input_defile.text()
        try:
            self.fnDecryptFile(file_path, m_password)
        except:
            QMessageBox.warning(self, "warning", "Please check all input element")

    def fnbtn_enfolder_browser(self):
        try:
            file = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        except:
            pass
        self.input_enfolder.setText(file)

    def fnbtn_enfolder_encrypt(self):
        m_folderpath = self.input_enfolder.text()
        self.fnzipdir(m_folderpath)

    # zipped folder to encrypt folder
    def fnzipdir(self, path):
        shutil.make_archive(path, 'zip', path)
        os.remove(path)




app = QApplication(sys.argv)
form = Main()
form.show()
app.exec_()