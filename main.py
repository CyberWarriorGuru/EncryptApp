import sys
from PyQt5.QtWidgets import *
import os
import base64
import ui_main
import shutil
from cryptography.fernet import Fernet
import zipfile
import hashlib
import sqlite3
import random
import string
import logging
import datetime

class Main(QDialog, ui_main.Ui_Dialog):
    def __init__(self, parent = None):
        super(Main, self).__init__(parent)
        self.setupUi(self)
        nowtime = datetime.datetime.now()       # Get current time to insert log
        logging.basicConfig(filename='db.log', encoding='utf-8', level=logging.DEBUG)   # db.log file create
        logging.info('The programe running at' + str(nowtime))          # record time at start programe
        self.count = 0                      # count input password. If count above 3 times, file is deleted
        self.BLOCK_SIZE = 65536             # hash block size
        ######There are 7 group box in this programe.  So in this part, encrypt file group box is shown and others are hidden
        self.groupBox_encryptfile.show()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.hide()
        ############################

        # Options Button Functions.  In this part, you can set visible or hidden of groupboxes
        self.btn_encryptfile.clicked.connect(self.fnbtn_enfile_option)
        self.btn_decryptfile.clicked.connect(self.fnbtn_defile_option)
        self.btn_encryptfolder.clicked.connect(self.fnbtn_enfolder_option)
        self.btn_decryptfolder.clicked.connect(self.fnbtn_defolder_option)
        self.btn_filecheck.clicked.connect(self.fnbtn_checkfile_option)
        self.btn_enrar.clicked.connect(self.fnbtn_enrar_option)
        self.btn_derar.clicked.connect(self.fnbtn_derar_option)
        self.btn_filecheck.clicked.connect(self.fnbtn_checkfile_option)
        #######################################

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
        # Decrypt folder Browser button function
        self.btn_defolderbrowser.clicked.connect(self.fnbtn_defolder_browser)
        # Decrypt folder decrypt button function
        self.btn_decryptfolder_2.clicked.connect(self.fnbtn_defolder_decrypt)
        # Rar and Zip File browser button function
        self.btn_enrarbrowser.clicked.connect(self.fnbtn_enrar_browser)
        # rar and zip encrypt button function
        self.btn_encryptrar.clicked.connect(self.fnbtn_enrar_encrypt)
        # rar and zip file browser de button function
        self.btn_derarbrowser.clicked.connect(self.fnbtn_derar_browser)
        # rar and zip decrypt button function
        self.btn_decryptrar.clicked.connect(self.fnbtn_derar_decrypt)
        # file check browser
        self.btn_checkfilebrowser.clicked.connect(self.fnbtn_check_browser)
        # save file hash in db
        self.btn_savedbhash.clicked.connect(self.fnbtn_save_hash)
        # get all file id from db
        self.getallID()
        # if user change combobox fnChangeComboBox function running
        self.comboBox_dbID.currentTextChanged.connect(self.fnChangeComboBox)
        # open file1 and get hash value
        self.btn_getfilehash1.clicked.connect(self.fnGetFile1Hash)
        # compare hash of file1 and database
        self.btn_compare.clicked.connect(self.fnCompare)

    def fnCompare(self):
        m_file1 = self.textEdit_file1_hash.toPlainText()    #select file hash value
        m_file2 = self.textEdit_dbhash.toPlainText()        # get hash value from database
        if m_file1 == m_file2:          # If they are equal, file is safe but else, file is modify
            QMessageBox.information(self, "Information", "Hash of file is correct")
        else:
            QMessageBox.warning(self, "Warning", "The File is modify")

    def fnGetFile1Hash(self):    # Open file and get hash value
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))            # show open dialog
        with open(opendlg[0], 'rb') as file:
            original = file.read()              # read file from open dialog
        temp_hash = str(original[-64:].decode("utf-8"))     # read data converted string from bytes
        self.textEdit_file1_hash.setText(str(temp_hash))    # show string of hash

    def fnChangeComboBox(self):                 # if user select combobox , this function running
        id = self.comboBox_dbID.currentText()   # get current text of combobox
        sqliteConnection = sqlite3.connect('HashDB.db') # 'HashDB' database connect
        nowtime = datetime.datetime.now()           # get current time to record in log file
        logging.basicConfig(filename='db.log', encoding='utf-8', level=logging.DEBUG)  # open log file
        logging.info('The programe sync database at' + str(nowtime))            # record time
        cursor = sqliteConnection.cursor()                  # create cursor to execute sql query
        cursor.execute("SELECT HASH FROM HashTable where ID=?", (id,))
        rows = cursor.fetchone()        # get data from database
        try:
            self.textEdit_dbhash.setText(str(rows[0]))  # show hash value from database
        except:
            nowtime = datetime.datetime.now()
            logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
            logging.warning('The programe does not sync database at' + str(nowtime))        # record time when error happen in database

    # get all file id from database
    def getallID(self):
        try:
            sqliteConnection = sqlite3.connect('HashDB.db')
            nowtime = datetime.datetime.now()
            logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
            logging.info('The programe sync database at' + str(nowtime))        # record time when sync database
            cursor = sqliteConnection.cursor()
            cursor.execute("SELECT ID FROM HashTable")
            rows = cursor.fetchall()
            self.comboBox_dbID.clear()          # clear combobox to show again
            for row in rows:
                self.comboBox_dbID.addItem(row[0])      # insert data in combobox
        except:
            nowtime = datetime.datetime.now()
            logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
            logging.warning('The programe does not sync database at' + str(nowtime))        # record time when error happen in sync database
    # save hash value after generate hash value
    def fnbtn_save_hash(self):
        try:
            sqliteConnection = sqlite3.connect('HashDB.db')
            cursor = sqliteConnection.cursor()
            nowtime = datetime.datetime.now()  # this part is connect database and create cursor to execute query
            logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
            logging.info('The programe sync database at' + str(nowtime))    # record time when sync database
            sqlite_insert_query = '''INSERT INTO HashTable (ID, HASH) VALUES (?,?)'''
            insert_data = (self.ID, self.hash)  # make turple from id and hash to insert database
            try:
                cursor.execute(sqlite_insert_query, insert_data)
                sqliteConnection.commit()           # save database
                sqliteConnection.close()            # close database
                self.getallID()                     # refresh combobox after save hash in database
            except:
                QMessageBox.warning(self, "Error", "Already exist.  Please try again")
                nowtime = datetime.datetime.now()
                logging.basicConfig(filename='example.log', encoding='utf-8', level=logging.DEBUG)
                logging.info('The ID is already exist in database. this time is ' + str(nowtime))       # record time when sync error with database
        except:
            pass

    def fnbtn_check_browser(self):
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))
        self.input_checkpath.setText(opendlg[0])     # show path of file
        filename = os.path.basename(opendlg[0])
        size = os.path.getsize(opendlg[0])              # get size of file
        with open(opendlg[0], 'rb') as file:
            original = file.read()
        if original[:6] != b'gAAAAA':           # check this file is encrypt file.  So if header part is gAAAAA, this is encrypt file but else this is not encrypt file
            QMessageBox.warning(self, "Warning", "This isn't encrypt file")
            return
        self.input_detail_name.setText(str(filename))
        self.input_detail_size.setText(str(size)+"Bytes")       # show size of file with bytes
        try:
            self.hash = str(original[-64:].decode("utf-8"))     # get hash value from file.  hash value is in file at last
            self.input_detail_hash.setText(self.hash)           # show hash value of file
            self.ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))  # id random generate
            self.label_19.setText(self.ID)  # show file id
            QMessageBox.information(self, "Your ID", "The File id for" + str(filename)+ " will be " + self.ID)
        except:
            QMessageBox.warning(self, "Warning", "This isn't encrypt file")
            self.input_detail_hash.setText("Error")

    def count_upper_case_letters(self,str_obj):   # this function is count uppercase to check input password.
        count = 0
        for elem in str_obj:
            if elem.isupper():          # every character check and if he is uppercase, increase count
                count += 1
        return count

    def count_lower_case_letters(self, str_obj):  # this function is counted lowercase to check input password
        count = 0
        for elem in str_obj:
            if elem.islower():          # every character check and if he is lowercase, increase count
                count += 1
        return count

    def count_number_letters(self, str_obj):          # this function is counted number to check input password
        count = 0
        for elem in str_obj:
            if elem.isnumeric():            # every character check and if he is number, increase count
                count += 1
        return count

    def count_special_letters(self, str_obj): # this function is counted special character to check input password
        count = 0
        for elem in str_obj:
            if (elem.isalpha()):
                pass
            elif (elem.isdigit()):
                pass
            else:
                count = count + 1           # every character check and if he isn't letter and number, increase count
        return count

    def fnbtn_enfile_option(self):              # if user click Encrypt File button in options, this function show only encrypt file groupbox and others are hidden
        self.groupBox_encryptfile.show()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.hide()

    def fnbtn_defile_option(self):            # if user click decrypt File button in options, this function show only decrypt file groupbox and others are hidden
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.show()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.hide()

    def fnbtn_enfolder_option(self):    # if user click Encrypt folder button in options, this function show only encrypt folder groupbox and others are hidden
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.show()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.hide()

    def fnbtn_defolder_option(self):    # if user click decrypt folder button in options, this function show only decrypt folder groupbox and others are hidden
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.show()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.hide()

    def fnbtn_checkfile_option(self):   # if user click 'File Integrity Checker' button in options, this function show only 'File Integrity Checker' groupbox and others are hidden
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.show()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.hide()
        self.getallID()

    def fnbtn_enrar_option(self):        # if user click Encrypt rar button in options, this function show only encrypt rar groupbox and others are hidden
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.show()
        self.groupBox_decryptrar.hide()

    def fnbtn_derar_option(self):   # if user click decrypt rar button in options, this function show only decrypt rar groupbox and others are hidden
        self.groupBox_encryptfile.hide()
        self.groupBox_decryptfile.hide()
        self.groupBox_decryptfolder.hide()
        self.groupBox_encryptfolder.hide()
        self.groupBox_Filechecker.hide()
        self.groupBox_enrar.hide()
        self.groupBox_decryptrar.show()

    def fnbtn_enfile_browser(self):             # show open file dialog when user click browser button in encrypt file groupbox
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))
        self.input_enfile.setText(opendlg[0])       # show file path

    def fnbtn_enfile_encrypt(self):         # click encrypt file button function
        m_password = self.input_password.text()     # get password
        m_confirmpwd = self.input_confirmpwd.text() # get confirm password
        if m_password == "" or m_confirmpwd == "":  # if password or confirm password are blank
            QMessageBox.warning(self, "warning", "Please input password")
            return
        if m_password != m_confirmpwd:      # if they are different pop up warning message
            QMessageBox.warning(self, "warning", "Don't match password and confirm password")
            return
        if m_password == m_confirmpwd:      # if they are equal,  it check password strong
            # if password length is less than 8 character and doesn't include one uppercase and lowercase and two numbers and one special character
            # password is failed so user have to again input password for ex: Qwer123!@#
            if len(m_password) >= 8 and self.count_upper_case_letters(m_password) >= 1 and self.count_lower_case_letters(m_password) >= 1 and self.count_number_letters(m_password) >= 2 and self.count_special_letters(m_password) >= 1:
                file_path = self.input_enfile.text()
                try:
                    self.fnEncryptFile(file_path, m_password)   # if password is strong , it encrypt file
                except:
                    QMessageBox.warning(self, "warning", "Please check all elements")
            else:
                QMessageBox.warning(self, "warning", "Password must be above 8 length and included 1 lowercase/uppercase letter and 2 numberand 1 special charcter")

    def fnEncryptFile(self, inputfile_path, key):
        # if length of key isn't 32 ,  it add 0 at last of key
        if len(key) < 32:
            key += '0' * (32 - len(key))
        else:
            key = key[0:32]
        key = bytes(key, 'utf-8')      # convert string to bytes.  Because all operate in cipher, used bytes
        aes_key = base64.urlsafe_b64encode(key)     # encoding key with base64
        fernet = Fernet(aes_key)        # create Fernet cipher mode basic on aes
        hash_tag = self.fnGetHash(inputfile_path)   # get file hash value
        with open(inputfile_path, 'rb') as file:
            original = file.read()          # read file with byte mode
        encrypted = fernet.encrypt(original) + bytes(hash_tag, 'utf-8')  # add hash value at end of file after encrypt file
        os.remove(inputfile_path)   # original file is deleted
        with open(inputfile_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)         # create encrypt file
        self.output_enfile.setText(inputfile_path)  # show output path of file
        QMessageBox.information(self, "Success", "Success Encrypt")

    def fnGetHash(self, inputfile_path):
        file_hash = hashlib.sha256()            # create sha256 object
        with open(inputfile_path, 'rb') as f:  # Open the file to read it's bytes
            fb = f.read(self.BLOCK_SIZE)  # Read from the file. Take in the amount declared above
            while len(fb) > 0:  # While there is still data being read from the file
                file_hash.update(fb)  # Update the hash
                fb = f.read(self.BLOCK_SIZE)  # Read the next block from the file
        return file_hash.hexdigest()        # return hexdigest of hash value

    def fnbtn_defile_browser(self):
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))        # show ope file dialog to decrypt file
        self.input_defile.setText(opendlg[0])   # show path of file

    def fnbtn_defile_decrypt(self):     # click decrypt file button action
        m_password = self.input_depassword.text()   # get password
        file_path = self.input_defile.text()        # get file path to decrypt
        try:
            self.fnDecryptFile(file_path, m_password)  # decrypt file function
        except:
            QMessageBox.warning(self, "warning", "Please check all input element")

    def fnDecryptFile(self, inputfile_path, key):
        # if length of key isn't 32 ,  it add 0 at last of key
        if len(key) < 32:
            key += '0' * (32 - len(key))
        else:
            key = key[0:32]
        key = bytes(key, 'utf-8')   # convert string to bytes.  Because all operate in cipher, used bytes
        aes_key = base64.urlsafe_b64encode(key)     # encoding key with base64
        fernet = Fernet(aes_key)         # create Fernet cipher mode basic on aes
        with open(inputfile_path, 'rb') as file:
            original = file.read()          # read data from encrypt filoe
        try:
            decrypted = fernet.decrypt(original[:-64])      # get data from encrypt file without hash value
        except:
            self.count += 1             # if user input incorrect password, count increase
            if self.count >= 3 :        # and then if count is 3 times,  delete file
                os.remove(inputfile_path)
                QMessageBox.error(self, "Failed", "You enter incorrect password 3 times.")
                self.count = 0
                return
            QMessageBox.warning(self, "Failed", "Please input correct password")
            return
        os.remove(inputfile_path)       # delete encrypt file and generate decrypt file
        with open(inputfile_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        QMessageBox.information(self, "Success", "Success Decrypt")
        self.output_defile.setText(inputfile_path)

    def fnbtn_enfolder_browser(self):           # select folder to encrypt
        try:
            folder = str(QFileDialog.getExistingDirectory(self, "Select Directory"))
        except:
            pass
        self.input_enfolder.setText(folder)     # show folder path

    def fnbtn_enfolder_encrypt(self):
        m_folderpath = self.input_enfolder.text()           # get file path
        m_password = self.input_folderpassword.text()       # get password
        m_confirmpwd = self.input_confirmfolderpwd.text()   # get confirm password
        if m_password == "" or m_confirmpwd == "":          # password check their matching and strong
            QMessageBox.warning(self, "warning", "Please input password")
            return
        if m_password != m_confirmpwd:
            QMessageBox.warning(self, "warning", "Don't match password and confirm password")
            return
        if m_password == m_confirmpwd:
            if len(m_password) >= 8 and self.count_upper_case_letters(
                    m_password) >= 1 and self.count_lower_case_letters(m_password) >= 1 and self.count_number_letters(
                    m_password) >= 2 and self.count_special_letters(m_password) >= 1:
                try:
                    # zipped folder
                    self.fnzipdir(m_folderpath)
                    # encrypt zip file
                    self.fnFolderEncrypt(m_folderpath + ".zip", m_password)
                except:
                    QMessageBox.warning(self, "warning", "Please check all elements")
            else:
                QMessageBox.warning(self, "warning",
                                    "Password must be above 8 length and included 1 lowercase/uppercase letter and 2 numberand 1 special charcter")

    # zipped folder to encrypt folder
    def fnzipdir(self, path):
        shutil.make_archive(path, 'zip', path)
        shutil.rmtree(path)                 # delete folder after zipped folder

    def fnEncryptRar(self, inputfile_path, key):
        # if length of key isn't 32 ,  it add 0 at last of key
        if len(key) < 32:
            key += '0' * (32 - len(key))
        else:
            key = key[0:32]
        key = bytes(key, 'utf-8')  # convert string to bytes
        aes_key = base64.urlsafe_b64encode(key)     # encoding base64
        fernet = Fernet(aes_key)        # create Fernet cipher object
        hash_tag = self.fnGetHash(inputfile_path)   # get file hash value
        with open(inputfile_path, 'rb') as file:
            original = file.read()          # read data of file
        encrypted = fernet.encrypt(original) + bytes(hash_tag, 'utf-8') # and encrypt file and add hash value at end
        os.remove(inputfile_path)       # remove original file
        with open(inputfile_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)     # and then create encrypt file
        QMessageBox.information(self, "Success", "Success Encrypt")

    def fnFolderEncrypt(self, input_path, key):
        if len(key) < 32:       # if length of key isn't 32 ,  it add 0 at last of key
            key += '0' * (32 - len(key))
        else:
            key = key[0:32]
        key = bytes(key, 'utf-8')
        aes_key = base64.urlsafe_b64encode(key)
        fernet = Fernet(aes_key)
        with open(input_path, 'rb') as file:    # read folder file
            original = file.read()
        encrypted = fernet.encrypt(original)
        os.remove(input_path)       # remove orignal file
        with open(input_path[:-4]+".folder", 'wb') as encrypted_file:  # create *.folder file
            encrypted_file.write(encrypted)
        self.output_enfolder.setText(input_path[:-4]+".folder")
        QMessageBox.information(self, "Success", "Success Encrypt")

    def fnbtn_defolder_browser(self):       # open decrypt folder browser function.  it shows open file dialog and user can open .folder file to decrypt it
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", ("*.folder"))
        self.input_defolder.setText(opendlg[0])

    def fnbtn_defolder_decrypt(self):       # this is decrypt folder function
        m_password = self.input_depassword_2.text()
        file_path = self.input_defolder.text()
        try:
            self.fnDecryptFolder(file_path, m_password)
        except:
            QMessageBox.warning(self, "warning", "Please check all input element")

    def fnDecryptFolder(self, inputfile_path, key):
        if len(key) < 32:       # if length of key isn't 32 ,  it add 0 at last of key
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
            self.count += 1
            if self.count >= 3 :        # if user input incorrect password 3 times, delete file
                os.remove(inputfile_path)
                QMessageBox.error(self, "Failed", "You enter incorrect password 3 times.")
                self.count = 0
                return
            QMessageBox.warning(self, "Failed", "Please input correct password")
            return
        os.remove(inputfile_path)
        with open(inputfile_path[:-6]+".zip", 'wb') as decrypted_file:      # create decrypt file
            decrypted_file.write(decrypted)
        with zipfile.ZipFile(inputfile_path[:-6]+".zip", 'r') as zip_ref:
            zip_ref.extractall(inputfile_path[:-6])
        os.remove(inputfile_path[:-6]+".zip")
        QMessageBox.information(self, "Success", "Success Decrypt")

    def fnbtn_enrar_browser(self):  # this is show open dialog to encrypt rar or zip file
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", ("*.rar *.zip"))
        self.input_enrar.setText(opendlg[0])

    def fnbtn_enrar_encrypt(self):      # this is encrypt rar or zip file function
        m_password = self.input_rarpassword.text()
        m_confirmpwd = self.input_rarconfirmpwd.text()

        # this part is password check with their matching and strong
        if m_password == "" or m_confirmpwd == "":
            QMessageBox.warning(self, "warning", "Please input password")
            return
        if m_password != m_confirmpwd:
            QMessageBox.warning(self, "warning", "Don't match password and confirm password")
            return
        if m_password == m_confirmpwd:
            if len(m_password) >= 8 and self.count_upper_case_letters(m_password) >= 1 and self.count_lower_case_letters(m_password) >= 1 and self.count_number_letters(m_password) >= 2 and self.count_special_letters(m_password) >= 1:
                file_path = self.input_enrar.text()
                try:
                    # encrypt rar function
                    self.fnEncryptRar(file_path, m_password)
                except:
                    QMessageBox.warning(self, "warning", "Please check all elements")
            else:
                QMessageBox.warning(self, "warning", "Password must be above 8 length and included 1 lowercase/uppercase letter and 2 numberand 1 special charcter")

    def fnbtn_derar_browser(self):
        opendlg = QFileDialog.getOpenFileName(self, ("Open File"), "", (""))
        self.input_derar.setText(opendlg[0])

    def fnbtn_derar_decrypt(self):
        m_password = self.input_derarpassword.text()        # get password
        file_path = self.input_derar.text()                 # get path
        try:
            self.fnDecryptRar(file_path, m_password)
        except:
            QMessageBox.warning(self, "warning", "Please check all input element")

    def fnDecryptRar(self, inputfile_path, key):
        # if length of key isn't 32 ,  it add 0 at last of key
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
            decrypted = fernet.decrypt(original[:-64])
        except:
            self.count += 1
            if self.count >= 3 :           # if user input incorrect password 3 times file is delteted
                os.remove(inputfile_path)
                QMessageBox.error(self, "Failed", "You enter incorrect password 3 times.")
                self.count = 0
                return
            QMessageBox.warning(self, "Failed", "Please input correct password")
            return
        os.remove(inputfile_path)
        with open(inputfile_path, 'wb') as decrypted_file:      # create decrypt file
            decrypted_file.write(decrypted)
        QMessageBox.information(self, "Success", "Success Decrypt")
        self.output_derar.setText(inputfile_path)

app = QApplication(sys.argv)
form = Main()
form.show()
app.exec_()