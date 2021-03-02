import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkmacosx import Button
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

root = tk.Tk()
root.title("Password Storage System")
root.withdraw()  # to hide the root window and ask for master password
objects = []
global counter
counter = 0
# ---------------------------------- ENCRYPTION ALGORITHM ---------------------------------
access = 'vendz'
password = access.encode()  # convert to type bytes
salt = b'w\x8a\x0b\x93f}\xd7u\xecD/3\xda\x1e\x05\xbd'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))  # can only use KDF(key derivation function) once
f = Fernet(key)


# ---------------------------------------- CLASSES ----------------------------------------


class popupWindow(object):
    loop = False
    attempts = 0

    def __init__(self, master):
        window = self.window = Toplevel(master)
        window.title('Input Password')
        window.geometry('{}x{}'.format(250, 100))
        window.resizable(width=False, height=False)
        self.label = Label(window, text=" Password: ", font=('Courier', 14), justify=CENTER)
        self.label.pack()
        self.entry = Entry(window, show='*', width=30)
        self.entry.pack(pady=7)
        self.button = Button(window, text='Submit', command=self.authenticate, font=('Courier', 14))
        self.button.pack()

    def authenticate(self):
        self.value = self.entry.get()

        if self.value == access:
            self.loop = True
            self.window.destroy()
            root.deiconify()
        else:
            self.attempts += 1
            if self.attempts == 5:
                root.quit()
                messagebox.showerror("INCORRECT PASSWORD", "You have exhausted your attempts")
            else:
                self.entry.delete(0, 'end')
                messagebox.showerror('INCORRECT PASSWORD',
                                     'INCORRECT PASSWORD \n attempts remaining: ' + str(5 - self.attempts))


class entity_add:
    def __init__(self, main_window, email, username, password):
        self.email = email
        self.username = username
        self.password = password
        self.root = main_window

    def write(self):
        file = open("app_manager.txt", "a")
        username = self.username
        password = self.password
        email = self.email

        byte_username = bytes(username, 'utf-8')  # converting username to byte array
        byte_encrypted_username = f.encrypt(byte_username)  # encrypting username
        username_encrypted = byte_encrypted_username.decode('utf-8')  # converting to string from bytes

        byte_email = bytes(email, 'utf-8')  # converting email to byte array
        byte_encrypted_email = f.encrypt(byte_email)  # encrypting email
        email_encrypted = byte_encrypted_email.decode('utf-8')  # converting to string from bytes

        byte_password = bytes(password, 'utf-8')  # converting password input to byte array
        byte_encrypted_password = f.encrypt(byte_password)  # encrypting password
        password_encrypted = byte_encrypted_password.decode('utf-8')  # converting to string from bytes

        file.write(username_encrypted + "," + email_encrypted + "," + password_encrypted + "\n")
        file.close()


class entity_display:
    def __init__(self, root, username, email, password, count):
        self.root = root
        self.username = username
        self.email = email
        self.password = password
        self.count = count

        byte_en_username = bytes(self.username, 'utf-8')  # converting the username to byte array
        decrypt_username = f.decrypt(byte_en_username)  # decrypting username
        original_username = decrypt_username.decode()  # converting byte array to string

        byte_en_email = bytes(self.email, 'utf-8')  # converting the email to byte array
        decrypt_email = f.decrypt(byte_en_email)  # decrypting email
        original_email = decrypt_email.decode()  # converting byte array to string

        byte_en_password = bytes(self.password, 'utf-8')  # converting the password to byte array
        decrypt_password = f.decrypt(byte_en_password)  # decrypting password
        original_password = decrypt_password.decode()  # converting byte array to string

        len_original_password = len(original_password)
        label_password = "*" * len_original_password

        self.username_display_label = Label(self.root, text=original_username, font=("Courier", 14))
        self.email_display_label = Label(self.root, text=original_email, font=("Courier", 14))
        self.password_display_label = Label(self.root, text=label_password,
                                            font=("Courier", 14))  # this will show password in '*'
        self.password_text_label = Label(self.root, text=original_password,
                                         font=("Courier", 14))  # this will show password in 'clear text'
        self.showButton = Button(self.root, text="show", fg='red', command=self.show)
        self.deleteButton = Button(self.root, text='delete', fg='red', command=self.delete)

    def display(self):
        self.username_display_label.grid(row=6 + self.count, sticky=W, padx=5)
        self.email_display_label.grid(row=6 + self.count, column=1, padx=5)
        self.password_display_label.grid(row=6 + self.count, column=2, sticky=E, padx=5)
        self.showButton.grid(row=6 + self.count, column=3, sticky=E)
        self.deleteButton.grid(row=6 + self.count, column=4, sticky=E)

    def delete(self):
        row = self.deleteButton.grid_info()['row']
        ask = messagebox.askquestion("Are You Sure", "are you sure you want to delete this?")

        if ask == "yes":

            objects[int(row - 6)].destroy()

            file = open("app_manager.txt", "r")
            lines = file.readlines()
            file.close()

            file = open("app_manager.txt", "w")
            count = 0

            for line in lines:
                if count != self.count:
                    file.write(line)
                    count += 1

            file.close()
            readfile()

    def destroy(self):
        self.username_display_label.destroy()
        self.email_display_label.destroy()
        self.password_display_label.destroy()
        self.showButton.destroy()
        self.deleteButton.destroy()

    def show(self):

        if self.showButton['text'] == "hide":
            self.showButton['text'] = "show"
            self.password_text_label.grid_forget()
            self.password_display_label.grid(row=6 + self.count, column=2, sticky=E, padx=5)
        else:
            self.showButton['text'] = "hide"
            self.password_display_label.grid_forget()
            self.password_text_label.grid(row=6 + self.count, column=2, sticky=E, padx=5)

# --------------------------------------- FUNCTIONS ---------------------------------------


def onadd():
    email = email_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    entries = entity_add(root, email, username, password)
    entries.write()
    email_entry.delete(0, 'end')
    username_entry.delete(0, 'end')
    password_entry.delete(0, 'end')
    messagebox.showinfo('Added Entity', 'Successfully Added, \n' + 'Username: ' + username + '\nEmail: ' + email)
    readfile()


def readfile():
    file = open("app_manager.txt", "r")
    count = 0

    for line in file:
        entityList = line.split(",")
        e = entity_display(root, entityList[0], entityList[1], entityList[2], count)
        objects.append(e)
        e.display()
        count += 1
    file.close()


# ---------------------------------------- GRAPHICS ---------------------------------------

master = popupWindow(root)  # this will first ask for password and then display main window

title = Label(root, text="Add Entity", font=("Courier", 18))
title.grid(columnspan=3, row=0)
username_label = Label(root, text="Username: ", font=("Courier", 14))
username_label.grid(row=1, sticky=E, padx=3)
username_entry = Entry(root, font=("Courier", 14))
username_entry.grid(columnspan=3, row=1, column=1, padx=2, pady=2, sticky=W)
email_label = Label(root, text="Email: ", font=("Courier", 14))
email_label.grid(row=2, sticky=E, padx=3)
email_entry = Entry(root, font=("courier", 14))
email_entry.grid(row=2, column=1, columnspan=3, padx=2, pady=2, sticky=W)
password_label = Label(root, text="Password: ", font=("Courier", 14))
password_label.grid(row=3, sticky=E, padx=3)
password_entry = Entry(root, font=("Courier", 14), show="*")
password_entry.grid(row=3, column=1, columnspan=3, padx=2, pady=2, sticky=W)
add_btn = Button(root, text="Add", font=("Courier", 14), command=onadd)
add_btn.grid(row=4, columnspan=3)

name_label2 = Label(root, text='Name: ', font=('Courier', 14))
name_label2.grid(row=5)
email_label2 = Label(root, text='Email: ', font=('Courier', 14))
email_label2.grid(row=5, column=1)
pass_label2 = Label(root, text='Password: ', font=('Courier', 14))
pass_label2.grid(row=5, column=2)

readfile()  # this will show all the contents from txt file on opening the root window
root.mainloop()
