import socket
import threading
import json
import hashlib
import requests
import schedule
import time
import datetime

import tkinter as tk 
from tkinter import messagebox
from tkinter import ttk
from tkinter import *
from tkinter.ttk import *
from typing import Sized
from PIL import Image, ImageTk

HOST = "127.0.0.1"
PORT = 55555
HEADER = 1024
FORMAT = "utf-8"
ADDR = (HOST, PORT)
DISCONNECT_MESSAGE = "Disconnect"
SIGNUP = "Signup"
LOGIN = "Login"
LOGOUT = "Logout"
SEARCH = "Search"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(ADDR)
s.listen()

LiveAccount = []

def addNewAccount(username, password):
    password = str(hashlib.md5(password.strip().encode(FORMAT)).hexdigest())
    newUser = {
        'username': username,
        'password': password
    }
    with open('userDatabase.json', 'r') as fin:
        data = json.load(fin)
        fin.close()
    data['users'].append(newUser)
    with open('userDatabase.json', 'w') as fout:
        json.dump(data, fout, indent=4)
        fout.close()


def checkClientSignUp(username):
    with open('userDatabase.json', 'r') as fin:
        data = json.load(fin)
        fin.close()

    for i in data["users"]:
        if(i["username"].strip() == username.strip()):
            return False
    return True


def clientSignUp(conn):
    username = conn.recv(HEADER).decode(FORMAT)
    conn.sendall(username.encode(FORMAT))

    password = conn.recv(HEADER).decode(FORMAT)

    username = username.strip()
    print(username)
    print(password)
    accepted = checkClientSignUp(username)
    print("accept:", accepted)
    conn.sendall(str(accepted).encode(FORMAT))
    if accepted:
        addNewAccount(username, password)

    print("End Sign Up\n")

def checkLivedAccount(username):
    for i in LiveAccount:
        if i == username:
            return True
    return False


def checkClientLogin(username, password):
    password = str(hashlib.md5(password.strip().encode(FORMAT)).hexdigest())
    if checkLivedAccount(username) == True:
        return 0

    with open('userDatabase.json', 'r') as fin:
        data = json.load(fin)
        fin.close()

    for i in data["users"]:
        if(i["username"].strip() == username.strip() and i["password"] == password):
            return 1
    return 2


def clientLogIn(conn):
    username = conn.recv(HEADER).decode(FORMAT)
    conn.sendall(username.encode(FORMAT))

    password = conn.recv(HEADER).decode(FORMAT)

    accepted = checkClientLogin(username, password)
    if accepted == 1:
        LiveAccount.append(username)

    print("accepted:", accepted)
    conn.sendall(str(accepted).encode(FORMAT))
    print("End Log In\n")
    

def clientSearch(conn):
    with open('database.json', 'r') as f:
        data = json.load(f)
        f.close()
    time = conn.recv(HEADER).decode(FORMAT)
    conn.sendall(time.encode(FORMAT))
    country = conn.recv(HEADER).decode(FORMAT)
    info = []
    notify = "0"
    for i in data:
        if(i["time"] == time):
            notify = "1"
            for j in i["info"]:
                if (j["country"] == country):
                    notify = "2"
                    info.append("Country: " + str(j["country"]))
                    info.append("Cases: " + str(j["cases"]))
                    info.append("Deaths: " + str(j["deaths"]))
                    info.append("Recovered: " + str(j["recovered"]))
                    info = "\n".join(info)
                    break
            break
    if (notify == "2"):
        conn.sendall("2".encode(FORMAT))
        conn.recv(HEADER).decode(FORMAT)
        conn.sendall(str(info).encode(FORMAT))
    elif (notify == "1"):
        conn.sendall("1".encode(FORMAT))
    elif (notify == "0"):
        conn.sendall("0".encode(FORMAT))


def clientLogOut(conn):
    username = conn.recv(HEADER).decode(FORMAT)
    for i in LiveAccount:
        if i == username:
            LiveAccount.remove(i)
            conn.sendall("True".encode(FORMAT))

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")

    while True:
        msg = conn.recv(HEADER).decode(FORMAT)

        if(msg == LOGIN):
            clientLogIn(conn)
        elif(msg == SIGNUP):
            clientSignUp(conn)
        elif(msg == SEARCH):
            clientSearch(conn)
        elif(msg == LOGOUT):
            clientLogOut(conn)

    conn.close()



def startServer():
    try: 
        

        print(HOST)
        print("Waiting for Client")
        
        while True:
            conn, addr = s.accept()

            clientThread = threading.Thread(target=handle_client, args=(conn,addr))
            # sThread.daemon = True
            clientThread.start()
            

    except KeyboardInterrupt:
        print("Error")
        s.close()
    finally:
        s.close()
        print("end")    


class App_Server(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        self.title("Covid Information")
        self.geometry("1000x600")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.resizable(width=False, height=False)

        container = tk.Frame(self)
        container.place(x = 0, y = 0)

        # container.grid_rowconfigure(0, weight=1)
        # container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (Background_Server, Home_Server):
            frame = F(container, self)

            self.frames[F] = frame 

            frame.grid(row=0, column=0, sticky="nsew")

        self.showFrame(Background_Server)


    def showFrame(self, container):
        
        frame = self.frames[container]
        if container == Home_Server:
            self.geometry("500x500")

        else:
            self.geometry("1000x600")
        frame.tkraise()
        
    
    def logIn(self, curFrame):

        username = curFrame.entry_username.get()
        password = curFrame.entry_password.get()
        if password == "":
            curFrame.notice["text"] = "password cannot be empty"
            return 

        if username == "admin" and password == "1":
            self.showFrame(Home_Server)
            curFrame.notice["text"] = ""
        else:
            curFrame.notice["text"] = "invalid username or password"

    

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.destroy()


class Background_Server(tk.Frame):
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent)

        self.img = Image.open("image/login_server.png")
        self.render = ImageTk.PhotoImage(self.img)
    
        canvas = Canvas(self, width=self.img.size[0], height=self.img.size[1])
        canvas.create_image(0, 0, anchor=NW, image=self.render)
        canvas.pack(fill=BOTH, expand=1)

        self.notice = tk.Label(self,text="",bg="#6184D6",fg='red')
        self.entry_username = tk.Entry(self,width=40,bg='white')
        self.entry_password = tk.Entry(self,width=40,bg='white', show="*")
        self.entry_username.place(x = 607, y = 260, height=40)
        self.entry_password.place(x = 607, y = 340, height=40)
        self.button_log = tk.Button(self,width = 40,cursor="hand2" ,text="LOG IN",bg="#7B96D4",fg='floral white',command=lambda: control.logIn(self))
        self.button_log.place(x = 607, y = 410, height=40)
        self.notice.place(x = 670, y = 380)
    
class Home_Server(tk.Frame):
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent)

        self.img = Image.open("image/home_server.png")
        self.render = ImageTk.PhotoImage(self.img)
    
        canvas = Canvas(self, width=self.img.size[0], height=self.img.size[1])
        canvas.create_image(0, 0, anchor=NW, image=self.render)
        canvas.place(x = 0, y = 0)
        
        self.data = tk.Listbox(self, height = 15, width = 40, bg='floral white',activestyle = 'dotbox', font = "Helvetica", fg='#20639b')
        self.data.place(x = 70, y = 120)
        self.button_log = tk.Button(self,width= 15,cursor="hand2" ,text="REFRESH",bg="#20639b",fg='floral white',command=self.Update_Client)
        self.button_back = tk.Button(self,width= 15,cursor="hand2", text="LOG OUT",bg="#20639b",fg='floral white' ,command=lambda: control.showFrame(Background_Server))
        self.button_log.place(x = 90, y =430)
        self.button_back.place(x = 300, y =430)  

    def Update_Client(self):
        self.data.delete(0,len(LiveAccount))
        for i in range(len(LiveAccount)):
            self.data.insert(i,LiveAccount[i])



# def updateData():
#     r = requests.get('https://coronavirus-19-api.herokuapp.com/countries')
#     my_dict = r.json()

#     d = datetime.datetime.now()
#     time = str(d.strftime("%d")) + "/" + str(d.strftime("%m")) + "/" + d.strftime("%y")
    
#     with open('database.json', 'r') as f:
#         data = json.load(f)
#         f.close()

#     newdata = {
#         "time": time,
#         "info": my_dict
#     }

#     if (data[len(data) - 1]["time"] == time):
#         data[len(data) - 1] = newdata
#     else:
#         data.append(newdata)

#     with open('database.json', 'w') as f:
#         json.dump(data, f, indent=4)
#         f.close()
#     print("Update Data")


# def checkTimeUpdate():
#     schedule.every(60).minutes.do(updateData)

#     while True:
#         schedule.run_pending()
#         time.sleep(1)
# sThreadUpdate = threading.Thread(target=checkTimeUpdate)
# sThreadUpdate.daemon = True
# sThreadUpdate.start()

sThread = threading.Thread(target= startServer)
sThread.daemon = True
sThread.start()

app = App_Server()
app.mainloop()