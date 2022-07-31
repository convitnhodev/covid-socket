import socket
import threading
import os

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

#GLOBAL socket initialize
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)


class App_Client(tk.Tk):
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
        for F in (Background_Client, Home_Client):
            frame = F(container, self)

            self.frames[F] = frame 

            frame.grid(row=0, column=0, sticky="nsew")

        self.showFrame(Background_Client)


    def showFrame(self, container):
        
        frame = self.frames[container]
        if container == Home_Client:
            self.geometry("500x500")

        else:
            self.geometry("1000x600")
        frame.tkraise()
        
    def logIn(self,curFrame,client):
        try:
            username = curFrame.entry_username.get()
            password = curFrame.entry_password.get()

            if username == '' or password == '':
                curFrame.notice = "username and password cannot be empty"
            
            msg = LOGIN
            client.sendall(msg.encode(FORMAT))

            client.sendall(username.encode(FORMAT))
            client.recv(HEADER)

            client.sendall(password.encode(FORMAT))

            self.user = username

            accepted = client.recv(HEADER).decode(FORMAT)
            if accepted == "1":
                self.showFrame(Home_Client)
                curFrame.notice["text"] = ""

            elif accepted == "2":
                curFrame.notice["text"] = "Invalid username or password"
            elif accepted == "0":
                curFrame.notice["text"] = "User already logged in"

        except:
            print("Error: Server is not responding")   


    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.destroy()
            try:
                if(self.user == ''):
                    return
                else:
                    username = self.user
                    msg = LOGOUT
                    client.sendall(msg.encode(FORMAT))
                    client.sendall(username.encode(FORMAT))
            except:
                pass

    def signUp(self, client, curFrame):
        try:

            username = curFrame.entry_username.get()
            password = curFrame.entry_password.get()
            print(username)
            print(password)
            if password == "":
                curFrame.notice["text"] = "password cannot be empty"
                return 
            msg = SIGNUP
            client.sendall(msg.encode(FORMAT))

            client.sendall(username.encode(FORMAT))
            client.recv(HEADER)

            client.sendall(password.encode(FORMAT))

            accepted = client.recv(HEADER).decode(FORMAT)
            if accepted == "True":
                self.showFrame(Background_Client)
                curFrame.notice["text"] = "Sign up success"
            else:
                curFrame.notice["text"] = "Username already exists"
            
        except:
            print("Error: Server is not responding") 

    def logOut(self, client, preFrame):
        try:
            username = preFrame.user
            msg = LOGOUT
            client.sendall(msg.encode(FORMAT))
            client.sendall(username.encode(FORMAT))
            accepted = client.recv(HEADER).decode(FORMAT)
            if accepted == "True":
                self.showFrame(Background_Client)
        except:
            print("Error: Server is not responding")  
    

class Background_Client(tk.Frame):
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent)

        self.img = Image.open("./image/login_client.png")
        self.render = ImageTk.PhotoImage(self.img)
    
        canvas = Canvas(self, width=self.img.size[0], height=self.img.size[1])
        canvas.create_image(0, 0, anchor=NW, image=self.render)
        canvas.pack(fill=BOTH, expand=1)

        self.notice = tk.Label(self,text="",bg="#6184D6",fg='red')
        self.entry_username = tk.Entry(self,width=40,bg='white')
        self.entry_password = tk.Entry(self,width=40,bg='white', show="*")
        self.entry_username.place(x = 607, y = 260, height=40)
        self.entry_password.place(x = 607, y = 340, height=40)
        self.button_log = tk.Button(self,width = 10,cursor="hand2" ,text="LOG IN",bg="#7B96D4",fg='floral white',command=lambda: control.logIn(self, client))
        self.button_sign = tk.Button(self,width = 10,cursor="hand2" ,text="SIGN UP",bg="#7B96D4",fg='floral white',command=lambda: control.signUp(client,self))
        self.button_log.place(x = 607, y = 410, height=40)
        self.button_sign.place(x = 810, y = 410, height=40)
        self.notice.place(x = 670, y = 380)


class Home_Client(tk.Frame):
    def __init__(self, parent, control):
        tk.Frame.__init__(self, parent)
        
        self.img = Image.open("./image/home_client.png")
        self.render = ImageTk.PhotoImage(self.img)
    
        canvas = Canvas(self, width=self.img.size[0], height=self.img.size[1])
        canvas.create_image(0, 0, anchor=NW, image=self.render)
        canvas.place(x = 0, y = 0)
        
        
        self.button_back = tk.Button(self,width= 15,cursor="hand2", text="LOG OUT",bg="#20639b",fg='floral white' ,command=lambda: control.logOut(client, control))
        self.button_back.place(x = 400, y = 10)  

        self.entry_time = tk.Entry(self,width= 30, bg= 'white')
        self.entry_search = tk.Entry(self,width = 30, bg = 'white')
        self.button_search = tk.Button(self,width=10,cursor="hand2", text="SEARCH",bg="#7B96D4",fg='floral white',command=lambda: self.Search())
        self.entry_time.place(x = 180, y = 120, height= 30)
        self.entry_search.place(x = 20, y = 180, height= 30)
        self.button_search.place(x = 250, y =180)

        self.data = tk.Listbox(self, height = 10, width = 40, bg='floral white',activestyle = 'dotbox', font = "Helvetica", fg='#20639b')
        self.data.place(x = 70, y = 230)

    def Search(self):
        try:
            msg = SEARCH
            client.sendall(msg.encode(FORMAT))
            time = self.entry_time.get()
            country = self.entry_search.get()
            client.sendall(time.encode(FORMAT))
            client.recv(HEADER)
            client.sendall(country.encode(FORMAT))

            notify = client.recv(HEADER).decode(FORMAT)
            if (notify == "0"):
                notice = "No Data"
                self.data.delete(0,10)
                self.data.insert(0,notice)
            elif (notify == "1"):
                notice = "No Country found"
                self.data.delete(0,10)
                self.data.insert(0,notice)
            elif (notify == "2"):
                client.sendall(notify.encode(FORMAT))
                info = client.recv(HEADER).decode(FORMAT)
                show = info.split("\n")
                self.data.delete(0,len(show))
                
                for i in range(len(show)):
                    self.data.insert(i,show[i])

        except:
            print("Error: Server is not responding")    

app = App_Client()


try:
    app.mainloop()
except:
    print("Error")
    client.close()

finally:
    client.close()


