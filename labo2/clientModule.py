#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 15 09:04:07 2022

@author: ga
"""
import secrets
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
import socket
from base64 import b64encode


def startCient():

    host = "localhost"
    port = 5000
    addr = (host,port)
    ki = "6bd96f7fdb64e0a02515efb0c0982d34"

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    
    clientGSM=ClientGSM(client_socket,ki);
    if clientGSM.auth():
        clientGSM.sartCom()
        client_socket.close()  # close the connection
    else:
        client_socket.close()  # close the connection
    


class ClientGSM(): 
    def __init__(self,conn,ki):
        self.state=0;
        self.buf = 1024
        self.conn = conn
        self.ki=ki
        
    # Authentification    
    def auth(self):
        
        #1. wait for challenge
        RAND = self.conn.recv(1024).decode()  # receive response
        
        #2. solve challenge and send
        blowfishChallenge= Blowfish.new(bytes.fromhex(self.ki), AES.MODE_ECB) # only one bloc
        RAND_comp_byte=bytes.fromhex(RAND)[0:8] # compresse RAND to 8 bytes, to work with one bloc
        SRES_byte=blowfishChallenge.encrypt(RAND_comp_byte);
        self.conn.send(SRES_byte)
        
        # wait anser from server
        answer = self.conn.recv(1024).decode()  # receive response
        if answer != 'pass':
            print("Authentification failed, disconnection")
            return 0;
        
        #5. deriv Key
        aesKc= AES.new(bytes.fromhex(self.ki), AES.MODE_ECB) # only one bloc
        self.kc_byte=aesKc.encrypt(aesKc.encrypt(bytes.fromhex(RAND))); # todo: Use a different algo
        #print("Kc =",len(self.kc_byte))
        
        return 1
    
    def sartCom(self):
        
        while True:
            message = input(" -> ")  # take input
            if message == "exit":
                break;
            
            #1. send IV from client
            nonce = secrets.token_hex(8)
            self.conn.send(nonce.encode())
            #print("IV:",nonce)
            #print("kc:",self.kc_byte)
            
            #2. init aes
            aesCom = AES.new(self.kc_byte, AES.MODE_CTR, nonce=bytes.fromhex(nonce)) 
            
            #3. encrypt and send data 
            cypher_byte = aesCom.encrypt(bytes(message,'utf-8'))
            #cypher= b64encode(cypher_byte).decode('utf-8')
            self.conn.send(cypher_byte)  # send message
            
            # wait for message from server
            nonce = self.conn.recv(self.buf).decode()
            if not nonce:
                # if data is not received break
                break
            #2. init aes
            aesCom = AES.new(self.kc_byte, AES.MODE_CTR, nonce=bytes.fromhex(nonce)) 
            
            #3. recieve data and decrypt
            cypher_byte = self.conn.recv(self.buf)
            
            data=aesCom.decrypt(cypher_byte);
            print("server says: ", data.decode() ) 
            



        
